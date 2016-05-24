local ffi = require('ffi')
local bit = require('bit')
local cdef = require('bpf.cdef')

local BPF, HELPER = ffi.typeof('struct bpf'), ffi.typeof('struct bpf_func_id')
local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}
local const_width_type = {
	[1] = ffi.typeof('uint8_t'), [2] = ffi.typeof('uint16_t'), [4] = ffi.typeof('uint32_t'), [8] = ffi.typeof('uint64_t'),
}

-- Built-ins that will be translated into BPF instructions
-- i.e. bit.bor(0xf0, 0x0f) becomes {'alu64, or, k', reg(0xf0), reg(0x0f), 0, 0}
local builtins = {
	[bit.lshift]  = 'LSH',
	[bit.rshift]  = 'RSH',
	[bit.band]    = 'AND',
	[bit.bnot]    = 'NEG',
	[bit.bor]     = 'OR',
	[bit.bxor]    = 'XOR',
	[bit.arshift] = 'ARSH',
	-- Extensions and intrinsics
}

local function width_type(w)
	return const_width_type[w] or ffi.typeof('uint8_t[?]', w)
end
builtins.width_type = width_type

-- Byte-order conversions for little endian
local function ntoh(x, w)
	if w then x = ffi.cast(const_width_type[w/8], x) end
	return bit.bswap(x)
end
local function hton(x, w) return ntoh(x, w) end
builtins.ntoh = ntoh
builtins.hton = hton
builtins[ntoh] = function (e, dst, a, w)
	-- This is trickery, but TO_LE means cpu_to_le(),
	-- and we want exactly the opposite as network is always 'be'
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_BE, e.vreg(dst), 0, 0, w)
end
builtins[hton] = function (e, dst, a, w)
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_LE, e.vreg(dst), 0, 0, w)
end
-- Byte-order conversions for big endian are no-ops
if ffi.abi('be') then
	ntoh = function (x, w)
		return w and ffi.cast(const_width_type[w/8], x) or x
	end
	hton = ntoh
	builtins[ntoh] = function(a, b, w) return end
	builtins[hton] = function(a, b, w) return end
end
-- Other built-ins
local function xadd(a, b) error('NYI') end
builtins.xadd = xadd
builtins[xadd] = function (e, dst, a, b, off)
	assert(e.V[a].const.__dissector, 'xadd(a, b) called on non-pointer')
	local w = ffi.sizeof(e.V[a].const.__dissector)
	assert(w == 4 or w == 8, 'NYI: xadd() - 1 and 2 byte atomic increments are not supported')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	local src_reg = e.vreg(b)
	local dst_reg = e.vreg(dst)
	e.emit(BPF.JMP + BPF.JEQ + BPF.K, dst_reg, 0, 1, 0) -- if (dst != NULL)
	e.emit(BPF.XADD + BPF.STX + const_width[w], dst_reg, src_reg, off or 0, 0)
end
builtins[ffi.cast] = function (e, dst, ct, x)
	assert(e.V[ct].const, 'ffi.cast(ctype, x) called with bad ctype')
	e.vcopy(dst, x)
	if not e.V[x].const then
		e.V[dst].type = ffi.typeof(e.V[ct].const)
	else
		e.V[dst].const.__dissector = ffi.typeof(e.V[ct].const)
	end
	-- Specific types also encode source of the data
	-- struct pt_regs - source of the data is probe
	-- struct skb     - source of the data is socket buffer
	if ffi.typeof(e.V[ct].const) == ffi.typeof('struct pt_regs') then
		e.V[dst].source = ffi.typeof('struct pt_regs')
	end

end
builtins[ffi.new] = function (e, dst, ct, x)
	ct = ffi.typeof(e.V[ct].const) -- Get ctype
	assert(not x, 'NYI: ffi.new(ctype, ...) - initializer is not supported')
	assert(not cdef.isptr(ct, true), 'NYI: ffi.new(ctype, ...) - ctype MUST NOT be a pointer')
	e.vset(dst, nil, ct)
	e.V[dst].const = {}
	e.V[dst].const.__base = e.valloc(ffi.sizeof(ct), true)
end
builtins[ffi.copy] = function (e,ret, dst, src)
	assert(cdef.isptr(e.V[dst].type), 'ffi.copy(dst, src) - dst MUST be a pointer type')
	assert(cdef.isptr(e.V[src].type), 'ffi.copy(dst, src) - src MUST be a pointer type')
	-- Specific types also encode source of the data
	-- struct pt_regs - source of the data is probe
	-- struct skb     - source of the data is socket buffer
	if e.V[src].source == ffi.typeof('struct pt_regs') then
		e.reg_alloc(e.tmpvar, 1)
		-- Load stack pointer to dst, since only load to stack memory is supported
		-- we have to either use spilled variable or allocated stack memory offset
		e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
		if e.V[dst].spill then
			e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].spill)
		elseif e.V[dst].const.__base then
			e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].const.__base)
		else error('ffi.copy(dst, src) - can\'t get stack offset of dst') end
		-- Set stack memory maximum size bound
		local dst_tname = cdef.typename(e.V[dst].type)
		if dst_tname:sub(-1) == '*' then dst_tname = dst_tname:sub(0, -2) end
		e.reg_alloc(e.tmpvar, 2)
		e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, ffi.sizeof(dst_tname))
		-- Set source pointer
		if e.V[src].reg then
			e.reg_alloc(e.tmpvar, 3) -- Copy from original register
			e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, e.V[src].reg, 0, 0)
		else
			local src_reg = e.vreg(src, 3)
			e.reg_spill(src) -- Spill to avoid overwriting
		end
		-- Call probe read helper
		e.vreg(ret, 0, true, ffi.typeof('int32_t'))
		e.V[ret].const = nil
		e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.probe_read)
		e.V[e.tmpvar].reg = nil  -- Free temporary registers
	elseif e.V[src].const and e.V[src].const.__map then
		error('NYI: ffi.copy(dst, src) - src is backed by BPF map')
	elseif e.V[src].const and e.V[src].const.__dissector then
		error('NYI: ffi.copy(dst, src) - src is backed by socket buffer')
	else
		-- TODO: identify cheap register move
		-- TODO: identify copy to/from stack
		error('NYI: ffi.copy(dst, src) - src is neither BPF map/socket buffer or probe')
	end	
end
-- print(format, ...) builtin changes semantics from Lua print(...)
-- the first parameter has to be format and only reduced set of conversion specificers
-- is allowed: %d %u %x %ld %lu %lx %lld %llu %llx %p %s
builtins[print] = function (e, ret, fmt, a1, a2, a3)
	-- Load format string and length
	e.reg_alloc(e.V[e.tmpvar], 1)
	e.reg_alloc(e.V[e.tmpvar+1], 1)
	if type(e.V[fmt].const) == 'string' then
		local src = e.V[fmt].const
		local len = #src + 1
		local dst = e.valloc(len, src)
		-- TODO: this is materialize step
		e.V[fmt].const = {__base=dst}
		e.V[fmt].type = ffi.typeof('char ['..len..']')
	elseif e.V[fmt].const.__base then -- NOP
	else error('NYI: print(fmt, ...) - format variable is not literal/stack memory') end
	-- Prepare helper call
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[fmt].const.__base)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, ffi.sizeof(e.V[fmt].type))
	if a1 then
		local args = {a1, a2, a3}
		assert(#args <= 3, 'print(fmt, ...) - maximum of 3 arguments supported')
		for i, arg in ipairs(args) do
			e.vcopy(e.tmpvar, arg)  -- Copy variable
			e.vreg(e.tmpvar, 3+i-1) -- Materialize it in arg register
		end
	end
	-- Call helper
	e.vreg(ret, 0, true, ffi.typeof('int32_t')) -- Return is integer
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.trace_printk)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end
-- Math library built-ins
math.log2 = function (x) error('NYI') end
builtins[math.log2] = function (e, dst, x)
	-- Classic integer bits subdivison algorithm to find the position
	-- of the highest bit set, adapted for BPF bytecode-friendly operations.
	-- https://graphics.stanford.edu/~seander/bithacks.html
	-- r = 0
	local r = e.vreg(dst, nil, true)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, r, 0, 0, 0)
	-- v = x
	e.vcopy(e.tmpvar, x)
	local v = e.vreg(e.tmpvar, 2)
	if cdef.isptr(e.V[x].const) then -- No pointer arithmetics, dereference
		e.vderef(v, v, ffi.typeof('uint64_t'))
	end
	-- Invert value to invert all tests, otherwise we would need and+jnz
	e.emit(BPF.ALU64 + BPF.NEG + BPF.K, v, 0, 0, 0)        -- v = ~v
	-- Unrolled test cases, converted masking to arithmetic as we don't have "if !(a & b)"
	-- As we're testing inverted value, we have to use arithmetic shift to copy MSB
	for i=4,0,-1 do
		local k = bit.lshift(1, i)
		e.emit(BPF.JMP + BPF.JGT + BPF.K, v, 0, 2, bit.bnot(bit.lshift(1, k))) -- if !upper_half(x)
		e.emit(BPF.ALU64 + BPF.ARSH + BPF.K, v, 0, 0, k)                       --     v >>= k
		e.emit(BPF.ALU64 + BPF.OR + BPF.K, r, 0, 0, k)                         --     r |= k
	end
	-- No longer constant, cleanup tmpvars
	e.V[dst].const = nil
	e.V[e.tmpvar].reg = nil
end
builtins[math.log10] = function (e, dst, x)
	-- Compute log2(x) and transform
	builtins[math.log2](e, dst, x)
	-- Relationship: log10(v) = log2(v) / log2(10)
	local r = e.V[dst].reg
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, r, 0, 0, 1)    -- Compensate round-down
	e.emit(BPF.ALU64 + BPF.MUL + BPF.K, r, 0, 0, 1233) -- log2(10) ~ 1233>>12
	e.emit(BPF.ALU64 + BPF.RSH + BPF.K, r, 0, 0, 12)
end
builtins[math.log] = function (e, dst, x)
	-- Compute log2(x) and transform
	builtins[math.log2](e, dst, x)
	-- Relationship: ln(v) = log2(v) / log2(e)
	local r = e.V[dst].reg
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, r, 0, 0, 1)    -- Compensate round-down
	e.emit(BPF.ALU64 + BPF.MUL + BPF.K, r, 0, 0, 2839) -- log2(e) ~ 2839>>12
	e.emit(BPF.ALU64 + BPF.RSH + BPF.K, r, 0, 0, 12)
end

-- Call-type helpers
local function call_helper(e, dst, h)
	local dst_reg = e.vreg(dst, 0, true)
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, h)
	e.V[dst].const = nil -- Target is not a function anymore
end
local function cpu() error('NYI') end
local function rand() error('NYI') end
local function time() error('NYI') end
local function pid_tgid() error('NYI') end
local function uid_gid() error('NYI') end

-- Export helpers and builtin variants
builtins.cpu = cpu
builtins.time = time
builtins.pid_tgid = pid_tgid
builtins.uid_gid = uid_gid
builtins[cpu] = function (e, dst) return call_helper(e, dst, HELPER.get_smp_processor_id) end
builtins[rand] = function (e, dst) return call_helper(e, dst, HELPER.get_prandom_u32) end
builtins[time] = function (e, dst) return call_helper(e, dst, HELPER.ktime_get_ns) end
builtins[pid_tgid] = function (e, dst) return call_helper(e, dst, HELPER.get_current_pid_tgid) end
builtins[uid_gid] = function (e, dst) return call_helper(e, dst, HELPER.get_current_uid_gid) end

return builtins
