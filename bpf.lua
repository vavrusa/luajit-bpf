-- Translate LuaJIT function into eBPF bytecode.
--
-- The code generation phase is currently one-pass and produces:
-- * Compiled code in eBPF bytecode format (https://www.kernel.org/doc/Documentation/networking/filter.txt)
-- * Variables with liveness analysis and other meta (spill information, compile-time value)
--
-- The code generator optimises as much as possible in single pass:
-- * Fold compile-time expressions and constant propagation
-- * Basic control flow analysis with dead code elimination (based on compile-time expressions)
-- * Single-pass optimistic register allocation
--
-- The first pass doesn't have variable lifetime visibility yet, so it relies on rewriter for further
-- optimisations such as:
-- * Dead store elimination (first-pass doesn't know if/when the variable is going to be used)
-- * Common sub-expression elimination (relies on DCE and liveness analysis)
-- * Orphan JMP elimination (removing this in first pass would break previous JMP targets)
-- * Better register allocation (needs to be recomputed after optimisations)

local ffi = require('ffi')
local bit = require('bit')
local band = bit.band
local S = require('syscall')
local c, t = S.c, S.t
local bytecode = require('bpf.ljbytecode')
local cdef = require('bpf.cdef')
local proto = require('bpf.proto')
local builtins = require('bpf.builtins')

-- Constants
local ALWAYS, NEVER = -1, -2
local BPF, CMD, PROG = ffi.typeof('struct bpf'), ffi.typeof('struct bpf_cmd'), ffi.typeof('struct bpf_prog')
local HELPER = ffi.typeof('struct bpf_func_id')

-- Symbolic table of constant expressions over numbers
local const_expr = {
	ADD = function (a, b) return a + b end,
	SUB = function (a, b) return a - b end,
	DIV = function (a, b) return a / b end,
	MOD = function (a, b) return a % b end,
	JEQ = function (a, b) return a == b end,
	JNE = function (a, b) return a ~= b end,
	JGE = function (a, b) return a >= b end,
	JGT = function (a, b) return a > b end,
}
local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}

-- Built-ins that are strict only (never compile-time expandable)
local builtins_strict = {
	[ffi.new] = true,
	[print]   = true,
}

-- Return struct member size/type (requires LuaJIT 2.1+)
-- I am ashamed that there's no easier way around it.
local function sizeofattr(ct, name)
	local cinfo = ffi.typeinfo(ct)
	while true do
		cinfo = ffi.typeinfo(cinfo.sib)
		if not cinfo then return end
		if cinfo.name == name then break end
	end
	local size = math.max(1, ffi.typeinfo(cinfo.sib or ct).size - cinfo.size)
	-- Guess type name
	return size, builtins.width_type(size)
end

-- Return true if the constant part is a proxy
local function is_proxy(x)
	return type(x) == 'table' and (x.__dissector or x.__map or x.__base)
end

-- Create compiler closure
local function create_emitter(env, stackslots, params)

local V = {}   -- Variable tracking / register allocator
local code = { -- Generated code
	pc = 0, bc_pc = 0,
	insn = ffi.new('struct bpf_insn[4096]'),
	fixup = {},
	reachable = true,
	seen_cmp = nil,
}
local Vstate = {} -- Track variable layout at basic block exits

-- Anything below this stack offset is free to use by caller
-- @note: There is no tracking memory allocator, so the caller may
-- lower it for persistent objects, but such memory will never
-- be reclaimed and the caller is responsible for resetting stack
-- top whenever the memory below is free to be reused
local stack_top = (stackslots + 1) * ffi.sizeof('uint64_t')

local function emit(op, dst, src, off, imm)
	local ins = code.insn[code.pc]
	ins.code = op
	ins.dst_reg = dst
	ins.src_reg = src
	ins.off = off
	ins.imm = imm
	code.pc = code.pc + 1
end

local function reg_spill(var)
	local vinfo = V[var]
	vinfo.spill = (var + 1) * ffi.sizeof('uint64_t') -- Index by (variable number) * (register width)
	emit(BPF.MEM + BPF.STX + BPF.DW, 10, vinfo.reg, -vinfo.spill, 0)
	vinfo.reg = nil
end

local function reg_fill(var, reg)
	local vinfo = V[var]
	assert(vinfo.spill, 'attempt to fill register with a VAR that isn\'t spilled')
	emit(BPF.MEM + BPF.LDX + BPF.DW, reg, 10, -vinfo.spill, 0)
	vinfo.reg = reg
	vinfo.spill = nil
end

-- Allocate a register (lazy simple allocator)
local function reg_alloc(var, reg)
	-- Specific register requested, must spill/move existing variable
	if reg then
		local spill = nil
		for k,v in pairs(V) do -- Spill any variable that has this register
			if v.reg == reg and not v.shadow then
				spill = k
				reg_spill(k)
				break
			end
		end
		return reg
	end
	-- Find free or least recently used slot
	local last, last_seen, used = nil, 0xffff, 0
	for k,v in pairs(V) do
		if v.reg then
			if not v.live_to or v.live_to < last_seen then
				last, last_seen = k, v.live_to or last_seen
			end
			used = bit.bor(used, bit.lshift(1, v.reg))
		end
	end
	-- Attempt to select a free register from R7-R9 (callee saved)
	local free = bit.bnot(used)
	if     bit.band(free, 0x80) ~= 0 then reg = 7
	elseif bit.band(free,0x100) ~= 0 then reg = 8
	elseif bit.band(free,0x200) ~= 0 then reg = 9
	end
	-- Select another variable to be spilled
	if not reg then
		assert(last)
		reg = V[last].reg
		reg_spill(last)
	end
	assert(reg, 'VAR '..var..'fill/spill failed')
	return reg
end

-- Set new variable
local function vset(var, reg, const)
	-- Get precise type for CDATA or attempt to narrow numeric constant
	local vtype = type(const) == 'cdata' and ffi.typeof(const)
	V[var] = {reg=reg, const=const, type=vtype}
end

-- Materialize (or register) a variable in a register
-- If the register is nil, then the a new register is assigned (if not already assigned)
local function vreg(var, reg, reserve, vtype)
	local vinfo = V[var]
	assert(vinfo, 'VAR '..var..' not registered')
	vinfo.live_to = code.pc-1
	if (vinfo.reg and not reg) and not vinfo.shadow then return vinfo.reg end
	reg = reg_alloc(var, reg)
	-- Materialize variable shadow copy
	local src = vinfo
	while src.shadow do src = V[src.shadow] end
	if reserve then
		-- No load to register occurs
	elseif src.reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, src.reg, 0, 0)
	elseif src.spill then
		vinfo.spill = src.spill
		reg_fill(var, reg)
	elseif src.const then
		vtype = vtype or src.type
		if type(src.const) == 'table' and src.const.__dissector then
			-- Load dissector offset (imm32), but keep the constant part (dissector proxy)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const.off or 0)
		elseif type(src.const) == 'table' and src.const.__base then
			-- Load pointer type
			emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, 10, 0, 0)
			emit(BPF.ALU64 + BPF.ADD + BPF.K, reg, 0, 0, -src.const.__base)
		elseif vtype and ffi.sizeof(vtype) == 8 then
			-- IMM64 must be done in two instructions with imm64 = (lo(imm32), hi(imm32))
			emit(BPF.LD + BPF.DW, reg, 0, 0, ffi.cast('uint32_t', src.const))
			emit(0, 0, 0, 0, ffi.cast('uint32_t', bit.rshift(bit.rshift(src.const, 16), 16)))
			vinfo.const = nil -- The variable is live
		else
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const)
			vinfo.const = nil -- The variable is live
		end
	else assert(false, 'VAR '..var..' has neither register nor constant value') end
	vinfo.reg = reg
	vinfo.shadow = nil
	vinfo.live_from = code.pc-1
	vinfo.type = vtype or vinfo.type
	return reg
end

-- Copy variable
local function vcopy(dst, src)
	if dst == src then return end
	V[dst] = {reg=V[src].reg, const=V[src].const, shadow=src, source=V[src].source, type=V[src].type}
end

-- Move variable
local function vmov(dst, src)
	if dst == src then return end
	V[dst] = V[src]
	V[src] = nil
end

-- Dereference variable of pointer type
local function vderef(dst_reg, src_reg, vtype)
	-- Dereference map pointers for primitive types
	-- BPF doesn't allow pointer arithmetics, so use the entry value
	local w = ffi.sizeof(vtype)
	assert(const_width[w], 'NYI: sizeof('..tostring(vtype)..') not 1/2/4/8 bytes')
	if dst_reg ~= src_reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, dst_reg, src_reg, 0, 0)    -- dst = src
	end
	emit(BPF.JMP + BPF.JEQ + BPF.K, src_reg, 0, 1, 0)                -- if (src != NULL)
	emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, src_reg, 0, 0) --     dst = *src;
end

-- Allocate a space for variable
local function valloc(size, blank)
	local base = stack_top
	assert(stack_top + size < 512 * 1024, 'exceeded maximum stack size of 512kB')
	stack_top = stack_top + size
	-- Align to 8 byte boundary
	stack_top = math.ceil(stack_top/8)*8
	-- Current kernel version doesn't support ARG_PTR_TO_RAW_STACK
	-- so we always need to have memory initialized, remove this when supported
	if blank then 
		if type(blank) == 'string' then
			local sp = 0
			while sp < size do
				-- TODO: no BPF_ST + BPF_DW instruction yet
				local as_u32 = ffi.new('uint32_t [1]')
				local sub = blank:sub(sp+1, sp+ffi.sizeof(as_u32))
				ffi.copy(as_u32, sub, #sub)
				emit(BPF.MEM + BPF.ST + BPF.W, 10, 0, -(stack_top-sp), as_u32[0])
				sp = sp + ffi.sizeof(as_u32)
			end
		elseif type(blank) == 'boolean' then
			reg_alloc(stackslots, 0)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, 0, 0, 0, 0)
			for sp = base+8,stack_top,8 do
				emit(BPF.MEM + BPF.STX + BPF.DW, 10, 0, -sp, 0)
			end
		else error('NYI: will with unknown type '..type(blank)) end
	end 
	return stack_top
end

-- Emit compensation code at the end of basic block to unify variable set layout on all block exits
-- 1. we need to free registers by spilling
-- 2. fill registers to match other exits from this BB
local function bb_end(Vcomp)
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].spill and not v.spill then
			reg_spill(i)
		end
	end
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].reg and not v.reg then
			vreg(i, Vcomp[i].reg)
		end
	end
end

local function BUILTIN(func, ...)
	func({V=V, vreg=vreg, vset=vset, vcopy=vcopy, vderef=vderef, valloc=valloc, emit=emit,
		  reg_alloc=reg_alloc, reg_spill=reg_spill, tmpvar=stackslots, const_width=const_width}, ...)
end

local function LD_ABS(dst, off, w)
	local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0
	-- assert(w < 8, 'NYI: LD_ABS64 is not supported') -- IMM64 has two IMM32 insns fused together
	emit(BPF.LD + BPF.ABS + const_width[w], dst_reg, 0, 0, off)
end

local function LD_IND(dst, src, w, off)
	local src_reg = vreg(src) -- Must materialize first in case dst == src
	local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0
	emit(BPF.LD + BPF.IND + const_width[w], dst_reg, src_reg, 0, off or 0)
end

local function LD_FIELD(a, d, w, imm)
	if imm then
		LD_ABS(a, imm, w)
	else
		LD_IND(a, d, w)
	end
end

local function LOAD(dst, src, off, vtype)
	local base = V[src].const
	assert(base.__dissector, 'NYI: load() on variable that doesnt have dissector')
	-- Cast to different type if requested
	vtype = vtype or base.__dissector
	local w = ffi.sizeof(vtype)
	assert(w <= 4, 'NYI: load() supports 1/2/4 bytes at a time only')
	if base.off then -- Absolute address to payload
		LD_ABS(dst, off + base.off, w)
	else -- Indirect address to payload
		LD_IND(dst, src, w, off)
	end
	V[dst].type = vtype
	V[dst].const = nil -- Dissected value is not constant anymore
end

local function CMP_REG(a, b, op)
	-- Fold compile-time expressions
	if V[a].const and V[b].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		code.seen_cmp = const_expr[op](V[a].const, V[b].const) and ALWAYS or NEVER
	else
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local a_reg, b_reg = vreg(a), vreg(b)
		-- Migrate operands from R0-5 as it will be spilled in compensation code when JMP out of BB
		if a_reg == 0 then a_reg = vreg(a, 7) end
		emit(BPF.JMP + BPF[op] + BPF.X, a_reg, b_reg, 0xffff, 0)
		code.seen_cmp = code.pc-1
	end
end

local function CMP_IMM(a, b, op)
	if V[a].const and not is_proxy(V[a].const) then -- Fold compile-time expressions
		code.seen_cmp = const_expr[op](V[a].const, b) and ALWAYS or NEVER
	else
		-- Convert imm32 to number
		if type(b) == 'string' then
			if     #b == 1 then b = b:byte()
			elseif #b <= 4 then
				-- Convert to u32 with network byte order
				local imm = ffi.new('uint32_t[1]')
				ffi.copy(imm, b, #b)
				b = builtins.hton(imm[0])
			else error('NYI: compare register with string, where #string > sizeof(u32)') end
		end
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local reg = vreg(a)
		-- Migrate operands from R0-5 as it will be spilled in compensation code when JMP out of BB
		if reg == 0 then reg = vreg(a, 7) end
		emit(BPF.JMP + BPF[op] + BPF.K, reg, 0, 0xffff, b)
		code.seen_cmp = code.pc-1
	end
end

local function ALU_IMM(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not is_proxy(V[a].const) then
			assert(type(V[a].const) == 'number', 'VAR '..a..' must be numeric')
			vset(dst, nil, const_expr[op](V[a].const, b))
	-- Now we need to materialize dissected value at DST, and add it
	else
		vcopy(dst, a)
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a].const.__dissector)
			V[dst].type = V[a].const.__dissector
		end
		emit(BPF.ALU64 + BPF[op] + BPF.K, dst_reg, 0, 0, b)
	end
end

local function ALU_REG(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		assert(type(V[a].const) == 'number', 'VAR '..a..' must be numeric')
		assert(type(V[b].const) == 'number', 'VAR '..b..' must be numeric')
		if type(op) == 'string' then op = const_expr[op] end
		vcopy(dst, a)
		V[dst].const = func(V[a].const, V[b].const)
	else
		local src_reg = b and vreg(b) or 0 -- SRC is optional for unary operations
		if b and cdef.isptr(V[b].type) then
			-- We have to allocate a temporary register for dereferencing to preserve
			-- pointer in source variable that MUST NOT be altered
			reg_alloc(stackslots, 2)
			vderef(2, src_reg, V[b].const.__dissector)
			src_reg = 2
		end
		vcopy(dst, a) -- DST may alias B, so copy must occur after we materialize B
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a].const.__dissector)
			V[dst].type = V[a].const.__dissector
		end
		emit(BPF.ALU64 + BPF[op] + BPF.X, dst_reg, src_reg, 0, 0)
		V[stackslots].reg = nil  -- Free temporary registers
	end
end


local function ALU_IMM_NV(dst, a, b, op)
	-- Do DST = IMM(a) op VAR(b) where we can't invert because
	-- the registers are u64 but immediates are u32, so complement
	-- arithmetics wouldn't work
	vset(stackslots+1, nil, a)
	ALU_REG(dst, stackslots+1, b, op)
end

local function CALL(a, b, d)
	assert(b-1 <= 1, 'NYI: CALL with >1 return values')
	-- Perform either compile-time, helper, or builtin
	local func = V[a].const
	-- Gather all arguments and check if they're constant
	local args, const, nargs = {}, true, d - 1
	for i = a+1, a+d-1 do
		table.insert(args, V[i].const)
		if not V[i].const or is_proxy(V[i].const) then const = false end
	end
	local builtin = builtins[func]
	if not const or nargs == 0 then
		if builtin and type(builtin) == 'function' then
			args = {a}
			for i = a+1, a+nargs do table.insert(args, i) end
			BUILTIN(builtin, unpack(args))
		elseif V[a+2] and V[a+2].const then -- var OP imm
			ALU_IMM(a, a+1, V[a+2].const, builtin)
		elseif nargs <= 2 then              -- var OP var
			ALU_REG(a, a+1, V[a+2] and a+2, builtin)
		else
			error('NYI: CALL non-builtin with 3 or more arguments')
		end
	-- Call on dissector implies slice retrieval
	elseif type(func) == 'table' and func.__dissector then
		assert(nargs >= 2, 'NYI: <dissector>.slice(a, b) must have at least two arguments')
		assert(V[a+1].const and V[a+2].const, 'NYI: slice() arguments must be constant')
		local off = V[a+1].const
		local vtype = builtins.width_type(V[a+2].const - off)
		LOAD(a, a, off, vtype)
	-- Strict builtins cannot be expanded on compile-time
	elseif builtins_strict[func] and builtin then
		args = {a}
		for i = a+1, a+nargs do table.insert(args, i) end
		BUILTIN(builtin, unpack(args))
	-- Attempt compile-time call expansion (expects all argument compile-time known)
	else
		V[a].const = func(unpack(args))
	end
end

-- @note: This is specific now as it expects registers reserved
local function LD_IMM_X(dst_reg, src_type, imm, w)
	if w == 8 then -- IMM64 must be done in two instructions with imm64 = (lo(imm32), hi(imm32))
		emit(BPF.LD + const_width[w], dst_reg, src_type, 0, ffi.cast('uint32_t', imm))
		-- Must shift in two steps as bit.lshift supports [0..31]
		emit(0, 0, 0, 0, ffi.cast('uint32_t', bit.lshift(bit.lshift(imm, 16), 16)))
	else
		emit(BPF.LD + const_width[w], dst_reg, src_type, 0, imm)
	end
end

local function MAP_INIT(map_var, key, imm)
	local map = V[map_var].const
	vreg(map_var, 1, true, ffi.typeof('uint64_t'))
	-- Reserve R1 and load ptr for process-local map fd
	LD_IMM_X(1, BPF.PSEUDO_MAP_FD, map.fd, ffi.sizeof(V[map_var].type))
	-- Reserve R2 and load R2 = key pointer
	local sp = stack_top + ffi.sizeof(map.key_type) -- Must use stack below spill slots
	local w = assert(const_width[ffi.sizeof(map.key)], 'NYI: map key width must be 1/2/4/8')
	if not imm then imm = V[key].const end
	if imm and (not key or not is_proxy(V[key].const)) then
		emit(BPF.MEM + BPF.ST + w, 10, 0, -sp, imm)
	elseif V[key].reg then
		emit(BPF.MEM + BPF.STX + w, 10, V[key].reg, -sp, 0)
	else
		assert(V[key].spill, 'VAR '..key..' is neither const-expr/register/spilled')
		sp = V[key].spill
	end
	reg_alloc(stackslots, 2) -- Spill anything in R2 (unnamed tmp variable)
	emit(BPF.ALU64 + BPF.MOV + BPF.X, 2, 10, 0, 0)
	emit(BPF.ALU64 + BPF.ADD + BPF.K, 2, 0, 0, -sp)
end

local function MAP_GET(dst, map_var, key, imm)
	local map = V[map_var].const
	MAP_INIT(map_var, key, imm)
	-- Flag as pointer type and associate dissector for map value type
	vreg(dst, 0, true, ffi.typeof('uint8_t *'))
	V[dst].const = {__dissector=map.val_type}
	emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_lookup_elem)
end

local function MAP_SET(map_var, key, key_imm, src)
	local map = V[map_var].const
	-- Set R0, R1 (map fd, preempt R0)
	reg_alloc(stackslots, 0) -- Spill anything in R0 (unnamed tmp variable)
	MAP_INIT(map_var, key, key_imm)
	-- Reserve R3 for value pointer
	local val_size = ffi.sizeof(map.val_type)
	local w = assert(const_width[val_size], 'NYI: MAP[K] = V; V width must be 1/2/4/8')
	-- Stack pointer must be aligned to both key/value size
	local sp = stack_top + math.max(ffi.sizeof(map.key_type), val_size) + val_size
	if V[src].reg then
		emit(BPF.MEM + BPF.STX + w, 10, V[src].reg, -sp, 0)
	elseif V[src].spill then
		-- If variable is a pointer, we can load it to R3 directly (cheap dereference)
		if cdef.isptr(V[src].type) then
			reg_fill(src, 3)
			emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_update_elem)
			return
		else -- We get a pointer to spilled register on stack
			sp = V[src].spill
		end
	else
		assert(not is_proxy(V[src].const), 'VAR '..src..' is neither const-expr/register/spilled')
		emit(BPF.MEM + BPF.ST + w, 10, 0, -sp, V[src].const)
		-- TODO: DW precision
	end
	reg_alloc(stackslots, 3) -- Spill anything in R3 (unnamed tmp variable)
	emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, 10, 0, 0)
	emit(BPF.ALU64 + BPF.ADD + BPF.K, 3, 0, 0, -sp)
	reg_alloc(stackslots, 4) -- Spill anything in R4 (unnamed tmp variable)
	emit(BPF.ALU64 + BPF.MOV + BPF.K, 4, 0, 0, 0)
	emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_update_elem)
end

-- Finally - this table translates LuaJIT bytecode into code emitter actions.
local BC = {
	-- Constants
	[0x29] = function(a, _, _, d) -- KSHORT
		vset(a, nil, d, ffi.typeof('int16_t'))
	end,
	[0x2b] = function(a, _, _, d) -- KPRI
		vset(a, nil, (d < 2) and 0 or 1, ffi.typeof('uint8_t'))
	end,
	[0x27] = function(a, _, c, _) -- KSTR
		vset(a, nil, c, ffi.typeof('const char[?]'))
	end,
	[0x12] = function(a, _, _, d) -- MOV var, var
		vcopy(a, d)
	end,
	-- Comparison ops
	-- Note: comparisons are always followed by JMP opcode, that
	--       will fuse following JMP to JMP+CMP instruction in BPF
	-- Note:  we're narrowed to integers, so operand/operator inversion is legit
	[0x00] = function(a, _, _, d) return CMP_REG(d, a, 'JGE') end, -- (a < d) (inverted)
	[0x01] = function(a, _, _, d) return CMP_REG(a, d, 'JGE') end, -- (a >= d)
	[0x03] = function(a, _, _, d) return CMP_REG(a, d, 'JGT') end, -- (a > d)
	[0x04] = function(a, _, _, d) return CMP_REG(a, d, 'JEQ') end, -- (a == d)
	[0x05] = function(a, _, _, d) return CMP_REG(a, d, 'JNE') end, -- (a ~= d)
	[0x06] = function(a, _, c, _) return CMP_IMM(a, c, 'JEQ') end, -- (a == str(c))
	[0x07] = function(a, _, c, _) return CMP_IMM(a, c, 'JNE') end, -- (a ~= str(c))
	[0x08] = function(a, _, c, _) return CMP_IMM(a, c, 'JEQ') end, -- (a == c)
	[0x09] = function(a, _, c, _) return CMP_IMM(a, c, 'JNE') end, -- (a ~= c)
	[0x0e] = function(_, _, _, d) return CMP_IMM(d, 0, 'JNE') end, -- (d)
	[0x0f] = function(_, _, _, d) return CMP_IMM(d, 0, 'JEQ') end, -- (not d)
	-- Binary operations with RHS constants
	[0x16] = function(a, b, c, _) return ALU_IMM(a, b, c, 'ADD') end,
	[0x17] = function(a, b, c, _) return ALU_IMM(a, b, c, 'SUB') end,
	[0x18] = function(a, b, c, _) return ALU_IMM(a, b, c, 'MUL') end,
	[0x19] = function(a, b, c, _) return ALU_IMM(a, b, c, 'DIV') end,
	[0x1a] = function(a, b, c, _) return ALU_IMM(a, b, c, 'MOD') end,
	-- Binary operations with LHS constants
	-- Cheat code: we're narrowed to integer arithmetic, so MUL+ADD are commutative
	[0x1b] = function(a, b, c, _) return ALU_IMM(a, b, c, 'ADD') end, -- ADDNV
	[0x1d] = function(a, b, c, _) return ALU_IMM(a, b, c, 'MUL') end, -- MULNV
	[0x1c] = function(a, b, c, _) return ALU_IMM_NV(a, c, b, 'SUB') end, -- SUBNV
	[0x1e] = function(a, b, c, _) return ALU_IMM_NV(a, c, b, 'DIV') end, -- DIVNV
	-- Binary operations between registers
	[0x20] = function(a, b, _, d) return ALU_REG(a, b, d, 'ADD') end,
	[0x21] = function(a, b, _, d) return ALU_REG(a, b, d, 'SUB') end,
	[0x22] = function(a, b, _, d) return ALU_REG(a, b, d, 'MUL') end,
	[0x23] = function(a, b, _, d) return ALU_REG(a, b, d, 'DIV') end,
	[0x24] = function(a, b, _, d) return ALU_REG(a, b, d, 'MOD') end,
	-- Tables
	[0x36] = function (a, _, c, _) -- GGET (A = GLOBAL[c])
		if env[c] ~= nil then
			vset(a, nil, env[c])
		else error(string.format("undefined global '%s'", c)) end
	end,
	[0x2d] = function (a, _, c, _) -- UGET (A = UPVALUE[c])
		if env[c] ~= nil then
			vset(a, nil, env[c])
		else error(string.format("undefined upvalue '%s'", c)) end
	end,
	[0x3a] = function (a, b, _, d) -- TGETB (A = B[D])
		if not V[a] then vset(a) end
		local base = V[b].const
		if base.__map then -- BPF map read (constant)
			MAP_GET(a, b, nil, d)
		else
			LOAD(a, b, d, ffi.typeof('uint8_t'))
		end
	end,
	[0x3e] = function (a, b, _, d) -- TSETB (B[D] = A)
		if V[b].const.__map then -- BPF map read (constant)
			return MAP_SET(b, nil, d, a) -- D is literal
		elseif V[b].const and V[b].const and V[a].const then
			V[b].const[V[d].const] = V[a].const
		else error('NYI: B[D] = A, where B is not Lua table or BPF map')
		end
	end,
	[0x3c] = function (a, b, _, d) -- TSETV (B[D] = A)
		if V[b].const.__map then -- BPF map read (constant)
			return MAP_SET(b, d, nil, a) -- D is literal
		elseif V[b].const and V[d].const and V[a].const then
			V[b].const[V[d].const] = V[a].const
		else error('NYI: B[D] = A, where B is not Lua table or BPF map')
		end
	end,
	[0x3d] = function (a, b, c, _) -- TSETS (B[C] = A)
		assert(V[b] and V[b].const, 'NYI: B[D] where B is not Lua table or BPF map')
		local base = V[b].const
		if base.__dissector then
			local ofs,bpos,bsize = ffi.offsetof(base.__dissector, c)
			assert(not bpos, 'NYI: B[C] = A, where C is a bitfield')
			local w = sizeofattr(base.__dissector, c)
			assert(const_width[w], 'B[C] = A, sizeof(A) must be 1/2/4/8')
			local src_reg = vreg(a)
			emit(BPF.JMP + BPF.JEQ + BPF.K, V[b].reg, 0, 1, 0) -- if (map[x] != NULL)
			emit(BPF.MEM + BPF.STX + const_width[w], V[b].reg, src_reg, ofs, 0)
		elseif V[a].const then
			base[c] = V[a].const
		else error('NYI: B[C] = A, where B is not Lua table or BPF map')
		end
	end,
	[0x38] = function (a, b, _, d) -- TGETV (A = B[D])
		assert(V[b] and V[b].const, 'NYI: B[D] where B is not Lua table or BPF map')
		if V[b].const.__map then -- BPF map read
			MAP_GET(a, b, d)
		elseif V[b].const == env.pkt then  -- Raw packet, no offset
			LD_FIELD(a, d, 1, V[d].const)
		else V[a].const = V[b].const[V[d].const] end
	end,
	[0x39] = function (a, b, c, _) -- TGETS (A = B[C])
		assert(V[b] and V[b].const, 'NYI: B[C] where C is string and B not Lua table or BPF map')
		local base = V[b].const
		if base.__dissector then
			local ofs,bpos,bsize = ffi.offsetof(base.__dissector, c)
			-- Resolve table key using metatable
			if not ofs and type(base.__dissector[c]) == 'string' then
				c = base.__dissector[c]
				ofs,bpos,bsize = ffi.offsetof(base.__dissector, c)
			end
			if not ofs and proto[c] then -- Load new dissector on given offset
				BUILTIN(proto[c], a, b, c)
			else
				assert(ofs, tostring(base.__dissector)..'.'..c..' attribute not exists')
				if not V[a] then vset(a) end
				-- Simple register load, get absolute offset or R-relative
				local w, atype = sizeofattr(base.__dissector, c)
				if base.rel then -- R-relative addressing
					local dst_reg = vreg(a, nil, true)
					assert(const_width[w], 'NYI: sizeof('..tostring(base.__dissector)..'.'..c..') not 1/2/4/8 bytes')
					emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, V[b].reg, ofs, 0)
				elseif base.off then -- Absolute address to payload
					LD_ABS(a, ofs + base.off, w)
				else -- Indirect address to payload
					LD_IND(a, b, w, ofs)
				end
				-- Bitfield, must be further narrowed with a bitmask/shift
				if bpos then
					local mask = 0
					for i=bpos+1,bpos+bsize do
						mask = bit.bor(mask, bit.lshift(1, w*8-i))
					end
					emit(BPF.ALU64 + BPF.AND + BPF.K, vreg(a), 0, 0, mask)
					-- Free optimization: single-bit values need just boolean result
					if bsize > 1 then
						local shift = w*8-bsize-bpos
						if shift > 0 then
							emit(BPF.ALU64 + BPF.RSH + BPF.K, vreg(a), 0, 0, shift)
						end
					end
				end
				V[a].type = atype
				V[a].const = nil -- Dissected value is not constant anymore
				V[a].source = V[b].source
			end
		else V[a].const = base[c] end
	end,
	-- Loops and branches
	[0x41] = function (a, b, _, d) -- A = A(A+1, ..., A+D+MULTRES)
		-- NYI: Support single result only
		CALL(a, b, d+2)
	end,
	[0x42] = function (a, b, _, d) -- A = A(A+1, ..., A+D-1)
		CALL(a, b, d)
	end,
	[0x58] = function (a, _, c, d) -- JMP
		-- Discard unused slots after jump
		for i,v in pairs(V) do
			if i >= a then V[i] = {} end
		end
		local val = code.fixup[c] or {}
		if code.seen_cmp and code.seen_cmp ~= ALWAYS then
			if code.seen_cmp ~= NEVER then -- Do not emit the jump or fixup
				-- Store previous CMP insn for reemitting after compensation code
				local jmpi = ffi.new('struct bpf_insn', code.insn[code.pc-1])
				code.pc = code.pc - 1
				-- First branch point, emit compensation code
				local Vcomp = Vstate[c]
				if not Vcomp then
					for i,v in pairs(V) do
						if not v.reg and v.const and not is_proxy(v.const) then
							vreg(i, 0)   -- Load to TMP register (not saved)
						end
						if v.reg and v.reg <= 5 then
							reg_spill(i) -- Spill caller-saved registers
						end
					end
					-- Record variable state
					Vstate[c] = V
					V = {}
					for i,v in pairs(Vstate[c]) do
						V[i] = {}
						for k,e in pairs(v) do
							V[i][k] = e
						end
					end
				-- Variable state already set, emit specific compensation code
				else bb_end(Vcomp) end
				-- Reemit CMP insn
				emit(jmpi.code, jmpi.dst_reg, jmpi.src_reg, jmpi.off, jmpi.imm)
				-- Fuse JMP into previous CMP opcode, mark JMP target for fixup
				-- as we don't knot the relative offset in generated code yet
				table.insert(val, code.pc-1)
				code.fixup[c] = val
			end
			code.seen_cmp = nil
		else
			emit(BPF.JMP + BPF.JEQ + BPF.X, 6, 6, 0xffff, 0) -- Always true
			table.insert(val, code.pc-1) -- Fixup JMP target
			code.reachable = false -- Code following the JMP is not reachable
			code.fixup[c] = val
		end
	end,
	[0x4c] = function (a, _, _, _) -- RET1
		if V[a].reg ~= 0 then vreg(a, 0) end
		emit(BPF.JMP + BPF.EXIT, 0, 0, 0, 0)
		-- Free optimisation: spilled variable will not be filled again
		for k,v in pairs(V) do if v.reg == 0 then v.reg = nil end end
		code.reachable = false
	end,
	[0x4b] = function (_, _, _, _) -- RET0
		emit(BPF.ALU64 + BPF.MOV + BPF.K, 0, 0, 0, 0)
		emit(BPF.JMP + BPF.EXIT, 0, 0, 0, 0)
		code.reachable = false
	end,
	compile = function ()
		return code
	end
}
-- Always initialize R6 with R1 context
emit(BPF.ALU64 + BPF.MOV + BPF.X, 6, 1, 0, 0)
-- Register R6 as context variable (first argument)
if params and params > 0 then
	vset(0, 6, proto.skb)
end
-- Register tmpvars
vset(stackslots)
vset(stackslots+1)
return setmetatable(BC, {
	__index = function (t, k, v)
		if type(k) == 'number' then
			local op_str = string.sub(require('jit.vmdef').bcnames, 6*k+1, 6*k+6)
			error(string.format("NYI: opcode '0x%02x' (%-04s)", k, op_str))
		end
	end,
	__call = function (t, op, a, b, c, d)
		code.bc_pc = code.bc_pc + 1
		-- Exitting BB straight through, emit compensation code
		if Vstate[code.bc_pc] and code.reachable then
			bb_end(Vstate[code.bc_pc])
		end
		-- Perform fixup of jump targets
		-- We need to do this because the number of consumed and emited
		-- bytecode instructions is different
		local fixup = code.fixup[code.bc_pc]
		if fixup ~= nil then
			-- Patch JMP source insn with relative offset
			for i,pc in ipairs(fixup) do
				code.insn[pc].off = code.pc - 1 - pc
			end
			code.fixup[code.bc_pc] = nil
			code.reachable = true
		end
		-- Execute
		if code.reachable then
			return t[op](a, b, c, d)
		end
	end,
})
end

-- Emitted code dump
local function dump_mem(cls, ins)
	local mode = bit.band(ins.code, 0xe0)
	if mode == BPF.XADD then cls = 5 end -- The only mode
	local op_1 = {'LD', 'LDX', 'ST', 'STX', '', 'XADD'}
	local op_2 = {[0]='W', [8]='H', [16]='B', [24]='DW'}
	local name = op_1[cls+1] .. op_2[bit.band(ins.code, 0x18)]
	local off = tonumber(ffi.cast('int16_t', ins.off)) -- Reinterpret as signed
	local dst = cls < 2 and 'R'..ins.dst_reg or string.format('[R%d%+d]', ins.dst_reg, off)
	local src = cls % 2 == 0 and '#'..ins.imm or 'R'..ins.src_reg
	if cls == BPF.LDX then src = string.format('[R%d%+d]', ins.src_reg, off) end
	if mode == BPF.ABS then src = string.format('[%d]', ins.imm) end
	if mode == BPF.IND then src = string.format('[R%d%+d]', ins.src_reg, ins.imm) end
	return string.format('%s\t%s\t%s', name, dst, src)
end
local function dump_alu(cls, ins, pc)
	local alu = {'ADD', 'SUB', 'MUL', 'DIV', 'OR', 'AND', 'LSH', 'RSH', 'NEG', 'MOD', 'XOR', 'MOV', 'ARSH', 'END' }
	local jmp = {'JA', 'JEQ', 'JGT', 'JGE', 'JSET', 'JNE', 'JSGT', 'JSGE', 'CALL', 'EXIT'}
	local helper = {'unspec', 'map_lookup_elem', 'map_update_elem', 'map_delete_elem', 'probe_read', 'ktime_get_ns',
					'trace_printk', 'get_prandom_u32', 'get_smp_processor_id', 'skb_store_bytes',
					'l3_csum_replace', 'l4_csum_replace', 'tail_call'}
	local op = 0
	for i = 0,13 do if 0x10 * i == bit.band(ins.code, 0xf0) then op = i + 1 break end end
	local name = (cls == 5) and jmp[op] or alu[op]
	local src = (bit.band(ins.code, 0x08) == BPF.X) and 'R'..ins.src_reg or '#'..ins.imm
	local target = (cls == 5 and op < 9) and string.format('\t=> %04d', pc + ins.off + 1) or ''
	if cls == 5 and op == 9 then target = string.format('\t; %s', helper[ins.imm + 1] or tostring(ins.imm)) end
	return string.format('%s\t%s\t%s%s', name, 'R'..ins.dst_reg, src, target)
end
local function dump(code)
	if not code then return end
	print(string.format('-- BPF %s:0-%u', code.insn, code.pc))
	local cls_map = {
		[0] = dump_mem, [1] = dump_mem, [2] = dump_mem, [3] = dump_mem,
		[4] = dump_alu, [5] = dump_alu, [7] = dump_alu,
	}
	for i = 0, code.pc - 1 do
		local ins = code.insn[i]
		local cls = bit.band(ins.code, 0x07)
		print(string.format('%04u\t%s', i, cls_map[cls](cls, ins, i)))
	end
end

-- BPF map interface
local bpf_map_mt = {
	__gc = function (map) S.close(map.fd) end,
	__len = function(map) return map.max_entries end,
	__index = function (map, k)
		if type(k) == 'string' then
			-- Return iterator
			if k == 'pairs' then
				return function(t, k)
					-- Get next key
					local next_key = ffi.new(ffi.typeof(t.key))
					t.key[0] = k or 0
					local ok, err = S.bpf_map_op(c.BPF_CMD.MAP_GET_NEXT_KEY, map.fd, map.key, next_key)
					if not ok then return nil end
					-- Get next value
					assert(S.bpf_map_op(c.BPF_CMD.MAP_LOOKUP_ELEM, map.fd, next_key, map.val))
					return next_key[0], map.val[0]
				end, map, nil
			end
			-- Signalise this is a map type
			return k == '__map'
		end
		-- Retrieve key
		map.key[0] = k
		local ok, err = S.bpf_map_op(c.BPF_CMD.MAP_LOOKUP_ELEM, map.fd, map.key, map.val)
		if not ok then return nil, err end
		return ffi.new(map.val_type, map.val[0])
	end,
	__newindex = function (map, k, v)
		map.key[0] = k
		if v == nil then
			return S.bpf_map_op(map.fd, c.BPF_CMD.MAP_DELETE_ELEM, map.key, nil)
		end
		map.val[0] = v
		return S.bpf_map_op(c.BPF_CMD.MAP_UPDATE_ELEM, map.fd, map.key, map.val)
	end,
}

-- Linux tracing interface
local function trace_check_enabled(path)
	path = path or '/sys/kernel/debug/tracing'
	if S.statfs(path) then return true end
	return nil, 'debugfs not enabled: "mount -t debugfs nodev /sys/kernel/debug" ?'
end

local function trace_bpf(tp, ptype, pname, pdef, retprobe, prog, pid, cpu, group_fd)
	-- Load BPF program
	local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.KPROBE, prog.insn, prog.pc)
	assert(prog_fd, tostring(err)..': '..tostring(log))
	-- Open tracepoint and attach
	local tp, err = S.perf_probe(ptype, pname, pdef, retprobe)
	if not tp then
		prog_fd:close()
		return nil, tostring(err)
	end
	local reader, err = S.perf_attach_tracepoint(tp, pid, cpu, group_fd, {sample_type='raw, callchain'})
	if not reader then
		prog_fd:close()
		S.perf_probe(ptype, pname, false)
		return nil, tostring(err)
	end
	local ok, err = reader:setbpf(prog_fd:getfd())
	if not ok then
		prog_fd:close()
		reader:close()
		S.perf_probe(ptype, pname, false)
		return nil, tostring(err)..' (kernel version should be at least 4.1)'
	end
	-- Create GC closure for reader to close BPF program
	-- and detach probe in correct order
	ffi.gc(reader, function ()
		prog_fd:close()
		reader:close()
		S.perf_probe(ptype, pname, false)
	end)
	return {reader=reader, prog=prog_fd, probe=pname, probe_type=ptype}
end

-- Module interface
return setmetatable({
	new = create_emitter,
	dump = dump,
	prog = PROG,
	maps = {},
	map = function (type, max_entries, key_ctype, val_ctype)
		if not key_ctype then key_ctype = ffi.typeof('uint32_t') end
		if not val_ctype then val_ctype = ffi.typeof('uint32_t') end
		if not max_entries then max_entries = 4096 end
		local fd, err = S.bpf_map_create(c.BPF_MAP[type], ffi.sizeof(key_ctype), ffi.sizeof(val_ctype), max_entries)
		if not fd then return nil, tostring(err) end
		local map = setmetatable({
			max_entries = max_entries,
			key = ffi.new(ffi.typeof('$ [1]', key_ctype)),
			val = ffi.new(ffi.typeof('$ [1]', val_ctype)),
			key_type = key_ctype,
			val_type = val_ctype,
			fd = fd:nogc():getfd(),
		}, bpf_map_mt)
		return map
	end,
	socket = function (sock, prog)
		-- Expect socket type, if sock is string then assume it's
		-- an interface name (e.g. 'lo'), if it's a number then typecast it as a socket
		if type(sock) == 'string' then
			local iface = assert(S.nl.getlink())[sock]
			assert(iface, sock..' is not interface name')
			sock = assert(S.socket('packet', 'raw'))
			assert(sock:bind(S.t.sockaddr_ll({protocol='all', ifindex=iface.index})))
		elseif type(sock) == 'number' then
			sock = assert(S.t.socket(sock))
		end
		-- Load program and attach it to socket
		local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.SOCKET_FILTER, prog.insn, prog.pc)
		assert(prog_fd, tostring(err)..': '..tostring(log))
		assert(sock:setsockopt('socket', 'attach_bpf', prog_fd:getfd()))
		return prog_fd, err
	end,
	tracepoint = function(tp, prog, pid, cpu, group_fd)
		error('NYI: no kernel support for static tracepoints yet')
		-- -- Load the BPF program
		-- local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.TRACEPOINT, prog.insn, prog.pc)
		-- assert(prog_fd, tostring(err)..': '..tostring(log))
		-- -- Open tracepoint and attach
		-- local tp = assert(S.perf_tracepoint("/sys/kernel/debug/tracing/events/"..tp))
		-- local reader = assert(S.perf_attach_tracepoint(tp, pid, cpu, group_fd))
		-- reader:setbpf(prog_fd:getfd())
		-- return reader, prog_fd
	end,
	kprobe = function(tp, prog, retprobe, pid, cpu, group_fd)
		assert(trace_check_enabled())
		-- Open tracepoint and attach
		local pname, pdef = tp:match('([^:]+):(.+)')
		return trace_bpf(tp, 'kprobe', pname, pdef, retprobe, prog, pid, cpu, group_fd)
	end,
	uprobe = function(tp, prog, retprobe, pid, cpu, group_fd)
		assert(trace_check_enabled())
		-- Translate symbol to address
		local obj, sym_want = tp:match('([^:]+):(.+)')
		if not S.statfs(obj) then return nil, S.t.error(S.c.E.NOENT) end
		-- Resolve Elf object (no support for anything else)
		local elf = require('bpf.elf').open(obj)
		local sym = elf:resolve(sym_want)
		if not sym then return nil, 'no such symbol' end
		sym = sym.st_value - elf:loadaddr()
		local sym_addr = string.format('%x%04x', tonumber(bit.rshift(sym, 32)),
		                                         tonumber(ffi.cast('uint32_t', sym)))
		-- Convert it to expected uprobe format
		local pname = string.format('%s_%s', obj:gsub('.*/', ''), sym_addr)
		local pdef = obj..':0x'..sym_addr
		return trace_bpf(tp, 'uprobe', pname, pdef, retprobe, prog, pid, cpu, group_fd)
	end,
	tracelog = function(path)
		assert(trace_check_enabled())
		path = path or '/sys/kernel/debug/tracing/trace_pipe'
		return io.open(path, 'r')
	end,
	ntoh = builtins.ntoh, hton = builtins.hton,
}, {
	__call = function (t, prog)
		-- Create code emitter sandbox, include caller locals
		local env = { pkt=proto.pkt }
		local i = 1
		while true do
			local n, v = debug.getlocal(2, i)
			if not n then break end
			env[n] = v
			i = i + 1
		end
		setmetatable(env, {
			__index = function (t, k)
				return proto[k] or builtins[k] or _G[k]
			end
		})
		-- Create code emitter and compile LuaJIT bytecode
		if type(prog) == 'string' then prog = loadstring(prog) end
		-- Create error handler to print traceback
		local funci, pc = bytecode.funcinfo(prog), 0
		local E = create_emitter(env, funci.stackslots, funci.params)
		local on_err = function (e)
				local funci = bytecode.funcinfo(prog, pc)
				local from, to = 0, 0
				for i=1,funci.currentline do
					from = to
					to = string.find(funci.source, '\n', from+1, true) or 0
				end
				print(funci.loc..':'..string.sub(funci.source, from+1, to-1))
				print('error: '..e)
				print(debug.traceback())
		end
		for pc,op,a,b,c,d in bytecode.decoder(prog) do
			local ok, res, err = xpcall(E,on_err,op,a,b,c,d)
			if not ok then
				return nil
			end
		end
		return E:compile()
	end,
})