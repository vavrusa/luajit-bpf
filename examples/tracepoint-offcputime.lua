-- Summarize off-CPU time by stack trace
-- Related tool: https://github.com/iovisor/bcc/blob/master/tools/offcputime.py
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Create BPF maps
-- TODO: made smaller to fit default memory limits
local key_t = 'struct { char name[16]; int32_t stack_id; }'
local starts = assert(bpf.map('hash', 128, ffi.typeof('uint32_t'), ffi.typeof('uint64_t')))
local counts = assert(bpf.map('hash', 128, ffi.typeof(key_t), ffi.typeof('uint64_t')))
local stack_traces = assert(bpf.map('stack_trace', 16))
-- Open tracepoint and attach BPF program
-- The 'arg' parses tracepoint format automatically
local tp = bpf.tracepoint('sched/sched_switch', function (arg)
	-- Update previous thread sleep time
	local pid = arg.prev_pid
	local now = time()
	starts[pid] = now
	-- Calculate current thread's delta time
	pid = arg.next_pid
	local from = starts[pid]
	if not from then
		return 0
	end
	local delta = (now - from) / 1000
	starts[pid] = nil
	-- Check if the delta is below 1us
	if delta < 1 then
		return
	end
	-- Create key for this thread
	local key = ffi.new(key_t)
	comm(key.name)
	key.stack_id = stack_id(stack_traces, BPF.F_FAST_STACK_CMP)
	-- Update current thread off cpu time with delta
	local val = counts[key]
	if not val then
		counts[key] = 0
	end
	xadd(counts[key], delta)
end, 0, -1)
-- Helper: load kernel symbols
ffi.cdef 'unsigned long long strtoull(const char *, char **, int);'
local ksyms = {}
for l in io.lines('/proc/kallsyms') do
	local addr, sym = l:match '(%w+) %w (%S+)'
	if addr then ksyms[ffi.C.strtoull(addr, nil, 16)] = sym end
end
-- User-space part of the program
while true do
	for k,v in counts.pairs,counts,nil do
		local s = ''
		local traces = stack_traces[k.stack_id]
		if traces then
			for i, ip in ipairs(traces) do
				s = s .. string.format("    %-16p %s", ip, ksyms[ip])
			end
		end
		s = s .. string.format("    %-16s %s", "-", ffi.string(k.name))
		s = s .. string.format("        %d", tonumber(v))
		print(s)
	end
	S.sleep(1)
end
