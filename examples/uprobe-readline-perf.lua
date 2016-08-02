-- Trace readline() call from all bash instances (print bash commands from all running shells).
-- This is rough equivallent to `bashreadline` with output through perf event API.
-- Source: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Perf event map
-- FIXME: better API in ljsyscall with dynamic typing
local event_t = ffi.typeof 'struct { struct perf_event_header header; uint32_t len; char data[80]; } *'
local events = bpf.map('perf_event_array')
-- Kernel-space part of the program
local prog = bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs) -- Cast to pt_regs, specialized type.
	local line = ffi.new('char [80]')              -- Create a byte buffer on stack
	ffi.copy(line, ffi.cast('char *', req.ax))     -- Cast `ax` to string pointer and copy to buffer
	table.insert(events, line)                     -- Write buffer to perf event map
	-- FIXME: support for structures as perf event data, not just byte buffers
end)
bpf.dump(prog)
local probe = assert(bpf.uprobe('/bin/bash:readline', prog, true, -1, 0))
-- User-space part of the program
local log = events:reader(nil, 0) -- Must specify PID or CPU_ID to observe
print('            TASK-PID         TIMESTAMP  FUNCTION')
print('               | |               |         |')
while true do
	S.select { readfds = {log.fd} } -- Wait until event reader is readable
	for len,e in ipairs(log) do     -- Collect all reader events
		e = ffi.cast(event_t, e)    -- FIXME: better API in ljsyscall with dynamic typing
		print(string.format('%12s%-16s %-10s %s', '', 'x', os.date("%H:%M:%S"), ffi.string(e.data)))
	end
end
