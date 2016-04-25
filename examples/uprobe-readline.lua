-- Trace readline() call from all bash instances (print bash commands from all running shells).
-- This is rough equivallent to `bashreadline`
-- Source: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Kernel-space part of the program
local prog = bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs) -- Cast to pt_regs, specialized type.
	local line = ffi.new('char [40]')              -- Create a 40 byte buffer on stack
	ffi.copy(line, ffi.cast('char *', req.ax))     -- Cast `ax` to string pointer and copy to buffer
	print('%s\n', line)                            -- Print to trace_pipe
end)
bpf.dump(prog)
local probe = assert(bpf.uprobe('/bin/bash:readline', prog, true, -1, 0))
-- User-space part of the program
local ok, err = pcall(function()
	local log = bpf.tracelog()
	print('            TASK-PID   CPU#         TIMESTAMP  FUNCTION')
	print('               | |      |               |         |')
	while true do
		print(log:read())
	end
end)
