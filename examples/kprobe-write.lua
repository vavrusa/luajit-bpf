-- Simple tracing example that executes a program on
-- return from sys_write() and tracks the number of hits
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')

-- Shared part of the program
local map = bpf.map('array', 1)
-- Kernel-space part of the program
local probe = assert(bpf.kprobe('myprobe:sys_write', bpf(function (ptregs)
   xadd(map[0], 1)
end), true))
-- User-space part of the program
pcall(function()
	for i=1,10 do
	   print('hits: ', tonumber(map[0]))
	   S.sleep(1)
	end
end)
probe:close()
