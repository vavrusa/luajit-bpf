-- Trace operations on keys matching given pattern in KyotoTycoon daemon.
-- This can show you if certain keys were modified or read during the lifetime
-- even if KT doesn't support this. It also shows how to attach to C++ mangled symbols.
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
local function help(err)
	print(string.format('%s [get|set] [key]', arg[0]))
	if err then print('error: '..err) end
	os.exit(1)
end
-- Accept the same format as ktremotemgr for clarity: <get|set> <key>
local writeable, watch_key, klen = 'any', arg[2] or '*', 80
if     arg[1] == 'get' then writeable = 0
elseif arg[1] == 'set' then writeable = 1
elseif arg[1] == '-h' or arg[1] == '--help' then help()
elseif arg[1] and arg[1] ~= 'any' then
	help(string.format('bad cmd: "%s"', arg[1]))
end
if watch_key ~= '*' then klen = #watch_key end

-- Find a good entrypoint that has both key and differentiates read/write in KT
-- That is going to serve as an attachment point for BPF program
-- ABI: bool accept(void *this, const char* kbuf, size_t ksiz, Visitor* visitor, bool writable)
local key_type = string.format('char [%d]', klen)
local prog = bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs) -- Cast to pt_regs, specialized type.
	-- Watch either get/set or both
	if writeable ~= 'any' then
		if req.parm5 ~= writeable then return end
	end
	local line = ffi.new(key_type)
	ffi.copy(line, ffi.cast('char *', req.parm2))
	-- Check if we're looking for specific key
	if watch_key ~= '*' then
		if req.parm3 ~= klen then return false end
		if line ~= watch_key then return false end
	end
	print('%s write:%d\n', line, req.parm5)
end)
local probe = assert(bpf.uprobe('/usr/local/bin/ktserver:kyotocabinet::StashDB::accept', prog, false, -1, 0))
-- User-space part of the program
local ok, err = pcall(function()
	local log = bpf.tracelog()
	print('            TASK-PID   CPU#         TIMESTAMP  FUNCTION')
	print('               | |      |               |         |')
	while true do
		print(log:read())
	end
end)
