-- This example program measures latency of block device operations and plots it
-- in a histogram. It is similar to BPF example:
-- https://github.com/torvalds/linux/blob/master/samples/bpf/tracex3_kern.c
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')

-- Shared part of the program
local bins = 100
local map = bpf.map('hash', 512, ffi.typeof('uint64_t'), ffi.typeof('uint64_t'))
local lat_map = bpf.map('array', bins)

-- Kernel-space part of the program
local trace_start = assert(bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs)
	map[req.parm1] = time()
end))
local trace_end = assert(bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs)
	-- The lines below are computing index
	-- using log10(x)*10 = log2(x)*10/log2(10) = log2(x)*3
	-- index = 29 ~ 1 usec
	-- index = 59 ~ 1 msec
	-- index = 89 ~ 1 sec
	-- index = 99 ~ 10sec or more
	local delta = time() - map[req.parm1]
	local index = 3 * math.log2(delta)
	if index >= bins then
		index = bins-1
	end
	xadd(lat_map[index], 1)
	return true
end))
local probes = {
	bpf.kprobe('myprobe:blk_start_request', trace_start, false, -1, 0),
	bpf.kprobe('myprobe2:blk_account_io_completion', trace_end, false, -1, 0),
}
-- User-space part of the program
pcall(function()
	local counter = 0
	local sym = {' ',' ','.','.','*','*','o','o','O','O','#','#'}
	while true do
		-- Print header once in a while
		if counter % 50 == 0 then
			print('|1us      |10us     |100us    |1ms      |10ms     |100ms    |1s       |10s')
			counter = 0
		end
		counter = counter + 1
		-- Collect all events
		local hist, events = {}, 0
		for i=29,bins-1 do
			local v = tonumber(lat_map[i] or 0)
			if v > 0 then
				hist[i] = hist[i] or 0 + v
				events = events + v
			end
		end
		-- Print histogram symbols based on relative frequency
		local s = ''
		for i=29,bins-1 do
			if hist[i] then
				local c = math.ceil((hist[i] / (events + 1)) * #sym)
				s = s .. sym[c]
			else s = s .. ' ' end
		end
		print(s .. string.format('  ; %d events', events))
		S.sleep(1)
	end
end)