-- Simple parsing example of UDP/DNS that counts frequency of QTYPEs.
-- It shows how to parse packet variable-length packet structures.
local ffi = require("ffi")
local bpf = require("bpf")
local S = require("syscall")

-- Shared part of the program
local map = assert(bpf.map('array', 256))
-- Kernel-space part of the program
local prog = bpf.socket('lo', bpf(function (skb)
	local ip = pkt.ip   -- Accept only UDP messages
	if ip.proto ~= c.ip.proto_udp then return false end
	local udp = ip.udp  -- Only messages >12 octets (DNS header)
	if udp.length < 12 then return false end
	-- Unroll QNAME (up to 2 labels)
	udp = udp.data + 12
	local label = udp[0]
	if label > 0 then
		udp = udp + label + 1
		label = udp[0]
		if label > 0 then
			udp = udp + label + 1
		end
	end
	-- Track QTYPE (low types)
	if udp[0] == 0 then
		local qtype = udp[2] -- Low octet from QTYPE
		xadd(map[qtype], 1)
	end
end))
-- User-space part of the program
for _ = 1, 10 do
	for k,v in map.pairs,map,0 do
		v = tonumber(v)
		if v > 0 then
			print(string.format('TYPE%d: %d', k, v))
		end
	end
	S.sleep(1)
end