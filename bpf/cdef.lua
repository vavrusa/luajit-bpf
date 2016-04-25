local ffi = require('ffi')
local M = {}

ffi.cdef [[
struct bpf {
	/* Instruction classes */
	static const int LD   = 0x00;
	static const int LDX  = 0x01;
	static const int ST   = 0x02;
	static const int STX  = 0x03;
	static const int ALU  = 0x04;
	static const int JMP  = 0x05;
	static const int ALU64 = 0x07;
	/* ld/ldx fields */
	static const int W    = 0x00;
	static const int H    = 0x08;
	static const int B    = 0x10;
	static const int ABS  = 0x20;
	static const int IND  = 0x40;
	static const int MEM  = 0x60;
	static const int LEN  = 0x80;
	static const int MSH  = 0xa0;
	/* alu/jmp fields */
	static const int ADD  = 0x00;
	static const int SUB  = 0x10;
	static const int MUL  = 0x20;
	static const int DIV  = 0x30;
	static const int OR   = 0x40;
	static const int AND  = 0x50;
	static const int LSH  = 0x60;
	static const int RSH  = 0x70;
	static const int NEG  = 0x80;
	static const int MOD  = 0x90;
	static const int XOR  = 0xa0;
	static const int JA   = 0x00;
	static const int JEQ  = 0x10;
	static const int JGT  = 0x20;
	static const int JGE  = 0x30;
	static const int JSET = 0x40;
	static const int K    = 0x00;
	static const int X    = 0x08;
	static const int JNE  = 0x50;	/* jump != */
	static const int JSGT = 0x60;	/* SGT is signed '>', GT in x86 */
	static const int JSGE = 0x70;	/* SGE is signed '>=', GE in x86 */
	static const int CALL = 0x80;	/* function call */
	static const int EXIT = 0x90;	/* function return */
	/* ld/ldx fields */
	static const int DW    = 0x18;	/* double word */
	static const int XADD  = 0xc0;	/* exclusive add */
	/* alu/jmp fields */
	static const int MOV   = 0xb0;	/* mov reg to reg */
	static const int ARSH  = 0xc0;	/* sign extending arithmetic shift right */
	/* change endianness of a register */
	static const int END   = 0xd0;	/* flags for endianness conversion: */
	static const int TO_LE = 0x00;	/* convert to little-endian */
	static const int TO_BE = 0x08;	/* convert to big-endian */
	/* misc */
	static const int PSEUDO_MAP_FD = 0x01;
};
/* eBPF commands */
struct bpf_cmd {
	static const int MAP_CREATE       = 0;
	static const int MAP_LOOKUP_ELEM  = 1;
	static const int MAP_UPDATE_ELEM  = 2;
	static const int MAP_DELETE_ELEM  = 3;
	static const int MAP_GET_NEXT_KEY = 4;
	static const int PROG_LOAD        = 5;
	static const int OBJ_PIN          = 6;
	static const int OBJ_GET          = 7;
};
/* eBPF program types */
struct bpf_prog {
	static const int UNSPEC        = 0;
	static const int SOCKET_FILTER = 1;
	static const int KPROBE        = 2;
	static const int SCHED_CLS     = 3;
	static const int SCHED_ACT     = 4;
};
/* eBPF helpers */
struct bpf_func_id {
	static const int unspec               = 0;
	static const int map_lookup_elem      = 1;
	static const int map_update_elem      = 2;
	static const int map_delete_elem      = 3;
	static const int probe_read           = 4;
	static const int ktime_get_ns         = 5;
	static const int trace_printk         = 6;
	static const int get_prandom_u32      = 7;
	static const int get_smp_processor_id = 8;
	static const int skb_store_bytes      = 9;
	static const int l3_csum_replace      = 10;
	static const int l4_csum_replace      = 11;
	static const int tail_call            = 12;
	static const int clone_redirect       = 13;
	static const int get_current_pid_tgid = 14;
	static const int get_current_uid_gid  = 15;
	static const int get_current_comm     = 16;
	static const int get_cgroup_classid   = 17;
	static const int skb_vlan_push        = 18;
	static const int skb_vlan_pop         = 19;
	static const int skb_get_tunnel_key   = 20;
	static const int skb_set_tunnel_key   = 21;
	static const int perf_event_read      = 22;
	static const int redirect             = 23;
	static const int get_route_realm      = 24;
	static const int perf_event_output    = 25;
	static const int skb_load_bytes       = 26;
};
]]

-- Compatibility: ljsyscall doesn't have support for BPF syscall
local S = require('syscall')
if not S.bpf then
	function S.bpf () error("ljsyscall doesn't support bpf(), must be updated") end
end 

-- Reflect cdata type
function M.typename(v)
	if not v or type(v) ~= 'cdata' then return nil end
	return string.match(tostring(ffi.typeof(v)), '<([^>]+)')
end

-- Reflect if cdata type can be pointer (accepts array or pointer) 
function M.isptr(v, noarray)
	local ctname = M.typename(v)
	if ctname then
		ctname = string.sub(ctname, -1)
		ctname = ctname == '*' or (not noarray and ctname == ']')
	end
	return ctname
end

return M