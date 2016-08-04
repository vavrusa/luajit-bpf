[![Build Status](https://travis-ci.org/vavrusa/luajit-bpf.svg?branch=master)](https://travis-ci.org/vavrusa/luajit-bpf)

# LuaJIT to extended BPF compiler

Why? BPF allows you to execute a small sandboxed programs directly in kernel, that can talk back to userspace over shared maps. Since the programs are small and verified, they are guaranteed not to crash or lock the kernel. That's fantastic not only as a performance introspection tool with tracepoints and probes, but also for low-latency packet filtering, load-balancing, IPS and a ton of other purposes.

However, it's not dead simple to use as Brendan Greggs puts it:

> it's hard to use via its assembly or C interface. The challenge attracts me, but it can be a brutal experience, especially if you write eBPF assembly directly (eg, see `bpf_insn_prog[]` from sock_example.c; I've yet to code one of these from scratch that compiles). The C interface is better (see other examples in [samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)), but it's still laborious and difficult to use.

Now it possible to write Lua functions and compile them transparently to BPF byte code, here's the same socket example:

```lua
local bpf = require('bpf')
local map = bpf.map('array', 256)
-- Kernel-space part of the program
local prog = assert(bpf(function ()
	local proto = pkt.ip.proto  -- Get byte (ip.proto) from frame at [23]
	xadd(map[proto], 1)         -- Increment packet count
end))
-- User-space part of the program
local S = require('ljsyscall')
local sock = assert(bpf.socket('lo', prog))
for i=1,10 do
	local icmp, udp, tcp = map[1], map[17], map[6]
	print('TCP', tcp, 'UDP', udp, 'ICMP', icmp, 'packets')
	S.sleep(1)
end
```

Similarly, the [bcc][bcc] project uses LLVM rewriter to compile C code with BPF-specific extensions to BPF bytecode. This project takes a function in Lua, decodes its bytecode and compiles it into BPF. What's the difference? luajit-bpf integrates seamlessly with existing code (and access existing Lua upvalues), no user/kernel-space separations, ELF walking and no embedded C code.

The other application of BPF programs is attaching to probes for [perf event tracing][tracing]. That means you can trace events inside the kernel (or user-space), and then collect results - for example histogram of `sendto()` latency, off-cpu time stack traces, syscall latency, and so on. While kernel probes and perf events have unstable ABI, with a dynamic language we can create and use proper type based on the tracepoint ABI on runtime.

Runtime automatically recognizes memory that needs a helper to be accessed. The type casts denote source of the memory, for example the [bashreadline][bashreadline] example that prints entered bash commands from all running shells:

```lua
local ffi = require('ffi')
local bpf = require('bpf')
-- Kernel-space part of the program
local prog = bpf(function (ptregs)
	local req = ffi.cast('struct pt_regs', ptregs) -- Cast to pt_regs, specialized type.
	local line = ffi.new('char [40]')              -- Create a 40 byte buffer on stack
	ffi.copy(line, ffi.cast('char *', req.ax))     -- Cast `ax` to string pointer and copy to buffer
	print('%s\n', line)                            -- Print to trace_pipe
end)
local probe = assert(bpf.uprobe('/bin/bash:readline', prog, true, -1, 0))
-- User-space part of the program
local ok, err = pcall(function()
	local log = bpf.tracelog()
	print('            TASK-PID   CPU#         TIMESTAMP  FUNCTION')
	print('               | |      |               |         |')
	while true do
		print(log:read()) -- Tail trace_pipe log
	end
end)
```

Where cast to `struct pt_regs` flags the source of data as probe arguments, which means any pointer derived
from this structure points to kernel and a helper is needed to access it. Casting `req.ax` to pointer is then required for `ffi.copy` semantics, otherwise it would be treated as `u64` and only it's value would be
copied.

## Installation

```bash
$ luarocks install bpf
```

## Examples

See `examples` directory.

### Helpers

* `print(...)` is a wrapper for `bpf_trace_printk`, the output is captured in `cat /sys/kernel/debug/tracing/trace_pipe`
* `bit.*` library **is** supported (`lshift, rshift, arshift, bnot, band, bor, bxor`)
* `math.*` library *partially* supported (`log2, log, log10`)
* `ffi.cast()` is implemented
* `ffi.new(...)` allocates memory on stack, initializers are NYI
* `ffi.copy(...)` copies memory (possibly using helpers) between stack/kernel/registers
* `ntoh(x[, width])` - convert from network to host byte order.
* `hton(x[, width])` - convert from host to network byte order.
* `xadd(dst, inc)` - exclusive add, a synchronous `*dst += b` if Lua had `+=` operator

Below is a list of BPF-specific helpers:

* `time()` - return current monotonic time in nanoseconds (uses `bpf_ktime_get_ns`)
* `cpu()` - return current CPU number (uses `bpf_get_smp_processor_id`)
* `pid_tgid()` - return caller `tgid << 32 | pid` (uses `bpf_get_current_pid_tgid`)
* `uid_gid()` - return caller `gid << 32 | uid` (uses `bpf_get_current_uid_gid`)
* `perf_submit(map, var)` - submit variable to perf event array BPF map

## Current state

* Not all LuaJIT bytecode opcodes are supported *(notable mentions below)*
* Closures `UCLO` will probably never be supported, although you can use upvalues inside compiled function.
* Type narrowing is opportunistic. Numbers are 64-bit by default, but 64-bit immediate loads are not supported (e.g. `local x = map[ffi.cast('uint64_t', 1000)]`)
* Tail calls `CALLT`, and iterators `ITERI` are NYI (as of now)
* Arbitrary ctype **is** supported both for map keys and values
* Basic optimisations like: constant propagation, partial DCE, liveness analysis and speculative register allocation are implement, but there's no control flow analysis yet. This means the compiler has the visibility when things are used and dead-stores occur, but there's no rewriter pass to eliminate them.
* No register sub-allocations, no aggressive use of caller-saved `R1-5`, no aggressive narrowing (this would require variable range assertions and variable relationships)
* Slices with not 1/2/4/8 length are NYI (requires allocating a memory on stack and using pointer type)


[bcc]: https://github.com/iovisor/bcc
[tracing]: http://www.brendangregg.com/blog/2016-03-05/linux-bpf-superpowers.html
[bashreadline]: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
