package = "bpf"
version = "scm-1"
source = {
   url = "git+https://github.com/vavrusa/luajit-bpf.git"
}
description = {
   summary = "A LuaJIT to BPF compiler.",
   detailed = [[
   ]],
   homepage = "https://github.com/vavrusa/luajit-bpf",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "ljsyscall >= 0.12",
}
external_dependencies = {
    LIBELF = {
       library = "elf"
    }
}
build = {
  type = "builtin",
  install = {
    bin = {
    }
  },
  modules = {
    ["bpf.builtins"] = "bpf/builtins.lua",
    ["bpf.cdef"] = "bpf/cdef.lua",
    ["bpf.elf"] = "bpf/elf.lua",
    ["bpf.proto"] = "bpf/proto.lua",
    ["bpf.ljbytecode"] = "bpf/ljbytecode.lua",
    bpf = "bpf.lua",
  }
}
