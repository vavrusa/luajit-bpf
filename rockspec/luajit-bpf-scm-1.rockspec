package = "luajit-bpf"
version = "0.1-1"
source = {
   url = "git://git@gitlab.com:vavrusa/luajit-bpf.git"
}
description = {
   summary = "A LuaJIT to extended BPF compiler.",
   detailed = [[
   ]],
   homepage = "https://gitlab.com/vavrusa/luajit-bpf",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "ljsyscall >= scm",
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
