"""Interesting gadget patterns for ROP/JOP chain construction."""

# ARM64 gadget classifiers for cb gadget (regex-based categorization)
# x86_64 gadget classifiers for cb gadget (regex-based categorization)
X86_64_CLASSIFIERS = {
    "stack_pivot":      [r"xchg\s+.*rsp", r"mov\s+rsp,", r"leave"],
    "register_control": [r"pop\s+r(di|si|dx|cx|ax|8|9)", r"pop\s+rbp"],
    "memory_write":     [r"mov\s+.*\[r\w+\],\s*r\w+", r"mov\s+.*\[rsp"],
    "memory_read":      [r"mov\s+r\w+,\s*.*\[r\w+"],
    "syscall":          [r"syscall", r"int\s+0x80"],
    "function_call":    [r"call\s+r\w+", r"jmp\s+r\w+"],
}

# Chain templates for x86_64 (rax = syscall number)
CHAIN_TEMPLATES_X86_64 = {
    "execve": {
        "description": "execve('/bin/sh', NULL, NULL)",
        "needs": ["register_control", "syscall"],
        "registers": {"rdi": "/bin/sh", "rsi": "NULL", "rdx": "NULL", "rax": "59"},
    },
    "mprotect_shellcode": {
        "description": "mprotect(addr, size, RWX) + jump to shellcode",
        "needs": ["register_control", "syscall", "stack_pivot"],
        "registers": {"rdi": "page_addr", "rsi": "0x4000", "rdx": "7", "rax": "10"},
    },
    "dlopen_dlsym": {
        "description": "dlopen + dlsym to load and call arbitrary function",
        "needs": ["register_control", "function_call"],
        "call_sequence": ["dlopen", "dlsym", "call"],
    },
}

ARM64_CLASSIFIERS = {
    "stack_pivot":      [r"mov\s+sp,\s*x\d+", r"add\s+sp,\s+sp,\s+#"],
    "register_control": [r"ldp\s+x\d+.*\[sp", r"ldr\s+x0,\s*\[sp"],
    "memory_write":     [r"str\s+[xw]\d+,\s*\[[xw]\d+", r"stp\s+[xw]\d+"],
    "memory_read":      [r"ldr\s+[xw]\d+,\s*\[[xw]\d+"],
    "syscall":          [r"svc\s+#"],
    "function_call":    [r"blr\s+x\d+", r"br\s+x\d+"],
}

# Chain templates for macOS ARM64 (x16 = syscall number)
CHAIN_TEMPLATES = {
    "execve": {
        "description": "execve('/bin/sh', NULL, NULL)",
        "needs": ["register_control", "syscall"],
        "registers": {"x0": "/bin/sh", "x1": "NULL", "x2": "NULL", "x16": "59"},
    },
    "mprotect_shellcode": {
        "description": "mprotect(addr, size, RWX) + jump to shellcode",
        "needs": ["register_control", "syscall", "stack_pivot"],
        "registers": {"x0": "page_addr", "x1": "0x4000", "x2": "7", "x16": "74"},
    },
    "posix_spawn": {
        "description": "posix_spawn to execute arbitrary binary",
        "needs": ["register_control", "function_call"],
        "call": "posix_spawn",
    },
    "dlopen_dlsym": {
        "description": "dlopen + dlsym to load and call arbitrary function",
        "needs": ["register_control", "function_call"],
        "call_sequence": ["dlopen", "dlsym", "blr"],
    },
}

# Common useful gadget patterns to search for with cb grep --mode gadgets
ARM64_GADGETS = {
    "stack_pivot": r"mov sp,",
    "syscall": r"svc",
    "function_call": r"blr x",
    "indirect_branch": r"br x",
    "load_pair": r"ldp x\d+, x\d+.*ret",
    "store_pair": r"stp x\d+, x\d+",
    "mov_x0": r"mov x0,.*ret",
    "mov_x1": r"mov x1,.*ret",
    "load_x0": r"ldr x0,.*ret",
    "write_where": r"str x\d+, \[x\d+\].*ret",
    "add_sp": r"add sp, sp,.*ret",
}

X86_64_GADGETS = {
    "pop_rdi": r"pop rdi.*ret",
    "pop_rsi": r"pop rsi.*ret",
    "pop_rdx": r"pop rdx.*ret",
    "pop_rax": r"pop rax.*ret",
    "pop_rcx": r"pop rcx.*ret",
    "syscall": r"syscall",
    "mov_rdi_rax": r"mov rdi, rax.*ret",
    "mov_rsi_rax": r"mov rsi, rax.*ret",
    "write_where": r"mov.*\[r\w+\], r\w+.*ret",
    "stack_pivot": r"xchg.*rsp.*ret",
    "leave_ret": r"leave.*ret",
    "jmp_rax": r"jmp rax",
    "call_rax": r"call rax",
}

# Gadget chains for common exploitation primitives
USEFUL_CHAINS = {
    "execve_x86_64": {
        "description": "Set up execve('/bin/sh', NULL, NULL) on x86_64",
        "needed": ["pop_rdi", "pop_rsi", "pop_rdx", "pop_rax", "syscall"],
        "notes": "rax=59 (execve), rdi=/bin/sh, rsi=0, rdx=0",
    },
    "mprotect_x86_64": {
        "description": "Set up mprotect(addr, size, PROT_RWX) on x86_64",
        "needed": ["pop_rdi", "pop_rsi", "pop_rdx", "pop_rax", "syscall"],
        "notes": "rax=10 (mprotect), rdi=addr, rsi=size, rdx=7 (RWX)",
    },
    "write_what_where": {
        "description": "Arbitrary write primitive",
        "needed": ["write_where"],
        "notes": "mov [reg1], reg2; ret - with control of both registers",
    },
}
