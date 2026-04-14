"""Linux kernel vulnerability patterns for source code analysis."""

# Patterns for scanning kernel C source files
# Each pattern has: regex, severity, category, description, and optional context

KERNEL_VULN_PATTERNS = {
    # === MEMORY SAFETY ===
    "copy_from_user_no_check": {
        "pattern": r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)",
        "severity": "high",
        "category": "overflow",
        "description": "copy_from_user — verify size is validated before this call",
        "check_context": "look for size validation before this line",
    },
    "copy_to_user_info_leak": {
        "pattern": r"copy_to_user\s*\([^,]+,\s*&(\w+)\s*,\s*sizeof",
        "severity": "medium",
        "category": "info_leak",
        "description": "copy_to_user of stack struct — check all fields are initialized",
    },
    "put_user_unchecked": {
        "pattern": r"__put_user\s*\(",
        "severity": "medium",
        "category": "overflow",
        "description": "__put_user (no access_ok check) — verify caller checks",
    },
    "get_user_unchecked": {
        "pattern": r"__get_user\s*\(",
        "severity": "medium",
        "category": "overflow",
        "description": "__get_user (no access_ok check) — verify caller checks",
    },
    "direct_user_deref": {
        "pattern": r"\*\s*\(\s*__user\s",
        "severity": "critical",
        "category": "overflow",
        "description": "Direct dereference of __user pointer without copy_from_user",
    },

    # === INTEGER OVERFLOW ===
    "kmalloc_multiplication": {
        "pattern": r"k[mzv]?alloc\s*\([^)]*\*[^)]*,",
        "severity": "high",
        "category": "integer",
        "description": "Multiplication in kmalloc size — check for overflow",
    },
    "kmalloc_user_size": {
        "pattern": r"k[mzv]?alloc\s*\(\s*(\w+)\s*,",
        "severity": "medium",
        "category": "integer",
        "description": "kmalloc with variable size — trace if user-controlled",
    },
    "array_size_missing": {
        "pattern": r"kmalloc\s*\(\s*\w+\s*\*\s*sizeof",
        "severity": "high",
        "category": "integer",
        "description": "Should use kmalloc_array() or array_size() for overflow protection",
    },
    "unchecked_arithmetic": {
        "pattern": r"(size|len|count|num|nr)\s*\+[=]\s*",
        "severity": "medium",
        "category": "integer",
        "description": "Arithmetic on size/length variable — check for overflow",
    },
    "signed_size": {
        "pattern": r"(int|long)\s+(size|len|length|count|offset)\b",
        "severity": "medium",
        "category": "integer",
        "description": "Signed type for size/length — potential signedness bug",
    },

    # === USE-AFTER-FREE ===
    "kfree_then_use": {
        "pattern": r"kfree\s*\(\s*(\w+)\s*\)(?:(?!\1\s*=\s*NULL)[\s\S]){1,300}\b\1\s*->",
        "severity": "critical",
        "category": "uaf",
        "description": "Object accessed after kfree without NULL assignment",
        "multiline": True,
    },
    "kfree_no_null": {
        "pattern": r"kfree\s*\(\s*(\w+)\s*\)\s*;(?!\s*\1\s*=\s*NULL)",
        "severity": "medium",
        "category": "uaf",
        "description": "kfree without setting pointer to NULL — potential dangling pointer",
    },
    "refcount_missing_put": {
        "pattern": r"(get|grab|acquire)\w*\s*\([^)]*\)(?:(?!put|release|drop)[\s\S]){1,500}return\s",
        "severity": "high",
        "category": "uaf",
        "description": "Reference acquired but potentially not released on error path",
        "multiline": True,
    },

    # === RACE CONDITIONS ===
    "toctou_file": {
        "pattern": r"(access|stat|lstat)\s*\([^)]+\)[\s\S]{1,200}(open|unlink|rename|chmod)\s*\(",
        "severity": "high",
        "category": "race",
        "description": "TOCTOU: check then use on filesystem path",
        "multiline": True,
    },
    "missing_lock_hint": {
        "pattern": r"/\*.*(?:must|should|needs?).*(?:hold|lock|mutex).*\*/",
        "severity": "medium",
        "category": "race",
        "description": "Comment suggests locking requirement — verify lock is held",
        "flags": "IGNORECASE",
    },
    "unlocked_list_op": {
        "pattern": r"list_(add|del|move|splice)\s*\(",
        "severity": "low",
        "category": "race",
        "description": "List operation — verify appropriate lock is held",
    },

    # === MISSING CHECKS ===
    "missing_null_after_alloc": {
        "pattern": r"(\w+)\s*=\s*k[mzv]?alloc\s*\([^)]+\)\s*;(?!\s*if\s*\(\s*!\s*\1)",
        "severity": "medium",
        "category": "null_deref",
        "description": "Allocation result not checked for NULL",
    },
    "missing_capable": {
        "pattern": r"(SYSCALL_DEFINE|ioctl)\w*.*\{(?:(?!capable|ns_capable|CAP_)[\s\S]){1,2000}\}",
        "severity": "medium",
        "category": "privilege",
        "description": "Syscall/ioctl handler without capability check",
        "multiline": True,
    },
    "missing_copy_check": {
        "pattern": r"copy_from_user\s*\([^)]+\)\s*;(?!\s*if\b)",
        "severity": "high",
        "category": "overflow",
        "description": "copy_from_user return value not checked",
    },

    # === INFO LEAKS ===
    "uninitialized_struct": {
        "pattern": r"struct\s+\w+\s+(\w+)\s*;(?!\s*memset)(?:(?!= \{)[\s\S]){1,200}copy_to_user\s*\([^,]+,\s*&\1",
        "severity": "high",
        "category": "info_leak",
        "description": "Stack struct not zeroed before copy_to_user — kernel memory leak",
        "multiline": True,
    },
    "padding_leak": {
        "pattern": r"struct\s+\w+\s*\{[^}]*__u\d+\s+\w+\s*;[^}]*\}.*__packed",
        "severity": "low",
        "category": "info_leak",
        "description": "Packed struct with mixed types — check for padding in non-packed version",
        "multiline": True,
    },

    # === BPF / NETFILTER ===
    "bpf_verifier_bypass": {
        "pattern": r"(ALU|JMP)\w*\s*\|\s*BPF_(K|X)",
        "severity": "high",
        "category": "logic",
        "description": "BPF instruction — check verifier handles this opcode correctly",
    },
    "nf_hook_missing_check": {
        "pattern": r"nf_register_net_hook\s*\(",
        "severity": "low",
        "category": "logic",
        "description": "Netfilter hook registration — check cleanup on module unload",
    },

    # === IOCTL PATTERNS ===
    "ioctl_switch_default": {
        "pattern": r"switch\s*\(\s*cmd\s*\)\s*\{(?:(?!default:)[\s\S])*\}",
        "severity": "low",
        "category": "logic",
        "description": "ioctl switch without default case",
        "multiline": True,
    },
    "ioctl_copy_size_mismatch": {
        "pattern": r"_IOC_SIZE\s*\(\s*cmd\s*\)(?:(?!copy_from_user)[\s\S]){1,500}copy_from_user\s*\([^,]+,\s*[^,]+,\s*sizeof",
        "severity": "high",
        "category": "overflow",
        "description": "ioctl uses sizeof for copy instead of _IOC_SIZE(cmd)",
        "multiline": True,
    },

    # === STACK ISSUES ===
    "vla_usage": {
        "pattern": r"\w+\s+\w+\s*\[\s*\w+\s*\]\s*;",
        "severity": "medium",
        "category": "overflow",
        "description": "Possible variable-length array on stack — check if size is bounded",
        "check_context": "verify the array size variable is compile-time constant or bounded",
    },
    "stack_sprintf": {
        "pattern": r"char\s+\w+\s*\[\s*\d+\s*\]\s*;[\s\S]{1,200}sprintf\s*\(\s*\w+\s*,",
        "severity": "high",
        "category": "overflow",
        "description": "sprintf into fixed-size stack buffer — use snprintf",
        "multiline": True,
    },

    # === DRIVER PATTERNS ===
    "platform_get_resource_no_check": {
        "pattern": r"platform_get_resource\s*\([^)]+\)\s*;(?!\s*if)",
        "severity": "medium",
        "category": "null_deref",
        "description": "platform_get_resource return not checked for NULL",
    },
    "devm_without_error": {
        "pattern": r"devm_k[mz]alloc\s*\([^)]+\)\s*;(?!\s*if)",
        "severity": "medium",
        "category": "null_deref",
        "description": "devm allocation not checked for NULL",
    },
}

# Patterns specifically for finding variant bugs from security patches
KERNEL_PATCH_PATTERNS = {
    "bounds_check_added": {
        "pattern": r"^\+\s*if\s*\(.*(?:>=|<=|>|<).*(?:size|len|count|max|limit)",
        "description": "Bounds check added — look for similar unchecked paths",
    },
    "lock_added": {
        "pattern": r"^\+\s*(mutex_lock|spin_lock|rcu_read_lock|down_read)",
        "description": "Lock added — check if all other access paths also lock",
    },
    "null_check_added": {
        "pattern": r"^\+\s*if\s*\(\s*!\s*\w+\s*\)",
        "description": "NULL check added — verify all callers also check",
    },
    "kfree_null_added": {
        "pattern": r"^\+\s*\w+\s*=\s*NULL\s*;",
        "description": "NULL assignment after free added — check other free sites",
    },
    "overflow_check_added": {
        "pattern": r"^\+.*(?:check_mul|array_size|size_add|overflow|INT_MAX)",
        "description": "Overflow check added — look for similar unchecked arithmetic",
    },
    "access_check_added": {
        "pattern": r"^\+.*(?:capable|ns_capable|CAP_|access_ok|may_)",
        "description": "Access check added — verify other entry points also check",
    },
}

# High-value kernel subsystems ranked by CVE frequency and bounty potential
KERNEL_SUBSYSTEMS = {
    "io_uring": {
        "path": "io_uring/",
        "risk": "critical",
        "description": "Async I/O — most CVE-dense subsystem 2021-2024",
        "entry_points": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
    },
    "bpf": {
        "path": "kernel/bpf/",
        "risk": "critical",
        "description": "BPF verifier — type confusion and bounds bypass",
        "entry_points": ["bpf_prog_load", "bpf_map_create"],
    },
    "netfilter": {
        "path": "net/netfilter/",
        "risk": "high",
        "description": "Packet filtering — UAF and race conditions",
        "entry_points": ["nf_tables_newrule", "nf_tables_newset"],
    },
    "usb": {
        "path": "drivers/usb/",
        "risk": "high",
        "description": "USB drivers — physically accessible, complex parsers",
        "entry_points": ["usb_submit_urb", "usb_control_msg"],
    },
    "bluetooth": {
        "path": "net/bluetooth/",
        "risk": "high",
        "description": "Bluetooth stack — remote attack surface",
        "entry_points": ["l2cap_connect", "hci_send_frame"],
    },
    "filesystems": {
        "path": "fs/",
        "risk": "high",
        "description": "Filesystem handling — mount/image parsing",
        "entry_points": ["vfs_read", "vfs_write", "do_mount"],
    },
    "nfs": {
        "path": "fs/nfs/",
        "risk": "medium",
        "description": "NFS client — remote attack surface via network",
    },
    "gpu_drm": {
        "path": "drivers/gpu/drm/",
        "risk": "medium",
        "description": "GPU drivers — complex ioctl interfaces",
    },
    "net_core": {
        "path": "net/core/",
        "risk": "medium",
        "description": "Core networking — socket operations",
    },
    "kvm": {
        "path": "arch/x86/kvm/",
        "risk": "critical",
        "description": "KVM hypervisor — guest-to-host escape",
        "entry_points": ["kvm_arch_vcpu_ioctl"],
    },
}
