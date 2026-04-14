"""ELF binary analysis using pwntools and pyelftools."""
import os
import re


def get_elf_info(path):
    """Full ELF analysis using pwntools."""
    # Import here to avoid slow pwntools import when not needed
    from pwn import ELF, context
    context.log_level = "error"

    e = ELF(path, checksec=False)

    info = {
        "file_info": {
            "path": path,
            "size_bytes": os.path.getsize(path),
            "format": "elf",
            "arch": e.arch,
            "bits": e.bits,
            "endian": e.endian,
            "type": e.elftype,
        },
        "protections": {
            "pie": bool(e.pie),
            "nx": bool(e.nx),
            "canary": bool(e.canary),
            "relro": e.relro if hasattr(e, "relro") else "unknown",
            "rpath": bool(e.rpath) if hasattr(e, "rpath") else False,
            "runpath": bool(e.runpath) if hasattr(e, "runpath") else False,
        },
        "sections": [],
        "imports": [],
        "exports": [],
        "libraries": list(e.libs.keys()) if hasattr(e, "libs") else [],
    }

    # Sections
    for name, section in e.sections.items() if hasattr(e.sections, "items") else []:
        info["sections"].append({
            "name": name,
            "address": hex(section.header.sh_addr),
            "size": section.header.sh_size,
        })

    # GOT/PLT entries as imports
    if hasattr(e, "got"):
        info["imports"] = list(e.got.keys())

    # Symbols as exports
    if hasattr(e, "symbols"):
        info["exports"] = [s for s in e.symbols.keys()
                           if not s.startswith("__")][:100]

    return info


def find_elf_function_address(path, func_name):
    """Look up a function symbol's virtual address in an ELF binary.

    Parameters
    ----------
    path : str
        Path to the ELF binary.
    func_name : str
        Function name to search for (with or without leading underscore).

    Returns
    -------
    int or None
        Virtual address of the function, or None if not found.
    """
    try:
        from pwn import ELF, context
        context.log_level = "error"
        e = ELF(path, checksec=False)
        # Try exact match first, then with/without underscore prefix
        for name in (func_name, f"_{func_name}", func_name.lstrip("_")):
            if name in e.symbols:
                return e.symbols[name]
    except Exception:
        pass
    return None


def categorize_imports(imports):
    """Categorize import symbols by function type."""
    categories = {
        "memory": [],
        "string": [],
        "file_io": [],
        "network": [],
        "process": [],
        "dangerous": [],
        "crypto": [],
        "ipc": [],
    }

    dangerous = {
        "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf",
        "fscanf", "sscanf", "system", "popen", "exec", "execve",
        "execvp", "execl", "execlp",
    }
    memory = {
        "malloc", "free", "calloc", "realloc", "mmap", "munmap",
        "mprotect", "brk", "sbrk", "alloca", "memalign",
    }
    string = {
        "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp",
        "strncmp", "strstr", "strtok", "memcpy", "memmove", "memset",
        "memcmp", "sprintf", "snprintf",
    }
    file_io = {
        "open", "close", "read", "write", "fopen", "fclose", "fread",
        "fwrite", "lseek", "stat", "fstat", "access", "unlink",
        "rename", "mkdir", "rmdir",
    }
    network = {
        "socket", "connect", "bind", "listen", "accept", "send",
        "recv", "sendto", "recvfrom", "getaddrinfo", "gethostbyname",
        "select", "poll", "epoll",
    }
    process = {
        "fork", "exec", "execve", "system", "popen", "kill",
        "signal", "sigaction", "wait", "waitpid", "exit", "abort",
        "pthread_create",
    }

    for imp in imports:
        # Strip common prefixes
        name = imp.lstrip("_")
        if name in dangerous:
            categories["dangerous"].append(imp)
        if name in memory:
            categories["memory"].append(imp)
        if name in string:
            categories["string"].append(imp)
        if name in file_io:
            categories["file_io"].append(imp)
        if name in network:
            categories["network"].append(imp)
        if name in process:
            categories["process"].append(imp)

    return categories
