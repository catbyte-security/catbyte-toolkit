"""Database of dangerous functions and vulnerability indicators."""

# Functions categorized by danger level and vulnerability type
DANGEROUS_IMPORTS = {
    "high": {
        "overflow": [
            "strcpy", "strcat", "gets", "sprintf", "vsprintf",
            "scanf", "fscanf", "sscanf", "wcscpy", "wcscat",
        ],
        "format": [
            "printf", "fprintf", "syslog", "NSLog", "CFStringCreateWithFormat",
            "vprintf", "vfprintf", "vsyslog",
        ],
        "exec": [
            "system", "popen", "exec", "execve", "execvp",
            "execl", "execlp", "execle", "dlopen",
        ],
        "ipc": [
            "MakeSelfOwnedReceiver", "mojo_core", "mojo_public",
            "xpc_connection_create_mach_service",
        ],
    },
    "medium": {
        "overflow": [
            "strncpy", "strncat", "snprintf", "vsnprintf",
            "memcpy", "memmove", "bcopy", "read", "recv",
            "recvfrom", "recvmsg", "fread", "fgets",
        ],
        "integer": [
            "atoi", "atol", "atoll", "strtol", "strtoul",
            "strtoll", "strtoull",
        ],
        "memory": [
            "realloc", "reallocf", "alloca",
        ],
    },
    "low": {
        "race": [
            "access", "stat", "lstat", "tmpnam", "mktemp",
            "tempnam", "tmpfile",
        ],
        "memory": [
            "free",  # double-free potential
        ],
        "info_leak": [
            "getenv",
        ],
    },
}

# Import categories for attack surface analysis
IMPORT_CATEGORIES = {
    "memory": {
        "malloc", "free", "calloc", "realloc", "reallocf",
        "mmap", "munmap", "mprotect", "brk", "sbrk",
        "alloca", "memalign", "posix_memalign", "valloc",
        "vm_allocate", "vm_deallocate",
    },
    "string": {
        "strcpy", "strncpy", "strcat", "strncat", "strlen",
        "strcmp", "strncmp", "strstr", "strtok", "strtok_r",
        "memcpy", "memmove", "memset", "memcmp", "memchr",
        "sprintf", "snprintf", "vsprintf", "vsnprintf",
        "strlcpy", "strlcat",  # BSD safe variants
    },
    "file_io": {
        "open", "close", "read", "write", "lseek",
        "fopen", "fclose", "fread", "fwrite", "fseek",
        "stat", "fstat", "lstat", "access", "unlink",
        "rename", "mkdir", "rmdir", "opendir", "readdir",
        "mmap", "truncate", "ftruncate",
    },
    "network": {
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom", "sendmsg",
        "recvmsg", "getaddrinfo", "gethostbyname",
        "gethostbyaddr", "select", "poll", "epoll_ctl",
        "kqueue", "kevent",
    },
    "process": {
        "fork", "vfork", "exec", "execve", "execvp",
        "system", "popen", "kill", "signal", "sigaction",
        "wait", "waitpid", "exit", "abort", "_exit",
        "pthread_create", "posix_spawn",
    },
    "ipc": {
        "mach_msg", "mach_port_allocate", "mach_port_deallocate",
        "bootstrap_look_up", "bootstrap_register",
        "xpc_connection_create", "xpc_connection_send_message",
        "pipe", "mkfifo", "shm_open", "sem_open",
        "msgget", "msgsnd", "msgrcv",
    },
    "crypto": {
        "CCCrypt", "CCCryptorCreate", "CCHmac",
        "SecKeyCreateSignature", "SecKeyEncrypt",
        "SSL_read", "SSL_write", "SSL_connect",
        "EVP_EncryptInit", "EVP_DecryptInit",
        "CommonCrypto", "SecureTransport",
    },
    "objc_runtime": {
        "objc_msgSend", "objc_getClass", "class_getMethodImplementation",
        "method_exchangeImplementations", "objc_allocateClassPair",
        "NSClassFromString", "NSSelectorFromString",
    },
    "chromium_ipc": {
        "MakeSelfOwnedReceiver", "BindOnce", "BindRepeating",
        "Unretained", "ReportBadMessage", "GetBadMessageCallback",
        "mojo_Remote", "mojo_Receiver", "mojo_PendingReceiver",
        "mojo_SelfOwnedReceiver", "BigBuffer",
        "RenderFrameHost", "FrameServiceBase", "DocumentService",
    },
    "v8_engine": {
        "v8_Isolate", "v8_Context", "v8_HandleScope",
        "CompileLazy", "TurboFan", "Maglev", "Turboshaft",
        "JSFunction", "HeapObject", "TaggedField",
        "CodeStubAssembler", "TNode",
    },
}

# Entitlements risk assessment (macOS)
DANGEROUS_ENTITLEMENTS = {
    "com.apple.security.cs.disable-library-validation": {
        "risk": "high",
        "description": "Allows loading unsigned dylibs - code injection vector",
    },
    "com.apple.security.cs.allow-dyld-environment-variables": {
        "risk": "high",
        "description": "DYLD_INSERT_LIBRARIES injection possible",
    },
    "com.apple.security.cs.debugger": {
        "risk": "high",
        "description": "Can attach debugger to other processes",
    },
    "com.apple.security.get-task-allow": {
        "risk": "medium",
        "description": "Process can be debugged (task_for_pid)",
    },
    "com.apple.private.security.no-sandbox": {
        "risk": "critical",
        "description": "Process runs without sandbox",
    },
    "com.apple.security.cs.allow-unsigned-executable-memory": {
        "risk": "high",
        "description": "Can create writable+executable memory (JIT)",
    },
    "com.apple.security.device.camera": {
        "risk": "medium",
        "description": "Camera access",
    },
    "com.apple.security.device.microphone": {
        "risk": "medium",
        "description": "Microphone access",
    },
    "com.apple.security.personal-information.location": {
        "risk": "medium",
        "description": "Location access",
    },
    "com.apple.security.files.all": {
        "risk": "high",
        "description": "Full filesystem access",
    },
    "com.apple.private.tcc.allow": {
        "risk": "high",
        "description": "Bypass TCC privacy protections",
    },
    "com.apple.rootless.install": {
        "risk": "critical",
        "description": "Can modify SIP-protected paths",
    },
    "platform-application": {
        "risk": "critical",
        "description": "Platform binary - runs with elevated trust",
    },
    "com.apple.security.cs.allow-jit": {
        "risk": "medium",
        "description": "JIT compilation allowed — needed for V8/JSC but weakens W^X",
    },
    "com.apple.security.network.client": {
        "risk": "low",
        "description": "Outbound network access — standard for browser/network processes",
    },
    "com.apple.security.network.server": {
        "risk": "medium",
        "description": "Inbound network access — check if actually needed",
    },
}

# Parser indicators - maps imports to likely file format handling
PARSER_INDICATORS = {
    "image": {
        "CGImageSource": ["JPEG", "PNG", "TIFF", "GIF", "HEIC", "BMP", "ICO"],
        "CGImageCreate": ["raw image data"],
        "vImage_Buffer": ["image processing"],
        "CIImage": ["CoreImage formats"],
        "NSBitmapImageRep": ["NSImage formats"],
        "png_read": ["PNG (libpng)"],
        "jpeg_read": ["JPEG (libjpeg)"],
        "WebPDecode": ["WebP"],
    },
    "document": {
        "xmlParse": ["XML"],
        "xmlRead": ["XML"],
        "htmlParse": ["HTML"],
        "CGPDFDocument": ["PDF"],
        "CGPDFPage": ["PDF"],
        "NSJSONSerialization": ["JSON"],
        "NSPropertyListSerialization": ["plist"],
        "yajl_": ["JSON (yajl)"],
        "json_": ["JSON"],
        "sqlite3_": ["SQLite"],
    },
    "media": {
        "CMSampleBuffer": ["video/audio samples"],
        "AVAssetReader": ["media containers"],
        "AudioFile": ["audio formats"],
        "CMFormatDescription": ["media format metadata"],
        "VTDecompressionSession": ["video decoding (H.264/HEVC)"],
    },
    "archive": {
        "BZ2_": ["bzip2"],
        "inflate": ["zlib/gzip"],
        "deflate": ["zlib/gzip"],
        "lzma_": ["LZMA/XZ"],
        "ZSTD_": ["Zstandard"],
        "LZ4_": ["LZ4"],
        "archive_read": ["libarchive (tar, zip, etc.)"],
        "unz": ["minizip/zlib unzip"],
        "ZipArchive": ["ZIP"],
    },
    "network_protocol": {
        "http_parser": ["HTTP"],
        "nghttp2_": ["HTTP/2"],
        "SSL_": ["TLS/SSL (OpenSSL)"],
        "SecureTransport": ["TLS (Apple)"],
        "nw_": ["Network.framework"],
        "DNS": ["DNS"],
        "curl_": ["libcurl (HTTP/FTP/etc)"],
    },
    "serialization": {
        "NSKeyedUnarchiver": ["NSCoding (deserialization)"],
        "NSUnarchiver": ["NSCoding (legacy)"],
        "protobuf": ["Protocol Buffers"],
        "flatbuffers": ["FlatBuffers"],
        "msgpack": ["MessagePack"],
    },
    "chromium": {
        "Stub_Accept": ["Mojo IPC dispatch"],
        "StructTraits_Read": ["Mojo struct validation"],
        "FromWire": ["Mojo deserialization"],
        "URLLoaderClient": ["Network request handling"],
        "NavigationRequest": ["Navigation processing"],
        "ScriptValue": ["V8 value handling"],
    },
}

# High-value services for targeting prioritization
HIGH_VALUE_SERVICES = {
    "com.apple.securityd", "com.apple.SecurityServer",
    "com.apple.coreservicesd", "com.apple.installd",
    "com.apple.packagekit.InstallAssistant",
    "com.apple.system.DirectoryService",
    "com.apple.opendirectoryd",
    "com.apple.sandboxd",
    "com.apple.kernel", "com.apple.kextd",
    "com.apple.authd", "com.apple.taskgated",
    "com.apple.CVMServer", "com.apple.cfprefsd",
    "com.apple.coreservices.launchservicesd",
    "com.apple.notifyd", "com.apple.powerd",
    "com.apple.diskarbitrationd",
    "com.apple.syspolicyd",
    "com.google.Chrome.helper", "com.google.Chrome.helper.GPU",
    "com.google.Chrome.helper.Renderer", "com.google.Chrome.helper.Plugin",
    "com.google.Chrome.framework", "org.chromium.Chromium.helper",
}

# Indicators of complex input handling
COMPLEX_INPUT_INDICATORS = {
    "xpc_dictionary_get_data", "xpc_dictionary_get_string",
    "xpc_dictionary_get_value", "xpc_array_get_value",
    "mach_msg", "mach_msg_receive",
    "CFDataGetBytePtr", "CFStringGetCString",
    "NSKeyedUnarchiver", "NSSecureCoding",
    "memcpy", "memmove", "bcopy",
    "CGImageSourceCreateWithData", "xmlParseMemory",
}
