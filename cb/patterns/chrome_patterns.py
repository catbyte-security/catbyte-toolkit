"""Chrome/Chromium-specific vulnerability detection patterns.

Patterns derived from CVE analysis of Chrome security bugs including:
- CVE-2025-2783: Mojo IPC handle lifecycle (sandbox escape via Windows IPC)
- CVE-2024-9369: V8 type confusion in JIT-compiled code
- CVE-2024-1284: Mojo use-after-free via self-owned receiver
- CVE-2024-0519: V8 OOB memory access in optimized code
- CVE-2023-4863: WebP heap buffer overflow (libwebp)
- CVE-2023-2033: V8 type confusion in compilation pipeline

These patterns target decompiled output, symbol tables, and binary
string/entitlement analysis of Chrome and Chromium-based browsers.
"""

# ---------------------------------------------------------------------------
# 1. Mojo IPC vulnerability patterns (applied to decompiled C/C++ output)
# ---------------------------------------------------------------------------

MOJO_IPC_VULN_PATTERNS = {
    "mojo_self_owned_raw_ptr": {
        "pattern": r"MakeSelfOwnedReceiver\s*\([^)]*\bnew\b",
        "severity": "high",
        "category": "uaf",
        "description": (
            "MakeSelfOwnedReceiver storing raw pointer to heap object. "
            "The raw pointer can dangle if the message pipe closes "
            "before the caller releases the pointer (CVE-2024-1284)."
        ),
    },
    "mojo_unretained_callback": {
        "pattern": (
            r"base::(BindOnce|BindRepeating)\s*\([^)]*"
            r"base::Unretained\s*\("
        ),
        "severity": "high",
        "category": "uaf",
        "description": (
            "base::Unretained used inside BindOnce/BindRepeating. "
            "The raw pointer outlives the bound invocation if the "
            "weak reference is destroyed before callback execution."
        ),
    },
    "bigbuffer_double_read": {
        "pattern": (
            r"(BigBuffer|shared_memory|SharedBufferHandle)"
            r"[\s\S]{1,300}"
            r"\1"
        ),
        "severity": "high",
        "category": "race",
        "description": (
            "Multiple reads from BigBuffer or shared memory region "
            "without copying to a local buffer first. Allows TOCTOU "
            "attacks from a compromised renderer process."
        ),
        "multiline": True,
    },
    "mojo_missing_report_bad_msg": {
        "pattern": (
            r"_Stub::Accept\s*\([^{]*\{"
            r"(?![\s\S]{0,2000}ReportBadMessage)"
            r"[\s\S]{10,2000}\}"
        ),
        "severity": "medium",
        "category": "validation",
        "description": (
            "Mojo Stub::Accept handler does not call ReportBadMessage "
            "on invalid input. Malformed IPC messages should be "
            "explicitly rejected to kill the misbehaving process."
        ),
        "multiline": True,
    },
    "mojo_check_on_ipc_input": {
        "pattern": r"\b(CHECK|DCHECK|CHECK_[A-Z]+)\s*\([^)]*\b(message|params|input|data)\b",
        "severity": "medium",
        "category": "validation",
        "description": (
            "CHECK/DCHECK on IPC-supplied value. A compromised renderer "
            "can trigger a browser-process crash via a crafted message. "
            "Use ReportBadMessage instead of CHECK for untrusted input."
        ),
    },
    "handle_dup_no_restrict": {
        "pattern": r"DuplicateHandle\s*\([^)]*DUPLICATE_SAME_ACCESS",
        "severity": "high",
        "category": "privilege",
        "description": (
            "DuplicateHandle with DUPLICATE_SAME_ACCESS duplicates all "
            "original access rights. Handle should be re-opened with "
            "minimum necessary rights to limit sandbox escape surface "
            "(CVE-2025-2783)."
        ),
    },
    "renderer_origin_trust": {
        "pattern": (
            r"(render_frame_host|rfh|renderer)[\w]*->"
            r"(GetLastCommittedOrigin|GetLastCommittedURL)"
            r"[\s\S]{0,200}"
            r"(if|switch|==|\.SchemeIs)"
        ),
        "severity": "high",
        "category": "trust_boundary",
        "description": (
            "Using renderer-supplied origin or URL for a security "
            "decision in the browser process. A compromised renderer "
            "can spoof its committed origin."
        ),
        "multiline": True,
    },
}

# ---------------------------------------------------------------------------
# 2. Chrome dangerous symbols (categorized by component)
# ---------------------------------------------------------------------------

CHROME_DANGEROUS_SYMBOLS = {
    "mojo_ipc": {
        "risk": "high",
        "symbols": [
            "MakeSelfOwnedReceiver",
            "base::Unretained",
            "base::BindOnce",
            "base::BindRepeating",
            "mojo::Remote",
            "mojo::Receiver",
            "mojo::PendingReceiver",
            "mojo::SelfOwnedReceiverRef",
            "mojo::SharedRemote",
            "mojo::AssociatedRemote",
            "ReportBadMessage",
            "BigBuffer",
            "BigBufferView",
        ],
        "description": "Mojo IPC patterns requiring careful lifetime management",
    },
    "v8_engine": {
        "risk": "medium",
        "symbols": [
            "v8::Isolate",
            "v8::Context",
            "v8::HandleScope",
            "v8::Local",
            "v8::MaybeLocal",
            "CompileLazy",
            "TurboFan",
            "Maglev",
            "BytecodeGenerator",
            "Builtins_",
            "Runtime_",
            "CodeStubAssembler",
            "TrustedPointerTable",
            "ExternalPointerTable",
        ],
        "description": "V8 JIT compilation -- type confusion hotspot",
    },
    "partition_alloc": {
        "risk": "medium",
        "symbols": [
            "PartitionAlloc",
            "PartitionFree",
            "PartitionRoot",
            "SlotSpan",
            "SuperPage",
            "PartitionBucket",
            "PartitionPage",
            "PartitionAllocFastPath",
            "PartitionAllocSlowPath",
            "MiraclePtr",
            "raw_ptr",
            "BackupRefPtr",
        ],
        "description": "Chrome memory allocator internals",
    },
    "browser_process": {
        "risk": "high",
        "symbols": [
            "RenderFrameHostImpl",
            "RenderProcessHostImpl",
            "BrowserProcessSubThread",
            "BrowserMainLoop",
            "NavigationRequest",
            "WebContentsImpl",
            "StoragePartitionImpl",
            "ServiceWorkerContextWrapper",
            "ChildProcessLauncher",
            "SandboxedProcessLauncherDelegate",
        ],
        "description": "Browser process components -- high privilege",
    },
    "blink_renderer": {
        "risk": "medium",
        "symbols": [
            "blink::Document",
            "blink::LocalFrame",
            "blink::ScriptState",
            "blink::HTMLParser",
            "blink::CSSParser",
            "blink::XMLParser",
            "blink::ImageDecoder",
            "blink::V8ScriptRunner",
            "blink::SerializedScriptValue",
            "blink::DOMArrayBuffer",
        ],
        "description": "Blink renderer engine -- parser and DOM attack surface",
    },
    "gpu_process": {
        "risk": "medium",
        "symbols": [
            "gpu::CommandBufferStub",
            "gpu::SharedImageStub",
            "gpu::SharedImageFactory",
            "viz::DisplayCompositorMemoryAndTaskController",
            "IOSurfaceRef",
            "GrDirectContext",
            "SkCanvas",
            "GLES2Implementation",
        ],
        "description": "GPU process -- shared memory and command buffer surface",
    },
}

# ---------------------------------------------------------------------------
# 3. V8 exploit patterns (sandbox escape indicators)
# ---------------------------------------------------------------------------

V8_EXPLOIT_PATTERNS = {
    "type_confusion_gadget": {
        "pattern": (
            r"(CheckMaps|DeoptimizeIf|CompareMap)"
            r"[\s\S]{0,500}"
            r"(LoadField|StoreField|LoadElement)"
        ),
        "severity": "high",
        "category": "type_confusion",
        "description": (
            "JIT miscompilation artifact: map check followed by "
            "unchecked field access. Type confusion can occur when "
            "speculative optimization elides the map guard."
        ),
        "multiline": True,
    },
    "trusted_pointer_table_access": {
        "pattern": r"\b(TrustedPointerTable|trusted_pointer_table)\b.*\b(Get|Set|At)\b",
        "severity": "high",
        "category": "sandbox_escape",
        "description": (
            "Access to V8 TrustedPointerTable, which maps trusted "
            "indices to raw code pointers. Corrupting table entries "
            "enables V8 sandbox escape."
        ),
    },
    "external_pointer_table_access": {
        "pattern": r"\b(ExternalPointerTable|external_pointer_table)\b.*\b(Get|Set|Allocate)\b",
        "severity": "high",
        "category": "sandbox_escape",
        "description": (
            "Access to V8 ExternalPointerTable. These entries map "
            "sandboxed indices to host pointers; corruption yields "
            "arbitrary read/write outside the V8 sandbox."
        ),
    },
    "arraybuffer_backing_store": {
        "pattern": (
            r"(ArrayBuffer|SharedArrayBuffer)"
            r"[\s\S]{0,200}"
            r"(backing_store|GetBackingStore|data\(\))"
        ),
        "severity": "high",
        "category": "oob_access",
        "description": (
            "Raw access to ArrayBuffer backing store pointer. "
            "If length or base can be corrupted, this gives "
            "out-of-bounds read/write (CVE-2024-0519)."
        ),
        "multiline": True,
    },
    "code_pointer_manipulation": {
        "pattern": (
            r"(Code::entry_point|InstructionStart|"
            r"code_entry_point|jump_table_start)"
        ),
        "severity": "high",
        "category": "sandbox_escape",
        "description": (
            "Direct manipulation of V8 Code object entry point "
            "or jump table. Overwriting these values redirects "
            "JIT execution to attacker-controlled code."
        ),
    },
    "wasm_memory_access": {
        "pattern": r"\b(WasmMemoryObject|wasm::Memory)\b.*\b(base|buffer|byte_length)\b",
        "severity": "medium",
        "category": "oob_access",
        "description": (
            "Wasm linear memory access. Corrupted base or length "
            "values enable out-of-bounds access from Wasm code."
        ),
    },
}

# ---------------------------------------------------------------------------
# 4. Chrome-specific macOS entitlement risks
# ---------------------------------------------------------------------------

CHROME_ENTITLEMENTS = {
    "com.apple.security.cs.allow-jit": {
        "risk": "medium",
        "description": (
            "V8 JIT requires MAP_JIT for writable-then-executable pages. "
            "Grants W^X exception -- expected for Chrome but increases "
            "code injection surface if sandbox is bypassed."
        ),
    },
    "com.apple.security.cs.allow-unsigned-executable-memory": {
        "risk": "high",
        "description": (
            "Allows creation of unsigned executable memory regions. "
            "Significantly weakens code-signing enforcement and "
            "enables shellcode injection post-exploit."
        ),
    },
    "com.apple.security.network.client": {
        "risk": "low",
        "description": (
            "Outbound network access. Standard for a browser but "
            "relevant in sandboxed helper processes that should "
            "not need direct network access."
        ),
    },
    "com.apple.security.cs.disable-library-validation": {
        "risk": "high",
        "description": (
            "Allows loading of unsigned or third-party signed "
            "dylibs. If present in Chrome, enables dylib injection "
            "attacks (DYLD_INSERT_LIBRARIES, etc.)."
        ),
    },
    "com.apple.security.network.server": {
        "risk": "medium",
        "description": (
            "Inbound network listen capability. Unexpected in "
            "browser helpers -- may indicate debug endpoint or "
            "DevTools remote protocol listener."
        ),
    },
    "com.apple.security.files.user-selected.read-write": {
        "risk": "low",
        "description": (
            "Read/write access to user-selected files via "
            "open/save panels. Standard for download manager."
        ),
    },
    "com.apple.security.device.audio-input": {
        "risk": "medium",
        "description": (
            "Microphone access for WebRTC. Verify this is only "
            "present on the browser/renderer, not utility processes."
        ),
    },
    "com.apple.security.device.camera": {
        "risk": "medium",
        "description": (
            "Camera access for WebRTC. Should be restricted to "
            "the renderer process, not GPU or utility helpers."
        ),
    },
}

# ---------------------------------------------------------------------------
# 5. Chrome fuzz target identification patterns
# ---------------------------------------------------------------------------

CHROME_FUZZ_TARGETS = {
    "mojo_interface_stubs": {
        "pattern": r"\w+_Stub::Accept\s*\(",
        "description": (
            "Mojo interface stub entry point. Every Accept method "
            "deserializes untrusted IPC messages -- prime fuzz target."
        ),
        "priority": "high",
        "component": "ipc",
    },
    "struct_traits_read": {
        "pattern": r"StructTraits<[^>]+>::Read\s*\(",
        "description": (
            "Mojo StructTraits::Read deserializes wire format into "
            "C++ structs. Incorrect validation causes type confusion "
            "or OOB access."
        ),
        "priority": "high",
        "component": "ipc",
    },
    "union_traits_read": {
        "pattern": r"UnionTraits<[^>]+>::Read\s*\(",
        "description": (
            "Mojo UnionTraits::Read for discriminated union types. "
            "Mishandled tag values cause type confusion."
        ),
        "priority": "high",
        "component": "ipc",
    },
    "v8_builtin_functions": {
        "pattern": r"Builtins_([\w]+)\s*\(",
        "description": (
            "V8 builtin function entry point. Builtins handle "
            "JavaScript operations and are reachable from script."
        ),
        "priority": "medium",
        "component": "v8",
    },
    "v8_runtime_functions": {
        "pattern": r"Runtime_([\w]+)\s*\(",
        "description": (
            "V8 runtime function called from generated code. "
            "Runtime functions bridge JIT code and the C++ runtime."
        ),
        "priority": "medium",
        "component": "v8",
    },
    "blink_html_parser": {
        "pattern": r"(HTMLTreeBuilder|HTMLDocumentParser|HTMLTokenizer)::\w+\s*\(",
        "description": (
            "Blink HTML parser entry points. Complex state machine "
            "with a long history of bugs."
        ),
        "priority": "high",
        "component": "blink",
    },
    "blink_css_parser": {
        "pattern": r"(CSSParser|CSSTokenizer|CSSPropertyParser)::\w+\s*\(",
        "description": (
            "Blink CSS parsing routines. Large attack surface "
            "reachable from web content via stylesheets."
        ),
        "priority": "medium",
        "component": "blink",
    },
    "blink_xml_parser": {
        "pattern": r"(XMLDocumentParser|XMLParser)::\w+\s*\(",
        "description": (
            "Blink XML/SVG parser. Handles untrusted XML documents "
            "and SVG images from the network."
        ),
        "priority": "medium",
        "component": "blink",
    },
    "image_decoder": {
        "pattern": (
            r"(ImageDecoder|PNGImageDecoder|JPEGImageDecoder|"
            r"WebPImageDecoder|GIFImageDecoder|"
            r"AVIFImageDecoder|BMPImageDecoder)::\w+\s*\("
        ),
        "description": (
            "Blink image decoder. Image parsers run in-process "
            "and have produced critical bugs (CVE-2023-4863 WebP)."
        ),
        "priority": "high",
        "component": "blink",
    },
    "media_decoder": {
        "pattern": (
            r"(FFmpegDemuxer|FFmpegVideoDecoder|"
            r"FFmpegAudioDecoder|MediaCodecBridge|"
            r"VpxVideoDecoder|Dav1dVideoDecoder)::\w+\s*\("
        ),
        "description": (
            "Media decoder entry points. Complex codec parsers "
            "handle untrusted audio/video from the network."
        ),
        "priority": "high",
        "component": "media",
    },
    "pdf_parser": {
        "pattern": r"(PDFiumEngine|CPDF_Parser|CPDF_Document)::\w+\s*\(",
        "description": (
            "PDFium parser components. PDF parsing involves "
            "deeply nested objects and complex font handling."
        ),
        "priority": "medium",
        "component": "pdfium",
    },
}

# ---------------------------------------------------------------------------
# 6. Sandbox escape indicators (string/symbol patterns)
# ---------------------------------------------------------------------------

SANDBOX_ESCAPE_INDICATORS = {
    "mach_msg_renderer": {
        "symbols": ["mach_msg", "mach_msg_send", "mach_msg_receive"],
        "context": "renderer",
        "risk": "high",
        "description": (
            "Mach message send/receive in renderer context. "
            "Renderer sandbox should not have direct Mach port "
            "access -- indicates sandbox policy gap or escape."
        ),
    },
    "iosurface_from_sandbox": {
        "symbols": [
            "IOSurfaceCreate",
            "IOSurfaceLookup",
            "IOSurfaceGetBaseAddress",
            "IOSurfaceWrapClientImage",
        ],
        "context": "sandboxed",
        "risk": "high",
        "description": (
            "IOSurface operations from sandboxed process. "
            "IOSurface kernel driver has been a repeated source "
            "of sandbox escape bugs."
        ),
    },
    "file_broker_access": {
        "symbols": [
            "FileSystemAccessManager",
            "NativeFileSystemManager",
            "FileSystemChooser",
            "OpenFile",
            "CreateOrOpen",
        ],
        "context": "renderer",
        "risk": "medium",
        "description": (
            "File broker IPC from renderer. The file broker mediates "
            "file access across the sandbox boundary; bugs in "
            "validation allow arbitrary file read/write."
        ),
    },
    "gpu_process_ipc": {
        "symbols": [
            "GpuChannelHost",
            "GpuChannel",
            "CommandBufferProxyImpl",
            "SharedImageInterface",
            "GpuMemoryBufferManager",
        ],
        "context": "renderer",
        "risk": "medium",
        "description": (
            "GPU process IPC from renderer. The GPU process is less "
            "sandboxed than the renderer -- bugs in GPU command "
            "buffer handling enable privilege escalation."
        ),
    },
    "network_process_ipc": {
        "symbols": [
            "NetworkContext",
            "URLLoaderFactory",
            "CookieManager",
            "WebSocketFactory",
            "NetworkServiceClient",
        ],
        "context": "renderer",
        "risk": "medium",
        "description": (
            "Network process IPC from renderer. The network process "
            "has network access the renderer lacks; IPC bugs can "
            "enable SSRF or credential theft."
        ),
    },
    "seatbelt_profile_ops": {
        "symbols": [
            "sandbox_init",
            "sandbox_check",
            "sandbox_extension_consume",
            "sandbox_extension_issue_file",
        ],
        "context": "any",
        "risk": "high",
        "description": (
            "macOS Seatbelt sandbox API calls. sandbox_extension_consume "
            "can widen sandbox permissions; verify extensions are "
            "properly scoped and revoked."
        ),
    },
    "task_port_access": {
        "symbols": [
            "task_for_pid",
            "mach_port_insert_right",
            "mach_port_extract_right",
            "thread_create_running",
        ],
        "context": "any",
        "risk": "high",
        "description": (
            "Mach task/thread port manipulation. Obtaining a task "
            "port for another process grants full memory read/write "
            "and code injection capability."
        ),
    },
}
