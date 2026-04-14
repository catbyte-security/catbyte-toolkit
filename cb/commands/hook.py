"""cb hook - Frida-based dynamic instrumentation and hooking."""
import argparse
import json
import os
import subprocess
import sys
import tempfile

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("hook", help="Generate/run Frida hooks for dynamic analysis")
    p.add_argument("binary", help="Path to binary, .app bundle, or process name")
    p.add_argument("--function", "-f", type=str, default=None,
                   help="Function to hook (C function or ObjC method)")
    p.add_argument("--objc-class", type=str, default=None,
                   help="Hook all methods of an ObjC class")
    p.add_argument("--trace-ipc", action="store_true",
                   help="Auto-hook XPC/Mach IPC handlers")
    p.add_argument("--trace-parsers", action="store_true",
                   help="Hook file format parsing functions")
    p.add_argument("--trace-alloc", action="store_true",
                   help="Hook malloc/free for heap analysis")
    p.add_argument("--generate", action="store_true", default=True,
                   help="Generate Frida script (default)")
    p.add_argument("--run", action="store_true",
                   help="Run the generated script with Frida")
    p.add_argument("--pid", type=int, default=None,
                   help="Attach to running process by PID")
    p.add_argument("--output-dir", type=str, default=".",
                   help="Directory to write generated scripts")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    binary = args.binary
    result = {}

    # Resolve app bundle
    process_name = None
    if binary.endswith(".app"):
        import plistlib
        info_plist = os.path.join(binary, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            process_name = plist.get("CFBundleExecutable", "")
            actual_binary = os.path.join(binary, "Contents", "MacOS", process_name)
        else:
            actual_binary = binary
    else:
        actual_binary = binary
        process_name = os.path.basename(binary)

    scripts = []

    if args.function:
        out.status(f"Generating hook for: {args.function}")
        scripts.append(generate_function_hook(args.function))

    if args.objc_class:
        out.status(f"Generating hooks for ObjC class: {args.objc_class}")
        scripts.append(generate_class_hook(args.objc_class))

    if args.trace_ipc:
        out.status("Generating IPC tracing hooks...")
        scripts.append(generate_ipc_hooks(actual_binary))

    if args.trace_parsers:
        out.status("Generating parser tracing hooks...")
        scripts.append(generate_parser_hooks(actual_binary))

    if args.trace_alloc:
        out.status("Generating heap analysis hooks...")
        scripts.append(generate_alloc_hooks())

    # If no specific hook requested, generate a comprehensive tracer
    if not any([args.function, args.objc_class, args.trace_ipc,
                args.trace_parsers, args.trace_alloc]):
        out.status("Generating comprehensive analysis hooks...")
        scripts.append(generate_ipc_hooks(actual_binary))
        scripts.append(generate_parser_hooks(actual_binary))

    # Combine all scripts
    combined = _FRIDA_HEADER + "\n\n".join(scripts) + "\n" + _FRIDA_FOOTER

    # Write script
    script_name = f"hook_{process_name or 'target'}.js"
    script_path = os.path.join(args.output_dir, script_name)
    with open(script_path, "w") as f:
        f.write(combined)

    result["script_path"] = script_path
    result["process_name"] = process_name
    result["run_command"] = f"frida -n {process_name} -l {script_path}" if process_name \
        else f"frida -f {binary} -l {script_path}"

    # Run if requested
    if args.run:
        out.status("Launching Frida...")
        result["run_output"] = run_frida(script_path, process_name, args.pid)

    out.emit(result, "hook")


def generate_function_hook(func_name):
    """Generate hook for a specific function."""
    # Detect ObjC method vs C function
    if func_name.startswith("-[") or func_name.startswith("+["):
        return _objc_method_hook(func_name)
    elif ":" in func_name and not func_name.startswith("0x"):
        # Might be "ClassName:selectorName"
        parts = func_name.split(":", 1)
        return _objc_method_hook(f"-[{parts[0]} {parts[1]}]")
    else:
        return _c_function_hook(func_name)


def _c_function_hook(func_name):
    return f"""
// Hook: {func_name}
(function() {{
    var addr = Module.findExportByName(null, "{func_name}");
    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                this.args = [];
                for (var i = 0; i < 6; i++) {{
                    this.args.push(args[i]);
                }}
                send({{
                    type: "call",
                    function: "{func_name}",
                    args: this.args.map(function(a) {{ return a.toString(); }}),
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).map(String),
                }});
            }},
            onLeave: function(retval) {{
                send({{
                    type: "return",
                    function: "{func_name}",
                    retval: retval.toString(),
                }});
            }}
        }});
        console.log("[+] Hooked: {func_name} at " + addr);
    }} else {{
        console.log("[-] Function not found: {func_name}");
    }}
}})();"""


def _objc_method_hook(method_sig):
    # Parse "-[ClassName selector:]"
    import re
    m = re.match(r"([-+])\[(\S+)\s+([^\]]+)\]", method_sig)
    if not m:
        return f"// Could not parse ObjC method: {method_sig}"
    sign = m.group(1)
    cls = m.group(2)
    sel = m.group(3)

    return f"""
// Hook: {method_sig}
(function() {{
    var cls = ObjC.classes["{cls}"];
    if (cls) {{
        var method = cls["{sign} {sel}"];
        if (method) {{
            Interceptor.attach(method.implementation, {{
                onEnter: function(args) {{
                    var self = new ObjC.Object(args[0]);
                    var sel = ObjC.selectorAsString(args[2]);
                    this.info = {{ class: "{cls}", selector: sel }};
                    // Log first few arguments
                    var argVals = [];
                    for (var i = 3; i < 7; i++) {{
                        try {{ argVals.push(new ObjC.Object(args[i]).toString()); }}
                        catch(e) {{ argVals.push(args[i] ? args[i].toString() : "nil"); }}
                    }}
                    send({{
                        type: "objc_call",
                        class: "{cls}",
                        selector: sel,
                        args: argVals,
                        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).map(String).slice(0, 5),
                    }});
                }},
                onLeave: function(retval) {{
                    try {{
                        var ret = new ObjC.Object(retval);
                        send({{ type: "objc_return", class: "{cls}",
                               selector: this.info.selector, retval: ret.toString() }});
                    }} catch(e) {{
                        send({{ type: "objc_return", class: "{cls}",
                               selector: this.info.selector, retval: retval.toString() }});
                    }}
                }}
            }});
            console.log("[+] Hooked: {method_sig}");
        }} else {{
            console.log("[-] Method not found: {method_sig}");
        }}
    }} else {{
        console.log("[-] Class not found: {cls}");
    }}
}})();"""


def generate_class_hook(class_name):
    """Hook all methods of an ObjC class."""
    return f"""
// Hook all methods of: {class_name}
(function() {{
    var cls = ObjC.classes["{class_name}"];
    if (!cls) {{
        console.log("[-] Class not found: {class_name}");
        return;
    }}
    var methods = cls.$ownMethods;
    console.log("[*] Hooking " + methods.length + " methods of {class_name}");
    methods.forEach(function(method) {{
        try {{
            var impl = cls[method].implementation;
            Interceptor.attach(impl, {{
                onEnter: function(args) {{
                    var sel = ObjC.selectorAsString(args[1]);
                    send({{
                        type: "objc_call",
                        class: "{class_name}",
                        selector: sel,
                    }});
                }}
            }});
        }} catch(e) {{
            // Some methods can't be hooked
        }}
    }});
    console.log("[+] Hooked " + methods.length + " methods of {class_name}");
}})();"""


def generate_ipc_hooks(binary_path):
    """Generate hooks for IPC/XPC functions."""
    hooks = []

    # XPC connection handlers
    hooks.append("""
// === XPC/IPC Tracing ===

// Hook xpc_connection_set_event_handler
var xpc_set_handler = Module.findExportByName(null, "xpc_connection_set_event_handler");
if (xpc_set_handler) {
    Interceptor.attach(xpc_set_handler, {
        onEnter: function(args) {
            var conn = args[0];
            send({
                type: "xpc",
                event: "set_event_handler",
                connection: conn.toString(),
            });
        }
    });
    console.log("[+] Hooked: xpc_connection_set_event_handler");
}

// Hook xpc_dictionary_get_string (data extraction from XPC messages)
var xpc_get_str = Module.findExportByName(null, "xpc_dictionary_get_string");
if (xpc_get_str) {
    Interceptor.attach(xpc_get_str, {
        onEnter: function(args) {
            this.key = args[1].readUtf8String();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                send({
                    type: "xpc",
                    event: "get_string",
                    key: this.key,
                    value: retval.readUtf8String(),
                });
            }
        }
    });
    console.log("[+] Hooked: xpc_dictionary_get_string");
}

// Hook xpc_dictionary_get_data
var xpc_get_data = Module.findExportByName(null, "xpc_dictionary_get_data");
if (xpc_get_data) {
    Interceptor.attach(xpc_get_data, {
        onEnter: function(args) {
            this.key = args[1].readUtf8String();
            this.lenPtr = args[2];
        },
        onLeave: function(retval) {
            if (!retval.isNull() && this.lenPtr && !this.lenPtr.isNull()) {
                var len = this.lenPtr.readUInt();
                send({
                    type: "xpc",
                    event: "get_data",
                    key: this.key,
                    size: len,
                    preview: retval.readByteArray(Math.min(len, 64)),
                });
            }
        }
    });
    console.log("[+] Hooked: xpc_dictionary_get_data");
}

// Hook mach_msg for raw Mach IPC
var mach_msg_fn = Module.findExportByName(null, "mach_msg");
if (mach_msg_fn) {
    Interceptor.attach(mach_msg_fn, {
        onEnter: function(args) {
            var header = args[0];
            if (!header.isNull()) {
                send({
                    type: "mach_msg",
                    msgh_bits: header.readU32(),
                    msgh_size: header.add(4).readU32(),
                    msgh_remote_port: header.add(8).readU32(),
                    msgh_local_port: header.add(12).readU32(),
                    msgh_id: header.add(20).readU32(),
                });
            }
        }
    });
    console.log("[+] Hooked: mach_msg");
}

// Hook NSXPCConnection delegate methods
if (ObjC.available) {
    try {
        var NSXPCListener = ObjC.classes.NSXPCListener;
        if (NSXPCListener) {
            var setDelegate = NSXPCListener["- setDelegate:"];
            if (setDelegate) {
                Interceptor.attach(setDelegate.implementation, {
                    onEnter: function(args) {
                        var delegate = new ObjC.Object(args[2]);
                        send({
                            type: "xpc",
                            event: "listener_set_delegate",
                            delegate_class: delegate.$className,
                        });
                    }
                });
                console.log("[+] Hooked: NSXPCListener setDelegate:");
            }
        }
    } catch(e) {}
}""")

    return "\n".join(hooks)


def generate_parser_hooks(binary_path):
    """Generate hooks for file parsing functions."""
    return """
// === File Parser Tracing ===

// Hook common parsing functions
var parse_funcs = [
    "CGImageSourceCreateWithData",
    "CGImageSourceCreateWithURL",
    "CGPDFDocumentCreateWithURL",
    "CGPDFDocumentCreateWithProvider",
    "xmlParseMemory",
    "xmlParseFile",
    "inflate",
    "BZ2_bzDecompress",
    "jpeg_read_header",
    "png_read_info",
];

parse_funcs.forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                send({
                    type: "parser_call",
                    function: name,
                    arg0: args[0].toString(),
                    backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).map(String).slice(0, 5),
                });
            },
            onLeave: function(retval) {
                send({
                    type: "parser_return",
                    function: name,
                    retval: retval.toString(),
                });
            }
        });
        console.log("[+] Hooked parser: " + name);
    }
});

// Hook memcpy/memmove with size tracking (for overflow detection)
["memcpy", "memmove"].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var size = args[2].toInt32();
                // Only log large copies (potential overflow)
                if (size > 4096 || size < 0) {
                    send({
                        type: "large_copy",
                        function: name,
                        dst: args[0].toString(),
                        src: args[1].toString(),
                        size: size,
                        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).map(String).slice(0, 5),
                    });
                }
            }
        });
        console.log("[+] Hooked: " + name + " (large copy detection)");
    }
});"""


def generate_alloc_hooks():
    """Generate hooks for heap analysis."""
    return """
// === Heap Analysis ===
var allocations = {};
var freeCount = 0;
var allocCount = 0;

var malloc_fn = Module.findExportByName(null, "malloc");
if (malloc_fn) {
    Interceptor.attach(malloc_fn, {
        onEnter: function(args) {
            this.size = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                allocCount++;
                allocations[retval.toString()] = {
                    size: this.size,
                    bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).map(String).slice(0, 3),
                };
                // Alert on suspicious sizes
                if (this.size > 10 * 1024 * 1024 || this.size < 0) {
                    send({
                        type: "suspicious_alloc",
                        size: this.size,
                        ptr: retval.toString(),
                        backtrace: allocations[retval.toString()].bt,
                    });
                }
            }
        }
    });
    console.log("[+] Hooked: malloc");
}

var free_fn = Module.findExportByName(null, "free");
if (free_fn) {
    Interceptor.attach(free_fn, {
        onEnter: function(args) {
            var ptr = args[0].toString();
            if (ptr !== "0x0") {
                freeCount++;
                if (!(ptr in allocations)) {
                    // Freeing untracked pointer - possible double free
                    send({
                        type: "suspicious_free",
                        event: "free_untracked",
                        ptr: ptr,
                        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).map(String).slice(0, 5),
                    });
                } else {
                    delete allocations[ptr];
                }
            }
        }
    });
    console.log("[+] Hooked: free");
}

// Periodic stats
setInterval(function() {
    var live = Object.keys(allocations).length;
    if (allocCount > 0) {
        send({
            type: "heap_stats",
            total_allocs: allocCount,
            total_frees: freeCount,
            live_allocations: live,
        });
    }
}, 5000);"""


def run_frida(script_path, process_name=None, pid=None):
    """Run Frida with the generated script."""
    if pid:
        cmd = ["frida", "-p", str(pid), "-l", script_path]
    elif process_name:
        cmd = ["frida", "-n", process_name, "-l", script_path]
    else:
        return {"error": "Need --pid or process name to attach"}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"stdout": result.stdout[:2000], "stderr": result.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"note": "Frida session started (30s preview timeout reached)"}
    except FileNotFoundError:
        return {"error": "Frida not found. Install with: pip install frida-tools"}


_FRIDA_HEADER = """// Auto-generated by cb hook - CatByte Security Toolkit
// Usage: frida -n <process> -l <this_script.js>
//    or: frida -f <binary> -l <this_script.js>
'use strict';

console.log("[*] CatByte hook script loaded");
console.log("[*] Attaching hooks...");
"""

_FRIDA_FOOTER = """
console.log("[*] All hooks attached. Monitoring...");
"""


def main():
    parser = argparse.ArgumentParser(prog="cbhook", description="Frida hook generator")
    parser.add_argument("binary")
    parser.add_argument("--function", "-f", type=str, default=None)
    parser.add_argument("--objc-class", type=str, default=None)
    parser.add_argument("--trace-ipc", action="store_true")
    parser.add_argument("--trace-parsers", action="store_true")
    parser.add_argument("--trace-alloc", action="store_true")
    parser.add_argument("--generate", action="store_true", default=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--pid", type=int, default=None)
    parser.add_argument("--output-dir", type=str, default=".")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
