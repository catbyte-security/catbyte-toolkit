"""cb fuzz - Fuzzing harness generator and target identification."""
import argparse
import os
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import get_imports, get_strings


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

# Functions that indicate interesting fuzz targets
PARSER_INDICATORS = {
    "parse", "read", "decode", "deserialize", "load", "process",
    "handle", "import", "convert", "extract", "unpack", "inflate",
    "decompress", "unmarshal",
}

DANGEROUS_CALLEES = {
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "sscanf", "malloc", "realloc", "free",
}

# Chrome/Mojo specific fuzz target indicators
CHROME_TARGET_INDICATORS = {
    "stub_accept", "structtraits_read", "fromwire", "towire",
    "validate", "deserialize", "serialize",
}

CHROME_HIGH_VALUE_NAMES = {
    "mojo", "ipc", "renderer", "browser", "compositor",
    "urlloader", "navigation", "blink", "v8", "wasm",
}


def register(subparsers):
    p = subparsers.add_parser("fuzz", help="Generate fuzzing harnesses")
    p.add_argument("binary", help="Path to binary or library")
    p.add_argument("--target", type=str, default=None,
                   help="Specific function to fuzz")
    p.add_argument("--auto", action="store_true", default=True,
                   help="Auto-detect interesting fuzz targets")
    p.add_argument("--generate", action="store_true",
                   help="Generate harness code")
    p.add_argument("--framework", choices=["libfuzzer", "afl", "honggfuzz"],
                   default="libfuzzer")
    p.add_argument("--output-dir", type=str, default=".",
                   help="Where to write generated files")
    p.add_argument("--dict", action="store_true",
                   help="Generate fuzzer dictionary from strings")
    p.add_argument("--suggest-corpus", action="store_true",
                   help="Suggest seed corpus based on format analysis")
    p.add_argument("--xpc", action="store_true",
                   help="Generate XPC-aware fuzzer")
    p.add_argument("--service", type=str, default=None,
                   help="Target Mach service name for XPC fuzzer")
    p.add_argument("--protocol-json", type=str, default=None,
                   help="Path to XPC protocol spec JSON (from cb ipc --protocol)")
    p.add_argument("--xpc-style", choices=["c", "objc"], default="objc",
                   help="XPC fuzzer code style (default: objc)")
    p.add_argument("--mojo", action="store_true",
                   help="Generate Mojo IPC interface fuzzer (MojoLPM-style)")
    p.add_argument("--structure-aware", action="store_true",
                   help="Generate FuzzedDataProvider-based structured harness")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    result = {}

    # XPC-aware fuzzer generation
    if getattr(args, 'xpc', False):
        out.status("Generating XPC-aware fuzzer...")
        result = generate_xpc_fuzzer(args, out)
        out.emit(result, "fuzz")
        return

    # Mojo IPC fuzzer generation
    if getattr(args, 'mojo', False):
        out.status("Generating Mojo IPC fuzzer...")
        result = generate_mojo_fuzzer(args, out)
        out.emit(result, "fuzz")
        return

    if args.target:
        out.status(f"Generating harness for: {args.target}")
        result["target"] = args.target
        if args.generate:
            result["harness"] = generate_harness(args)
    else:
        out.status("Auto-detecting fuzz targets...")
        result["suggested_targets"] = find_targets(args, out)

    if args.dict:
        out.status("Generating fuzzer dictionary...")
        result["dictionary"] = generate_dictionary(args.binary)

    if args.suggest_corpus:
        out.status("Analyzing for corpus suggestions...")
        result["corpus_suggestions"] = suggest_corpus(args.binary)

    out.emit(result, "fuzz")


def find_targets(args, out):
    """Score and rank functions as potential fuzz targets."""
    imports = get_imports(args.binary)
    import_set = {i.lstrip("_").lower() for i in imports}

    # Get function list from nm
    r = subprocess.run(["nm", "-defined-only", "-n", args.binary],
                       capture_output=True, text=True, timeout=60)
    functions = []
    lines = r.stdout.splitlines()

    for i, line in enumerate(lines):
        parts = line.split()
        if len(parts) >= 3:
            addr = parts[0]
            stype = parts[1]
            name = parts[2].lstrip("_")

            # Estimate size
            if i + 1 < len(lines):
                next_parts = lines[i + 1].split()
                try:
                    size = int(next_parts[0], 16) - int(addr, 16)
                except (ValueError, IndexError):
                    size = 0
            else:
                size = 0

            if stype not in ("T", "t"):
                continue
            if size < 32:
                continue

            score = score_target(name, size, import_set)
            if score > 10:
                functions.append({
                    "function": name,
                    "address": f"0x{addr}",
                    "size": size,
                    "score": score,
                    "reasons": get_score_reasons(name, size, import_set),
                })

    # Sort by score
    functions.sort(key=lambda f: f["score"], reverse=True)
    return functions[:args.max_results]


def score_target(name, size, import_set):
    """Score a function as a fuzz target (0-100)."""
    score = 0
    name_lower = name.lower()

    # Name indicates parser/handler
    for indicator in PARSER_INDICATORS:
        if indicator in name_lower:
            score += 20
            break

    # Size indicates complexity
    if size > 500:
        score += 15
    elif size > 200:
        score += 10
    elif size > 100:
        score += 5

    # Has dangerous imports in scope (crude check - binary-wide)
    dangerous_present = import_set & {f.lower() for f in DANGEROUS_CALLEES}
    score += min(len(dangerous_present) * 3, 15)

    # Name suggests it takes data input
    if any(x in name_lower for x in ["data", "buffer", "input", "packet",
                                      "message", "request", "payload"]):
        score += 15

    # Name suggests it's a callback/handler
    if any(x in name_lower for x in ["handler", "callback", "delegate",
                                      "listener", "observer"]):
        score += 10

    # Chrome/Mojo specific scoring
    for indicator in CHROME_TARGET_INDICATORS:
        if indicator in name_lower:
            score += 25
            break

    for component in CHROME_HIGH_VALUE_NAMES:
        if component in name_lower:
            score += 15
            break

    # Mojo handler dispatch patterns
    if "stub" in name_lower and "accept" in name_lower:
        score += 30
    if "structtraits" in name_lower and "read" in name_lower:
        score += 25

    # Penalty for test/debug functions
    if any(x in name_lower for x in ["test", "debug", "log", "print",
                                      "assert", "mock"]):
        score -= 20

    return max(score, 0)


def get_score_reasons(name, size, import_set):
    """Human-readable reasons for the score."""
    reasons = []
    name_lower = name.lower()

    for indicator in PARSER_INDICATORS:
        if indicator in name_lower:
            reasons.append(f"Name contains '{indicator}' (parser indicator)")
            break

    if size > 500:
        reasons.append(f"Large function ({size} bytes)")
    elif size > 200:
        reasons.append(f"Medium function ({size} bytes)")

    if any(x in name_lower for x in ["data", "buffer", "input", "packet"]):
        reasons.append("Name suggests data input handling")

    dangerous = import_set & {f.lower() for f in DANGEROUS_CALLEES}
    if dangerous:
        reasons.append(f"Binary uses dangerous functions: {', '.join(sorted(dangerous)[:5])}")

    for indicator in CHROME_TARGET_INDICATORS:
        if indicator in name_lower:
            reasons.append(f"Chrome/Mojo target indicator: '{indicator}'")
            break

    for component in CHROME_HIGH_VALUE_NAMES:
        if component in name_lower:
            reasons.append(f"Chrome high-value component: '{component}'")
            break

    return reasons


def generate_harness(args):
    """Generate a fuzzing harness for the target function."""
    framework = args.framework
    target = args.target
    binary = args.binary

    if getattr(args, 'structure_aware', False):
        template = _fuzzed_data_provider_template(target, binary)
    elif framework == "libfuzzer":
        template = _libfuzzer_template(target, binary)
    elif framework == "afl":
        template = _afl_template(target, binary)
    else:
        template = _honggfuzz_template(target, binary)

    # Write to file if output dir specified
    if args.generate:
        out_path = os.path.join(args.output_dir,
                                f"fuzz_{target.replace('::', '_')}_{framework}.c")
        with open(out_path, "w") as f:
            f.write(template)
        return {"file": out_path, "framework": framework, "code": template}

    return {"framework": framework, "code": template}


def _libfuzzer_template(target, binary):
    return f"""// Auto-generated libFuzzer harness for: {target}
// Binary: {binary}
//
// Build:
//   clang -fsanitize=fuzzer,address -o fuzz_{target} this_file.c -L/path -ltarget
//
// Run:
//   ./fuzz_{target} corpus_dir/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Forward declaration - match the actual prototype
// TODO: Update this signature to match the real function
extern int {target}(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Minimum input size check
    if (size < 4) return 0;

    // Maximum input size to prevent OOM
    if (size > 1024 * 1024) return 0;

    // Call target function
    {target}(data, size);

    return 0;
}}
"""


def _afl_template(target, binary):
    return f"""// Auto-generated AFL harness for: {target}
// Binary: {binary}
//
// Build:
//   afl-gcc -o fuzz_{target} this_file.c -L/path -ltarget
//
// Run:
//   afl-fuzz -i corpus_dir/ -o findings/ -- ./fuzz_{target} @@

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// TODO: Update this signature to match the real function
extern int {target}(const uint8_t *data, size_t size);

int main(int argc, char *argv[]) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    FILE *f = fopen(argv[1], "rb");
    if (!f) {{
        perror("fopen");
        return 1;
    }}

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size > 1024 * 1024) {{
        fclose(f);
        return 0;
    }}

    uint8_t *data = malloc(size);
    if (!data) {{
        fclose(f);
        return 1;
    }}

    fread(data, 1, size, f);
    fclose(f);

    {target}(data, size);

    free(data);
    return 0;
}}
"""


def _honggfuzz_template(target, binary):
    return f"""// Auto-generated honggfuzz harness for: {target}
// Binary: {binary}
//
// Build:
//   hfuzz-clang -o fuzz_{target} this_file.c -L/path -ltarget
//
// Run:
//   honggfuzz -i corpus_dir/ -- ./fuzz_{target} ___FILE___

#include <stdint.h>
#include <stddef.h>

extern int {target}(const uint8_t *data, size_t size);

extern int HF_ITER(uint8_t **buf, size_t *len);

int main(void) {{
    for (;;) {{
        uint8_t *buf;
        size_t len;
        HF_ITER(&buf, &len);

        if (len < 4 || len > 1024 * 1024) continue;

        {target}(buf, len);
    }}
    return 0;
}}
"""


def generate_dictionary(binary_path):
    """Generate fuzzer dictionary from binary strings."""
    strings_data = get_strings(binary_path, min_length=3, max_count=1000)
    entries = []

    # Magic bytes and headers
    all_strings = []
    for cat in strings_data["categories"].values():
        all_strings.extend(cat)

    # Short unique strings make good dictionary entries
    seen = set()
    for s in all_strings:
        s = s.strip()
        if len(s) < 3 or len(s) > 32:
            continue
        if s in seen:
            continue
        seen.add(s)

        # Format as fuzzer dict entry
        escaped = s.encode("unicode_escape").decode("ascii")
        entries.append(f'"{escaped}"')

        if len(entries) >= 200:
            break

    return {"entries": entries, "total": len(entries)}


def suggest_corpus(binary_path):
    """Suggest seed corpus based on format analysis."""
    imports = get_imports(binary_path)
    suggestions = []

    import_str = " ".join(imports).lower()

    if "png" in import_str or "cgimagesource" in import_str:
        suggestions.append("Collect sample PNG files (PNG parser detected)")
    if "jpeg" in import_str or "jpg" in import_str:
        suggestions.append("Collect sample JPEG files (JPEG parser detected)")
    if "xml" in import_str:
        suggestions.append("Collect sample XML files (XML parser detected)")
    if "json" in import_str:
        suggestions.append("Collect sample JSON files (JSON parser detected)")
    if "pdf" in import_str:
        suggestions.append("Collect sample PDF files (PDF parser detected)")
    if "sqlite" in import_str:
        suggestions.append("Collect sample SQLite databases")
    if "http" in import_str:
        suggestions.append("Collect sample HTTP request/response data")
    if "zip" in import_str or "inflate" in import_str:
        suggestions.append("Collect sample compressed archives (zlib/zip detected)")
    if "protobuf" in import_str:
        suggestions.append("Collect sample protobuf messages")
    if "plist" in import_str:
        suggestions.append("Collect sample plist files")
    if "mojo" in import_str or "ipc" in import_str:
        suggestions.append("Collect Mojo IPC message samples (use MojoLPM corpus)")
    if "v8" in import_str or "javascript" in import_str:
        suggestions.append("Collect JavaScript test cases (V8 test suite, Fuzzilli corpus)")
    if "blink" in import_str or "html" in import_str:
        suggestions.append("Collect HTML/CSS test cases (Domato grammar, web platform tests)")
    if "wasm" in import_str:
        suggestions.append("Collect WebAssembly modules (spec tests, WasmCFuzz corpus)")

    if not suggestions:
        suggestions.append("Analyze binary's input handling to determine format")
        suggestions.append("Use cb attack --parsers to identify format handlers")

    return suggestions


def generate_mojo_fuzzer(args, out):
    """Generate a MojoLPM-style Mojo IPC interface fuzzer."""
    target = args.target or "TargetInterface"

    code = _mojo_fuzzer_template(target)

    result = {
        "target": target,
        "framework": "mojolpm",
        "style": "cpp",
        "build_notes": "Requires Chromium build environment with MojoLPM",
        "code": code,
    }

    if getattr(args, 'generate', False):
        filename = f"fuzz_mojo_{target.lower()}.cc"
        out_path = os.path.join(args.output_dir, filename)
        with open(out_path, "w") as f:
            f.write(code)
        result["output_file"] = out_path
        out.status(f"Mojo fuzzer written to {out_path}")

    return result


def _mojo_fuzzer_template(target):
    return f"""// MojoLPM-style fuzzer for: {target}
// Auto-generated by cb fuzz --mojo
//
// This fuzzer uses MojoLPM (Mojo Libprotobuf Mutator) to generate
// structured Mojo IPC messages for interface fuzzing.
//
// Prerequisites:
//   - Chromium source tree with MojoLPM built
//   - .proto testcase definition (see below)
//   - BUILD.gn integration
//
// Testcase proto (fuzz_{target.lower()}.proto):
//
//   syntax = "proto2";
//   package content.fuzzing.{target.lower()}.proto;
//
//   import "testing/libfuzzer/proto/lpm_interface_fuzzer.proto";
//
//   message Action {{
//     oneof action {{
//       RunUntilIdle run_until_idle = 1;
//       // Add interface-specific actions here
//     }}
//   }}
//
//   message Testcase {{
//     repeated Action actions = 1;
//   }}
//
// BUILD.gn entry:
//
//   mojolpm_fuzzer_test("fuzz_{target.lower()}") {{
//     sources = [ "fuzz_{target.lower()}.cc" ]
//     proto_source = "fuzz_{target.lower()}.proto"
//     deps = [
//       "//content/browser",
//       "//content/public/browser",
//       "//third_party/libprotobuf-mutator",
//     ]
//   }}

#include "content/test/fuzzer/mojolpm_fuzzer_support.h"
#include "third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h"

// Include the generated proto header
#include "fuzz_{target.lower()}.pb.h"

// Include the Mojo interface being fuzzed
// TODO: Update this to the actual interface header
// #include "path/to/{target.lower()}.mojom.h"

#include "base/no_destructor.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "content/browser/browser_context.h"
#include "mojo/public/cpp/bindings/remote.h"

using content::fuzzing::{target.lower()}::proto::Action;
using content::fuzzing::{target.lower()}::proto::Testcase;

namespace {{

class {target}FuzzerEnvironment {{
 public:
  {target}FuzzerEnvironment()
      : fuzzer_support_(
            mojolpm::FuzzerSupport::Create(/* argc= */ 0, /* argv= */ nullptr)) {{
  }}

  mojolpm::FuzzerSupport& fuzzer_support() {{ return *fuzzer_support_; }}

 private:
  std::unique_ptr<mojolpm::FuzzerSupport> fuzzer_support_;
}};

{target}FuzzerEnvironment& GetEnvironment() {{
  static base::NoDestructor<{target}FuzzerEnvironment> environment;
  return *environment;
}}

scoped_refptr<base::SingleThreadTaskRunner> GetFuzzerTaskRunner() {{
  return GetEnvironment().fuzzer_support().fuzzer_task_runner();
}}

void RunAction(const Action& action,
               base::OnceClosure done_closure) {{
  // Dispatch action on the UI thread
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](const Action& action, base::OnceClosure done) {{
            switch (action.action_case()) {{
              case Action::kRunUntilIdle:
                // Let pending tasks complete
                break;
              // TODO: Add cases for interface-specific actions
              default:
                break;
            }}
            std::move(done).Run();
          }},
          std::cref(action), std::move(done_closure)));
}}

}}  // namespace

DEFINE_PROTO_FUZZER(const Testcase& testcase) {{
  // Set up the browser context and interface binding
  mojolpm::FuzzerSupport& support = GetEnvironment().fuzzer_support();

  base::RunLoop run_loop;
  auto done = run_loop.QuitClosure();

  // Execute each action in sequence
  GetFuzzerTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](const Testcase& tc, base::OnceClosure quit) {{
            for (int i = 0; i < tc.actions_size(); i++) {{
              base::RunLoop action_loop;
              RunAction(tc.actions(i), action_loop.QuitClosure());
              action_loop.Run();
            }}
            std::move(quit).Run();
          }},
          std::cref(testcase), std::move(done)));

  run_loop.Run();
}}
"""


def _fuzzed_data_provider_template(target, binary):
    return f"""// Structure-aware fuzzer for: {target}
// Binary: {binary}
// Auto-generated by cb fuzz --structure-aware
//
// Uses FuzzedDataProvider for structured input generation.
//
// Build:
//   clang++ -fsanitize=fuzzer,address -std=c++17 \\
//           -o fuzz_{target} this_file.cc -L/path -ltarget
//
// Run:
//   ./fuzz_{target} corpus_dir/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>

// Forward declaration - match the actual prototype
// TODO: Update this signature to match the real function
extern "C" int {target}(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 8) return 0;

    FuzzedDataProvider provider(data, size);

    // Extract structured fields from fuzz input
    uint32_t msg_type = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
    uint16_t field_count = provider.ConsumeIntegralInRange<uint16_t>(0, 64);
    std::string name = provider.ConsumeRandomLengthString(256);
    bool flag = provider.ConsumeBool();

    // Remaining bytes as raw payload
    std::vector<uint8_t> payload = provider.ConsumeRemainingBytes<uint8_t>();

    if (payload.empty()) return 0;

    // TODO: Build a structured input from the fields above
    // and pass it to the target function.
    //
    // Example: construct a message header + payload
    //   struct Header {{ uint32_t type; uint16_t count; uint8_t flags; }};
    //   Header hdr = {{ msg_type, field_count, flag ? 1 : 0 }};
    //   std::vector<uint8_t> input(sizeof(hdr) + payload.size());
    //   memcpy(input.data(), &hdr, sizeof(hdr));
    //   memcpy(input.data() + sizeof(hdr), payload.data(), payload.size());
    //   {target}(input.data(), input.size());

    {target}(payload.data(), payload.size());

    return 0;
}}
"""


def generate_xpc_fuzzer(args, out):
    """Generate an XPC-aware fuzzing harness."""
    import json as json_mod

    # Load protocol spec
    protocol = None
    if args.protocol_json:
        with open(args.protocol_json) as f:
            protocol = json_mod.load(f)
    elif args.binary:
        # Try to extract protocol inline
        out.status("Extracting XPC protocol from binary...")
        try:
            from cb.ghidra_bridge import run_ghidra_script
            raw = run_ghidra_script(args.binary, "XPCProtocol.java", ["20"], timeout=300)
            if raw:
                protocol = raw
        except Exception as e:
            out.status(f"Warning: Could not extract protocol: {e}")

    service_name = args.service or "com.apple.TARGET_SERVICE"
    messages = []
    if protocol:
        for msg in protocol.get("messages", protocol.get("message_ids", [])):
            msg_info = {"id": msg.get("id", "0"), "handler": msg.get("handler", "")}
            # Find args
            for spec in protocol.get("handler_specs", []):
                if spec.get("handler") == msg.get("handler"):
                    msg_info["args"] = spec.get("args", [])
                    break
            messages.append(msg_info)

    # Generate ObjC fuzzer
    code = _generate_xpc_fuzzer_objc(service_name, messages)
    build_cmd = (
        f"clang -fsanitize=fuzzer,address -framework Foundation "
        f"-o xpc_fuzz fuzz_xpc_{service_name.replace('.', '_')}.m"
    )

    result = {
        "service": service_name,
        "message_count": len(messages),
        "framework": "libfuzzer",
        "style": "objc",
        "build_command": build_cmd,
        "code": code,
    }

    # Write file if --generate
    if getattr(args, 'generate', False):
        filename = f"fuzz_xpc_{service_name.replace('.', '_')}.m"
        out_path = os.path.join(args.output_dir, filename)
        with open(out_path, "w") as f:
            f.write(code)
        result["output_file"] = out_path
        out.status(f"XPC fuzzer written to {out_path}")

    return result


def _generate_xpc_fuzzer_objc(service_name, messages):
    """Generate ObjC XPC fuzzer source code."""
    # Build message builder functions
    msg_builders = []
    msg_cases = []

    if not messages:
        # Generic fallback
        messages = [{"id": "0", "handler": "generic", "args": [
            {"key": "data", "type": "data"},
            {"key": "cmd", "type": "int64"},
        ]}]

    for i, msg in enumerate(messages):
        msg_id = msg.get("id", str(i))
        args = msg.get("args", [])
        handler = msg.get("handler", f"msg_{i}")

        # Generate builder function
        builder = f"""
static xpc_object_t build_msg_{i}(const uint8_t *data, size_t size, size_t *pos) {{
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(msg, "message", {msg_id});
"""
        for arg in args:
            key = arg.get("key", "unknown")
            atype = arg.get("type", "data")
            if atype in ("int64", "uint64"):
                builder += f"""
    if (*pos + 8 <= size) {{
        int64_t val;
        memcpy(&val, data + *pos, 8);
        xpc_dictionary_set_int64(msg, "{key}", val);
        *pos += 8;
    }}
"""
            elif atype == "string":
                builder += f"""
    if (*pos + 1 <= size) {{
        size_t slen = data[*pos] % 64;
        *pos += 1;
        if (*pos + slen <= size) {{
            char buf[65];
            memcpy(buf, data + *pos, slen);
            buf[slen] = '\\0';
            xpc_dictionary_set_string(msg, "{key}", buf);
            *pos += slen;
        }}
    }}
"""
            elif atype == "bool":
                builder += f"""
    if (*pos + 1 <= size) {{
        xpc_dictionary_set_bool(msg, "{key}", data[*pos] & 1);
        *pos += 1;
    }}
"""
            elif atype == "fd":
                builder += f"""
    xpc_dictionary_set_fd(msg, "{key}", STDOUT_FILENO);
"""
            else:  # data, any, array, dictionary
                builder += f"""
    if (*pos + 2 <= size) {{
        size_t dlen = ((size_t)data[*pos] << 8 | data[*pos+1]) % 4096;
        *pos += 2;
        if (*pos + dlen <= size) {{
            xpc_dictionary_set_data(msg, "{key}", data + *pos, dlen);
            *pos += dlen;
        }}
    }}
"""

        builder += "    return msg;\n}"
        msg_builders.append(builder)
        msg_cases.append(f"        case {i}: msg = build_msg_{i}(data + 1, size - 1, &pos); break;")

    builders_code = "\n".join(msg_builders)
    cases_code = "\n".join(msg_cases)
    num_msgs = len(messages)

    return f"""// XPC-aware fuzzer for {service_name}
// Auto-generated by cb fuzz --xpc
//
// Build:
//   clang -fsanitize=fuzzer,address -framework Foundation \\
//         -o xpc_fuzz this_file.m
//
// Run:
//   ./xpc_fuzz corpus_dir/

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static xpc_connection_t g_conn = NULL;
static dispatch_semaphore_t g_sem = NULL;

static void setup_connection(void) {{
    if (g_conn) return;
    g_conn = xpc_connection_create_mach_service(
        "{service_name}", NULL, 0);
    xpc_connection_set_event_handler(g_conn, ^(xpc_object_t event) {{
        // Ignore events during fuzzing
    }});
    xpc_connection_resume(g_conn);
    g_sem = dispatch_semaphore_create(0);
}}

static bool send_with_timeout(xpc_object_t msg, int timeout_sec) {{
    __block bool got_reply = false;
    xpc_connection_send_message_with_reply(g_conn, msg,
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        ^(xpc_object_t reply) {{
            got_reply = true;
            dispatch_semaphore_signal(g_sem);
        }});
    long result = dispatch_semaphore_wait(g_sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_sec * NSEC_PER_SEC));
    return result == 0;
}}
{builders_code}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 2) return 0;
    if (size > 65536) return 0;

    setup_connection();
    if (!g_conn) return 0;

    // First byte selects message type
    uint8_t msg_type = data[0] % {num_msgs};
    size_t pos = 0;
    xpc_object_t msg = NULL;

    switch (msg_type) {{
{cases_code}
        default: return 0;
    }}

    if (msg) {{
        send_with_timeout(msg, 2);
    }}

    return 0;
}}
"""


def main():
    parser = argparse.ArgumentParser(prog="cbfuzz", description="Fuzzing harness generator")
    parser.add_argument("binary")
    parser.add_argument("--target", type=str, default=None)
    parser.add_argument("--auto", action="store_true", default=True)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--framework", choices=["libfuzzer", "afl", "honggfuzz"],
                        default="libfuzzer")
    parser.add_argument("--output-dir", type=str, default=".")
    parser.add_argument("--dict", action="store_true")
    parser.add_argument("--suggest-corpus", action="store_true")
    parser.add_argument("--xpc", action="store_true")
    parser.add_argument("--service", type=str, default=None)
    parser.add_argument("--protocol-json", type=str, default=None)
    parser.add_argument("--xpc-style", choices=["c", "objc"], default="objc")
    parser.add_argument("--mojo", action="store_true")
    parser.add_argument("--structure-aware", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
