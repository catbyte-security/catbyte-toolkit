"""cb objc - Objective-C runtime analysis for macOS/iOS binaries."""
import argparse
import os
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import _run, get_objc_classes, get_objc_selectors


# Interesting ObjC patterns for security research
DANGEROUS_SELECTORS = {
    # Deserialization (type confusion, code exec)
    "initWithCoder:", "encodeWithCoder:", "unarchiveObjectWithData:",
    "unarchiveTopLevelObjectWithData:error:",
    "unarchivedObjectOfClass:fromData:error:",
    "unarchivedObjectOfClasses:fromData:error:",
    # Dynamic code execution
    "performSelector:", "performSelector:withObject:",
    "performSelector:withObject:withObject:",
    "valueForKey:", "setValue:forKey:", "valueForKeyPath:",
    "setValue:forKeyPath:",
    # URL handling (open redirect, SSRF)
    "openURL:", "canOpenURL:",
    "initWithContentsOfURL:", "dataWithContentsOfURL:",
    "stringWithContentsOfURL:encoding:error:",
    # File operations
    "writeToFile:atomically:", "writeToURL:atomically:",
    "removeItemAtPath:error:", "moveItemAtPath:toPath:error:",
    # IPC / XPC
    "listener:shouldAcceptNewConnection:",
    "connection:handleInvocation:",
    # Pasteboard (data exfiltration)
    "generalPasteboard", "setString:forType:",
    # Webview
    "evaluateJavaScript:completionHandler:",
    "loadHTMLString:baseURL:", "loadRequest:",
    # Keychain
    "SecItemAdd", "SecItemCopyMatching",
}

DANGEROUS_PROTOCOLS = {
    "NSCoding",  # Deserialization attack surface
    "NSSecureCoding",  # Safer but still interesting
    "NSXPCListenerDelegate",  # XPC handler
    "NSURLSessionDelegate",  # Network handler
    "NSURLSessionDataDelegate",
    "WKNavigationDelegate",  # WebView handler
    "WKScriptMessageHandler",  # JS→Native bridge
}


def register(subparsers):
    p = subparsers.add_parser("objc", help="Objective-C runtime analysis")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--classes", action="store_true",
                   help="List ObjC classes")
    p.add_argument("--selectors", action="store_true",
                   help="List ObjC selectors")
    p.add_argument("--dangerous", action="store_true",
                   help="Find dangerous ObjC patterns (default when no other mode set)")
    p.add_argument("--class-filter", type=str, default=None,
                   help="Filter classes by regex")
    p.add_argument("--selector-filter", type=str, default=None,
                   help="Filter selectors by regex")
    p.add_argument("--protocols", action="store_true",
                   help="Analyze protocol conformances")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    result = {}
    binary = args.binary

    # Resolve app bundle to binary
    if binary.endswith(".app"):
        import plistlib
        info_plist = os.path.join(binary, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exec_name = plist.get("CFBundleExecutable", "")
            if exec_name:
                binary = os.path.join(binary, "Contents", "MacOS", exec_name)

    # Check cache
    cache_args = {
        "classes": args.classes,
        "selectors": args.selectors,
        "dangerous": args.dangerous,
        "class_filter": args.class_filter,
        "selector_filter": args.selector_filter,
        "protocols": args.protocols,
    }
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cached = cache.get(binary, "objc", cache_args)
            if cached:
                cached.setdefault("_meta", {})["cached"] = True
                out.emit(cached, "objc")
                return
        except Exception:
            pass

    out.status("Extracting Objective-C metadata...")

    # Get classes
    classes = get_objc_classes(binary)
    if args.class_filter:
        try:
            pat = re.compile(args.class_filter, re.IGNORECASE)
        except re.error as e:
            out.emit({"error": f"Invalid --class-filter regex: {e}"}, "objc")
            return
        classes = [c for c in classes if pat.search(c)]

    # Get selectors
    selectors = get_objc_selectors(binary)
    if args.selector_filter:
        try:
            pat = re.compile(args.selector_filter, re.IGNORECASE)
        except re.error as e:
            out.emit({"error": f"Invalid --selector-filter regex: {e}"}, "objc")
            return
        selectors = [s for s in selectors if pat.search(s)]

    if args.classes:
        result["classes"] = {
            "total": len(classes),
            "list": classes[:args.max_results],
        }

    if args.selectors:
        result["selectors"] = {
            "total": len(selectors),
            "list": selectors[:args.max_results],
        }

    # Dangerous patterns analysis — run by default, skip if user only asked for --classes/--selectors
    if args.dangerous or not (args.classes or args.selectors):
        out.status("Scanning for dangerous Objective-C patterns...")

        findings = []
        selector_set = set(selectors)

        # Check for dangerous selectors
        for sel in DANGEROUS_SELECTORS:
            if sel in selector_set:
                category = _categorize_selector(sel)
                findings.append({
                    "type": "dangerous_selector",
                    "selector": sel,
                    "category": category["category"],
                    "severity": category["severity"],
                    "description": category["description"],
                })

        # Check for NSCoding conformance (deserialization attack surface)
        nscoding_classes = [c for c in classes
                           if any(s in selector_set for s in
                                  [f"-[{c} initWithCoder:]", "initWithCoder:"])]

        # Check class names for interesting patterns
        for cls in classes:
            cls_lower = cls.lower()
            if any(x in cls_lower for x in ["handler", "delegate", "listener",
                                              "controller", "manager"]):
                # Check if it has XPC or IPC related selectors
                interesting_sels = [s for s in selectors
                                    if cls in s and any(x in s for x in
                                        ["connection", "message", "request",
                                         "handle", "process", "receive"])]
                if interesting_sels:
                    findings.append({
                        "type": "ipc_handler_class",
                        "class": cls,
                        "severity": "high",
                        "interesting_selectors": interesting_sels[:10],
                        "description": f"Class {cls} appears to handle IPC/messages",
                    })

        # Check for NSKeyedUnarchiver usage (deserialization)
        if "NSKeyedUnarchiver" in " ".join(selectors):
            findings.append({
                "type": "deserialization",
                "severity": "high",
                "description": "Uses NSKeyedUnarchiver - check for insecure deserialization. "
                               "Verify NSSecureCoding is enforced and allowedClasses is restricted.",
            })

        # Check for evaluateJavaScript (XSS in native apps)
        if "evaluateJavaScript:completionHandler:" in selector_set:
            findings.append({
                "type": "javascript_bridge",
                "severity": "high",
                "description": "Uses evaluateJavaScript - check if user-controlled data "
                               "reaches the JS string (native XSS / code execution)",
            })

        # Check for KVC/KVO (property manipulation)
        kvc_sels = {"valueForKey:", "setValue:forKey:",
                     "valueForKeyPath:", "setValue:forKeyPath:"}
        if kvc_sels & selector_set:
            findings.append({
                "type": "kvc_usage",
                "severity": "medium",
                "description": "Uses Key-Value Coding - check if key strings are "
                               "user-controlled (arbitrary property access)",
            })

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 4))

        result["dangerous_patterns"] = {
            "total": len(findings),
            "findings": findings[:args.max_results],
        }

    result["summary"] = {
        "total_classes": len(classes),
        "total_selectors": len(selectors),
        "dangerous_findings": len(result.get("dangerous_patterns", {}).get("findings", [])),
    }

    # Cache store
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(binary, "objc", cache_args, result)
        except Exception:
            pass

    out.emit(result, "objc")


def _categorize_selector(sel):
    if any(x in sel for x in ["Coder", "archive", "Unarchiv"]):
        return {"category": "deserialization", "severity": "high",
                "description": "NSCoding deserialization - type confusion risk"}
    if any(x in sel for x in ["performSelector", "valueForKey", "setValue:forKey"]):
        return {"category": "dynamic_dispatch", "severity": "medium",
                "description": "Dynamic method/property access - check if input-controlled"}
    if any(x in sel for x in ["openURL", "loadRequest", "evaluateJavaScript"]):
        return {"category": "code_execution", "severity": "high",
                "description": "URL/JS execution - check for injection"}
    if any(x in sel for x in ["writeToFile", "removeItem", "moveItem"]):
        return {"category": "file_operation", "severity": "medium",
                "description": "File operation - check path traversal"}
    if any(x in sel for x in ["connection", "handleInvocation", "listener"]):
        return {"category": "ipc", "severity": "high",
                "description": "IPC handler - check authorization"}
    return {"category": "other", "severity": "low",
            "description": "Potentially dangerous selector"}


def main():
    parser = argparse.ArgumentParser(prog="cbobjc", description="ObjC analysis")
    parser.add_argument("binary")
    parser.add_argument("--classes", action="store_true")
    parser.add_argument("--selectors", action="store_true")
    parser.add_argument("--dangerous", action="store_true")
    parser.add_argument("--class-filter", type=str, default=None)
    parser.add_argument("--selector-filter", type=str, default=None)
    parser.add_argument("--protocols", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
