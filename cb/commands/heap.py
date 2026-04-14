"""cb heap - macOS Heap Exploitation Helper.

Classify allocation sizes into macOS magazine malloc zones, generate heap
spray plans with ObjC/C code, produce ASCII zone charts, and emit
zone-aware Frida allocation-tracking hooks.  Pure Python, no external tools.
"""
import argparse
import sys
import textwrap

from cb.output import add_output_args, make_formatter

# ---------------------------------------------------------------------------
# Zone geometry (arm64 / Apple Silicon)
# ---------------------------------------------------------------------------
ZONES = [
    {"name": "nano",  "min": 1,      "max": 256,    "quantum": 16,    "classes": 16,   "note": "arm64 only, per-CPU magazines"},
    {"name": "tiny",  "min": 257,    "max": 1008,   "quantum": 16,    "classes": 47,   "note": "free-list ordering, 16 B quantum"},
    {"name": "small", "min": 1009,   "max": 130048, "quantum": 512,   "classes": 254,  "note": "512 B quantum, region-based"},
    {"name": "large", "min": 130049, "max": None,   "quantum": 16384, "classes": None,  "note": "page-aligned (16 KB arm64)"},
]
_QUANTUM = {"nano": 16, "tiny": 16, "small": 512, "large": 16384}

# ---------------------------------------------------------------------------
# Core computation helpers
# ---------------------------------------------------------------------------

def size_to_zone(size: int) -> str:
    if size <= 256:       return "nano"
    if size <= 1008:      return "tiny"
    if size <= 127 * 1024: return "small"
    return "large"

def size_to_class(size: int) -> int:
    zone = size_to_zone(size)
    if zone in ("nano", "tiny"): return ((size + 15) // 16) * 16
    if zone == "small":          return ((size + 511) // 512) * 512
    return ((size + 16383) // 16384) * 16384

def classify_size(size: int) -> dict:
    zone = size_to_zone(size)
    cls = size_to_class(size)
    waste = cls - size
    return {
        "size": size, "zone": zone, "size_class": cls,
        "quantum": _QUANTUM[zone], "waste_bytes": waste,
        "waste_pct": round(waste / cls * 100, 1) if cls else 0.0,
    }

# ---------------------------------------------------------------------------
# Spray plan
# ---------------------------------------------------------------------------
_ZONE_NOTES = {
    "nano": [
        "nano zone uses per-CPU magazines -- spray must fill the magazine and spill into the region.",
        "nano zone is arm64-only; on x86_64 these sizes fall into tiny zone.",
        "Objects <= 256 B share 16-byte-aligned slots; similar sizes land in the same bucket.",
    ],
    "tiny": [
        "tiny zone free list is address-ordered; freeing every other object creates predictable holes.",
        "Magazine caching may delay reuse -- over-spray by ~20 % to compensate.",
    ],
    "small": [
        "small zone 512 B quanta can waste space for sizes just over a boundary.",
        "Region headers are separate from data -- metadata corruption needs a different primitive.",
    ],
    "large": [
        "large allocations use vm_allocate, page-aligned, individually tracked.",
        "Spraying large allocations is expensive; prefer a smaller target size if possible.",
    ],
}

def generate_spray_code(target_size: int, count: int,
                        payload: str = None, language: str = "objc") -> str:
    cls = size_to_class(target_size)
    zone = size_to_zone(target_size)
    fb = payload or "0x41"
    if language == "objc":
        return textwrap.dedent(f"""\
            // Heap spray: {count} x {cls} bytes  (zone: {zone})
            #import <Foundation/Foundation.h>
            void heap_spray(void) {{
                NSMutableArray *spray = [NSMutableArray arrayWithCapacity:{count}];
                // Step 1 -- fill magazine + region
                for (NSUInteger i = 0; i < {count}; i++) {{
                    NSMutableData *d = [NSMutableData dataWithLength:{cls}];
                    memset(d.mutableBytes, {fb}, {cls});
                    [spray addObject:d];
                }}
                // Step 2 -- poke holes (free every other object)
                for (NSInteger i = {count} - 1; i >= 0; i -= 2)
                    [spray removeObjectAtIndex:i];
                // Step 3 -- trigger target allocation ({target_size} B) to land in hole
                // <insert target trigger here>
                // Step 4 -- spray replacement objects with controlled data
                for (NSUInteger i = 0; i < {count} / 2; i++) {{
                    NSMutableData *d = [NSMutableData dataWithLength:{cls}];
                    memset(d.mutableBytes, {fb}, {cls});
                    [spray addObject:d];
                }}
            }}""")
    # C variant
    return textwrap.dedent(f"""\
        // Heap spray: {count} x {cls} bytes  (zone: {zone})
        #include <stdlib.h>
        #include <string.h>
        void heap_spray(void) {{
            void *spray[{count}];
            // Step 1 -- fill magazine + region
            for (int i = 0; i < {count}; i++) {{
                spray[i] = malloc({cls});
                memset(spray[i], {fb}, {cls});
            }}
            // Step 2 -- poke holes
            for (int i = 0; i < {count}; i += 2) {{ free(spray[i]); spray[i] = NULL; }}
            // Step 3 -- trigger target allocation ({target_size} B) to land in hole
            // <insert target trigger here>
            // Step 4 -- spray replacement objects with controlled data
            for (int i = 0; i < {count}; i += 2) {{
                spray[i] = malloc({cls});
                memset(spray[i], {fb}, {cls});
            }}
        }}""")

def generate_spray_plan(target_size: int, spray_count: int = 5000,
                        payload: str = None, language: str = "objc") -> dict:
    info = classify_size(target_size)
    zone, cls = info["zone"], info["size_class"]
    strategy = [
        {"step": 1, "action": f"Spray {spray_count} objects of size {cls} to fill magazine and region",
         "detail": "Saturates the free list so subsequent allocations come from a fresh region."},
        {"step": 2, "action": "Free every other object to create holes",
         "detail": "Creates alternating live/free slots for the target to land in."},
        {"step": 3, "action": "Trigger target allocation to land in hole",
         "detail": f"Vulnerable path allocates {target_size} B (rounded to {cls}), reuses a freed slot."},
        {"step": 4, "action": "Spray replacement objects with controlled data",
         "detail": "Fills remaining holes with attacker-controlled data for corruption."},
    ]
    code = generate_spray_code(target_size, spray_count, payload=payload, language=language)
    notes = list(_ZONE_NOTES.get(zone, []))
    if zone == "nano":
        notes.append("WARNING: nano zone is arm64-only.  Intel Macs use tiny zone for these sizes.")
    return {
        "target_size": target_size, "zone": zone, "size_class": cls,
        "quantum": info["quantum"], "waste_bytes": info["waste_bytes"],
        "waste_pct": info["waste_pct"], "spray_count": spray_count,
        "language": language, "strategy": strategy, "code": code, "notes": notes,
    }

# ---------------------------------------------------------------------------
# Zone chart
# ---------------------------------------------------------------------------

def zone_chart() -> str:
    lines = ["macOS Heap Zones (arm64)", "=" * 60, ""]
    hdr = f"{'Zone':<8}| {'Size Range':<20}| {'Quantum':<9}| {'Classes'}"
    lines += [hdr, f"{'-'*8}|{'-'*20}|{'-'*9}|{'-'*15}"]
    for z in ZONES:
        rng = f"{z['min']:,} - {z['max']:,}" if z["max"] else f"> {z['min']-1:,}"
        cl = str(z["classes"]) if z["classes"] is not None else "(page-aligned)"
        lines.append(f"{z['name']:<8}| {rng:<20}| {str(z['quantum']):<9}| {cl}")
    lines.append("")
    # Visual bar
    lines.append("Visual Scale (log2, not to scale):")
    lines.append("")
    segs = [("nano", 12, "="), ("tiny", 10, "#"), ("small", 22, "-"), ("large", 12, ".")]
    bar = "".join(f"|{ch*(w-1)}" for _, w, ch in segs) + "|"
    lbl = "".join(n.center(w) for n, w, _ in segs)
    lines += [f"  {bar}", f"  {lbl}",
              f"  1{'':>11}256{'':>7}1,008{'':>16}130,048{'':>5}...",
              "", "Quantum:  16 B         16 B         512 B            16 KB", ""]
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Frida hooks
# ---------------------------------------------------------------------------

def _frida_hook_block(fn, body_enter, body_leave=""):
    """Return a JS Interceptor.attach block for *fn*."""
    leave = ""
    if body_leave:
        leave = f",\n        onLeave: function(retval) {{\n{body_leave}\n        }}"
    return (f'    var _{fn} = Module.findExportByName(null, "{fn}");\n'
            f'    if (_{fn}) {{\n'
            f'      Interceptor.attach(_{fn}, {{\n'
            f'        onEnter: function(args) {{\n{body_enter}\n        }}'
            f'{leave}\n      }});\n'
            f'      console.log("[+] Hooked {fn}");\n'
            f'    }}')

def generate_frida_hooks(zone: str = "all") -> str:
    parts = [f"// Auto-generated by cb heap frida-hooks  (zone: {zone})",
             "'use strict';", "(function() {",
             "    var log = {}, stats = {malloc:0,free:0,calloc:0,realloc:0};"]
    # Optional zone filter
    filt = ""
    if zone != "all":
        lo, hi = {"nano": (1,256), "tiny": (257,1008),
                  "small": (1009,130048), "large": (130049,None)}[zone]
        if hi:
            parts.append(f"    function inZone(s){{ return s>={lo}&&s<={hi}; }}")
        else:
            parts.append(f"    function inZone(s){{ return s>={lo}; }}")
        filt = "          if(!inZone(this._sz)) return;"

    # malloc
    me = f"          this._sz=args[0].toInt32();\n{filt}" if filt else "          this._sz=args[0].toInt32();"
    ml = (f"          if(retval.isNull()) return;\n{filt}\n" if filt else "          if(retval.isNull()) return;\n")
    ml += ("          stats.malloc++; log[retval.toString()]=this._sz;\n"
           "          send({type:'malloc',size:this._sz,ptr:retval.toString()});")
    parts.append(_frida_hook_block("malloc", me, ml))

    # free
    fe = ("          var p=args[0]; if(p.isNull()) return;\n"
          "          var k=p.toString(), sz=log[k]||-1; this._sz=sz;\n")
    if filt: fe += filt + "\n"
    fe += ("          stats.free++;\n"
           "          if(!(k in log)){send({type:'free_untracked',ptr:k,bt:Thread.backtrace("
           "this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(String).slice(0,5)});}\n"
           "          else{send({type:'free',ptr:k,size:sz}); delete log[k];}")
    parts.append(_frida_hook_block("free", fe))

    # calloc
    ce = "          this._cnt=args[0].toInt32(); this._sz=args[1].toInt32(); this._t=this._cnt*this._sz;"
    if filt: ce += "\n" + filt
    cl = (f"          if(retval.isNull()) return;\n{filt}\n" if filt else "          if(retval.isNull()) return;\n")
    cl += ("          stats.calloc++; log[retval.toString()]=this._t;\n"
           "          send({type:'calloc',count:this._cnt,size:this._sz,total:this._t,ptr:retval.toString()});")
    parts.append(_frida_hook_block("calloc", ce, cl))

    # realloc
    re = "          this._old=args[0].isNull()?null:args[0].toString(); this._sz=args[1].toInt32();"
    if filt: re += "\n" + filt
    rl = (f"          if(retval.isNull()) return;\n{filt}\n" if filt else "          if(retval.isNull()) return;\n")
    rl += ("          stats.realloc++;\n"
           "          if(this._old&&this._old in log) delete log[this._old];\n"
           "          log[retval.toString()]=this._sz;\n"
           "          send({type:'realloc',old:this._old,ptr:retval.toString(),size:this._sz});")
    parts.append(_frida_hook_block("realloc", re, rl))

    # Zone-specific internal allocators
    for zn in ("nano", "tiny", "small"):
        if zone != "all" and zone != zn:
            continue
        fn = f"{zn}_malloc"
        ze = "          this._sz=args[1].toInt32();"
        zl = (f"          if(!retval.isNull()) send({{type:'{fn}',"
              f"size:this._sz,ptr:retval.toString()}});")
        parts.append(_frida_hook_block(fn, ze, zl))

    # Periodic stats
    parts += [
        "    setInterval(function(){send({type:'heap_stats',malloc:stats.malloc,free:stats.free,"
        "calloc:stats.calloc,realloc:stats.realloc,live:Object.keys(log).length});},5000);",
        "    console.log('[*] Heap hooks active.  Stats every 5 s.');",
        "})();", "",
    ]
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------

def register(subparsers):
    p = subparsers.add_parser("heap", help="macOS heap exploitation helper")
    sub = p.add_subparsers(dest="heap_command")

    s = sub.add_parser("classify", help="Zone + size class for an allocation size")
    s.add_argument("size", type=int, help="Allocation size in bytes")
    add_output_args(s)
    s.set_defaults(func=run)

    s = sub.add_parser("plan", help="Full heap spray plan for a target size")
    s.add_argument("target_size", type=int, help="Target allocation size in bytes")
    s.add_argument("--spray-count", type=int, default=5000, help="Spray objects (default: 5000)")
    s.add_argument("--payload", type=str, default=None, help="Fill byte (e.g. 0x41)")
    s.add_argument("--language", choices=["objc", "c"], default="objc", help="Code language (default: objc)")
    add_output_args(s)
    s.set_defaults(func=run)

    s = sub.add_parser("chart", help="ASCII zone boundary chart")
    add_output_args(s)
    s.set_defaults(func=run)

    s = sub.add_parser("frida-hooks", help="Zone-aware Frida allocation tracking hooks")
    s.add_argument("--zone", choices=["all", "nano", "tiny", "small", "large"],
                   default="all", help="Filter to zone (default: all)")
    add_output_args(s)
    s.set_defaults(func=run)

    p.set_defaults(func=run)

# ---------------------------------------------------------------------------
# Run handler
# ---------------------------------------------------------------------------

def run(args):
    out = make_formatter(args)
    cmd = getattr(args, "heap_command", None)

    if cmd == "classify":
        if args.size <= 0:
            out.status("Error: size must be positive"); sys.exit(1)
        out.status(f"Classifying size {args.size} ...")
        out.emit(classify_size(args.size), "heap")

    elif cmd == "plan":
        if args.target_size <= 0:
            out.status("Error: target_size must be positive"); sys.exit(1)
        out.status(f"Generating spray plan for {args.target_size} B "
                   f"({args.language}, {args.spray_count} objects) ...")
        out.emit(generate_spray_plan(args.target_size, spray_count=args.spray_count,
                                     payload=args.payload, language=args.language), "heap")

    elif cmd == "chart":
        out.status("Generating zone chart ...")
        out.emit({"chart": zone_chart()}, "heap")

    elif cmd == "frida-hooks":
        out.status(f"Generating Frida hooks (zone: {args.zone}) ...")
        out.emit({"zone_filter": args.zone, "frida_script": generate_frida_hooks(args.zone)}, "heap")

    else:
        out.status("No heap sub-command specified.")
        out.emit({"usage": "cb heap {classify,plan,chart,frida-hooks}",
                  "commands": {"classify": "Zone + size class for an allocation size",
                               "plan": "Full heap spray plan for a target size",
                               "chart": "ASCII zone boundary chart",
                               "frida-hooks": "Zone-aware Frida allocation tracking hooks"}}, "heap")

# ---------------------------------------------------------------------------
# Standalone entry point (cbheap)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="cbheap", description="macOS Heap Exploitation Helper")
    sub = parser.add_subparsers(dest="heap_command")

    s = sub.add_parser("classify", help="Zone + size class for an allocation size")
    s.add_argument("size", type=int); add_output_args(s)

    s = sub.add_parser("plan", help="Full heap spray plan")
    s.add_argument("target_size", type=int)
    s.add_argument("--spray-count", type=int, default=5000)
    s.add_argument("--payload", type=str, default=None)
    s.add_argument("--language", choices=["objc", "c"], default="objc")
    add_output_args(s)

    s = sub.add_parser("chart", help="ASCII zone boundary chart"); add_output_args(s)

    s = sub.add_parser("frida-hooks", help="Zone-aware Frida hooks")
    s.add_argument("--zone", choices=["all", "nano", "tiny", "small", "large"], default="all")
    add_output_args(s)

    args = parser.parse_args()
    run(args)

if __name__ == "__main__":
    main()
