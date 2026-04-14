// Build call graph and find paths from entries to dangerous sinks.
// Usage: analyzeHeadless ... -postScript CallGraph.java <mode:sinks|full|from_func> <target> <max_depth> <max_results>
// @category CatByte

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class CallGraph extends GhidraScript {

    private static final Set<String> DANGEROUS_SINKS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf",
        "system", "popen", "execve", "dlopen",
        "mach_msg_send", "xpc_connection_send_message",
        "IOConnectCallMethod", "IOConnectCallStructMethod",
        "objc_msgSend"
    ));

    private static final Set<String> ENTRY_POINTS = new HashSet<>(Arrays.asList(
        "main", "_main", "xpc_main", "CFRunLoopRun",
        "NSApplicationMain", "UIApplicationMain"
    ));

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "sinks";
        String target = args.length > 1 ? args[1] : "";
        int maxDepth = args.length > 2 ? Integer.parseInt(args[2]) : 8;
        int maxResults = args.length > 3 ? Integer.parseInt(args[3]) : 50;

        FunctionManager fm = currentProgram.getFunctionManager();

        StringBuilder json = new StringBuilder();
        json.append("{");

        if (mode.equals("sinks")) {
            // Find all paths from any function to dangerous sinks
            json.append("\"mode\":\"sink_reachability\",");
            json.append("\"paths\":");
            json.append(findPathsToSinks(fm, maxDepth, maxResults));
        } else if (mode.equals("from_func")) {
            // Build call graph from a specific function
            Function func = resolveFunction(target);
            if (func == null) {
                json.append("\"error\":\"Function not found: ").append(target).append("\"");
            } else {
                json.append("\"mode\":\"from_function\",");
                json.append("\"root\":").append(quote(func.getName())).append(",");
                json.append("\"graph\":");
                Set<String> visited = new HashSet<>();
                json.append(buildGraph(func, maxDepth, visited, 0));
            }
        } else {
            // Full call graph statistics
            json.append("\"mode\":\"statistics\",");
            json.append(buildStats(fm, maxResults));
        }

        json.append("}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String findPathsToSinks(FunctionManager fm, int maxDepth, int maxResults)
            throws Exception {
        List<String> paths = new ArrayList<>();

        // Find all sink functions in the binary
        Map<String, Function> sinkFunctions = new HashMap<>();
        for (Function f : fm.getFunctions(true)) {
            String name = f.getName().replaceAll("^_+", "");
            if (DANGEROUS_SINKS.contains(name)) {
                sinkFunctions.put(f.getName(), f);
            }
        }

        // For each sink, trace callers back to find reachable paths
        for (Map.Entry<String, Function> entry : sinkFunctions.entrySet()) {
            if (paths.size() >= maxResults || monitor.isCancelled()) break;

            Function sink = entry.getValue();
            Set<Function> callers = sink.getCallingFunctions(monitor);

            for (Function caller : callers) {
                if (paths.size() >= maxResults) break;

                // Build the chain from caller up to entry
                List<String> chain = new ArrayList<>();
                chain.add(entry.getKey()); // sink
                chain.add(caller.getName());

                // Walk up call tree
                Function current = caller;
                Set<String> seen = new HashSet<>();
                seen.add(caller.getName());
                boolean reachesEntry = false;

                for (int depth = 0; depth < maxDepth; depth++) {
                    Set<Function> upper = current.getCallingFunctions(monitor);
                    if (upper.isEmpty()) break;

                    // Pick the first unseen caller
                    Function next = null;
                    for (Function u : upper) {
                        if (!seen.contains(u.getName())) {
                            next = u;
                            break;
                        }
                    }
                    if (next == null) break;

                    chain.add(next.getName());
                    seen.add(next.getName());
                    String cleanName = next.getName().replaceAll("^_+", "");
                    if (ENTRY_POINTS.contains(cleanName)) {
                        reachesEntry = true;
                        break;
                    }
                    current = next;
                }

                Collections.reverse(chain);

                StringBuilder path = new StringBuilder();
                path.append("{");
                path.append("\"sink\":").append(quote(entry.getKey())).append(",");
                path.append("\"caller\":").append(quote(caller.getName())).append(",");
                path.append("\"caller_address\":").append(quote(caller.getEntryPoint().toString())).append(",");
                path.append("\"caller_size\":").append(caller.getBody().getNumAddresses()).append(",");
                path.append("\"reaches_entry\":").append(reachesEntry).append(",");
                path.append("\"chain\":").append(jsonArray(chain)).append(",");
                path.append("\"depth\":").append(chain.size());
                path.append("}");
                paths.add(path.toString());
            }
        }

        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < paths.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(paths.get(i));
        }
        sb.append("]");
        return sb.toString();
    }

    private String buildGraph(Function func, int maxDepth, Set<String> visited, int depth)
            throws Exception {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"name\":").append(quote(func.getName())).append(",");
        sb.append("\"address\":").append(quote(func.getEntryPoint().toString())).append(",");
        sb.append("\"size\":").append(func.getBody().getNumAddresses()).append(",");

        // Check if it's a dangerous sink
        String cleanName = func.getName().replaceAll("^_+", "");
        boolean isSink = DANGEROUS_SINKS.contains(cleanName);
        sb.append("\"is_sink\":").append(isSink).append(",");

        if (depth < maxDepth && !visited.contains(func.getName()) && !isSink) {
            visited.add(func.getName());
            Set<Function> callees = func.getCalledFunctions(monitor);
            sb.append("\"callees\":[");
            int i = 0;
            for (Function callee : callees) {
                if (i > 0) sb.append(",");
                if (i >= 20) { // Limit branching
                    sb.append("{\"name\":").append(quote("...")).append(",\"truncated\":true}");
                    break;
                }
                sb.append(buildGraph(callee, maxDepth, visited, depth + 1));
                i++;
            }
            sb.append("]");
        } else {
            sb.append("\"callees\":[]");
            if (visited.contains(func.getName())) {
                sb.append(",\"recursive\":true");
            }
        }

        sb.append("}");
        return sb.toString();
    }

    private String buildStats(FunctionManager fm, int maxResults) throws Exception {
        int totalFunctions = 0;
        int sinkCallers = 0;
        List<String> hotspots = new ArrayList<>(); // Functions calling most sinks

        Map<String, Integer> sinkCallCounts = new HashMap<>();

        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            totalFunctions++;

            Set<Function> callees = f.getCalledFunctions(monitor);
            int sinkCount = 0;
            List<String> sinks = new ArrayList<>();
            for (Function callee : callees) {
                String name = callee.getName().replaceAll("^_+", "");
                if (DANGEROUS_SINKS.contains(name)) {
                    sinkCount++;
                    sinks.add(name);
                }
            }
            if (sinkCount > 0) {
                sinkCallers++;
                if (sinkCount >= 2) { // Functions calling 2+ sinks are interesting
                    hotspots.add("{\"name\":" + quote(f.getName()) +
                        ",\"address\":" + quote(f.getEntryPoint().toString()) +
                        ",\"size\":" + f.getBody().getNumAddresses() +
                        ",\"sink_count\":" + sinkCount +
                        ",\"sinks\":" + jsonArray(sinks) + "}");
                }
            }
        }

        // Sort hotspots by sink count (descending) via simple comparison
        hotspots.sort((a, b) -> {
            int ca = Integer.parseInt(a.replaceAll(".*sink_count\":(\\d+).*", "$1"));
            int cb = Integer.parseInt(b.replaceAll(".*sink_count\":(\\d+).*", "$1"));
            return cb - ca;
        });

        StringBuilder sb = new StringBuilder();
        sb.append("\"total_functions\":").append(totalFunctions).append(",");
        sb.append("\"functions_calling_sinks\":").append(sinkCallers).append(",");
        sb.append("\"hotspots\":[");
        for (int i = 0; i < Math.min(hotspots.size(), maxResults); i++) {
            if (i > 0) sb.append(",");
            sb.append(hotspots.get(i));
        }
        sb.append("]");
        return sb.toString();
    }

    private String jsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(quote(items.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private Function resolveFunction(String target) {
        if (target.startsWith("0x")) {
            try {
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(target);
                return getFunctionAt(addr);
            } catch (Exception e) { return null; }
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(target) || f.getName().contains(target)) return f;
        }
        return null;
    }

    private String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
