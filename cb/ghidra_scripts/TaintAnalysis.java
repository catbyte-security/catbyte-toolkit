// Inter-procedural taint analysis: trace data from sources to sinks.
// Usage: analyzeHeadless ... -postScript TaintAnalysis.java <source_func_or_"auto"> <max_depth> <max_results>
// @category CatByte

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.util.regex.*;

public class TaintAnalysis extends GhidraScript {

    // Data sources: where untrusted input enters
    private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
        "read", "recv", "recvfrom", "recvmsg", "fread", "fgets",
        "mach_msg", "mach_msg_receive", "xpc_dictionary_get_string",
        "xpc_dictionary_get_data", "xpc_dictionary_get_value",
        "xpc_dictionary_get_int64", "xpc_dictionary_get_uint64",
        "CFReadStreamRead", "NSInputStream",
        "getenv", "scanf", "fscanf", "sscanf",
        "CGImageSourceCreateWithData", "CGImageSourceCreateWithURL",
        "xmlParseMemory", "xmlReadMemory",
        "NSKeyedUnarchiver", "NSPropertyListSerialization"
    ));

    // Dangerous sinks: where tainted data causes harm
    private static final Set<String> TAINT_SINKS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "bcopy", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf",
        "malloc", "calloc", "realloc", "alloca",
        "system", "popen", "exec", "execve", "execvp",
        "mach_msg", "mach_msg_send", "xpc_connection_send_message",
        "printf", "fprintf", "syslog", "NSLog",
        "open", "fopen", "unlink", "rename",
        "objc_msgSend", "IOConnectCallMethod", "IOConnectCallStructMethod",
        "SecItemAdd", "SecItemUpdate"
    ));

    // Propagation functions: taint passes through these
    private static final Set<String> PROPAGATORS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
        "strdup", "strndup", "realloc",
        "CFStringCreateWithBytes", "CFDataCreate",
        "NSData", "NSString", "NSMutableData"
    ));

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String sourceSpec = args.length > 0 ? args[0] : "auto";
        int maxDepth = args.length > 1 ? Integer.parseInt(args[1]) : 5;
        int maxResults = args.length > 2 ? Integer.parseInt(args[2]) : 50;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        List<String> flows = new ArrayList<>();

        // Find all taint source call sites
        List<Function> sourceFunctions = new ArrayList<>();
        if (sourceSpec.equals("auto")) {
            // Auto-detect: find functions that call taint sources
            for (Function f : fm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                Set<Function> callees = f.getCalledFunctions(monitor);
                for (Function callee : callees) {
                    String name = callee.getName().replaceAll("^_+", "");
                    if (TAINT_SOURCES.contains(name)) {
                        sourceFunctions.add(f);
                        break;
                    }
                }
            }
        } else {
            Function f = resolveFunction(sourceSpec);
            if (f != null) sourceFunctions.add(f);
        }

        monitor.setMessage("Found " + sourceFunctions.size() + " functions with taint sources");

        // For each source function, trace data flow to sinks
        int flowCount = 0;
        for (Function sourceFunc : sourceFunctions) {
            if (monitor.isCancelled() || flowCount >= maxResults) break;

            Set<Function> callees = sourceFunc.getCalledFunctions(monitor);
            List<String> sources = new ArrayList<>();
            List<String> sinks = new ArrayList<>();

            for (Function callee : callees) {
                String name = callee.getName().replaceAll("^_+", "");
                if (TAINT_SOURCES.contains(name)) sources.add(name);
                if (TAINT_SINKS.contains(name)) sinks.add(name);
            }

            if (!sources.isEmpty() && !sinks.isEmpty()) {
                // Direct source-to-sink in same function
                StringBuilder flow = new StringBuilder();
                flow.append("{");
                flow.append("\"type\":\"direct\",");
                flow.append("\"function\":").append(quote(sourceFunc.getName())).append(",");
                flow.append("\"address\":").append(quote(sourceFunc.getEntryPoint().toString())).append(",");
                flow.append("\"size\":").append(sourceFunc.getBody().getNumAddresses()).append(",");
                flow.append("\"sources\":").append(jsonArray(sources)).append(",");
                flow.append("\"sinks\":").append(jsonArray(sinks)).append(",");
                flow.append("\"severity\":").append(quote(scoreSeverity(sources, sinks)));

                // Decompile to get the actual code
                try {
                    DecompileResults dr = decomp.decompileFunction(sourceFunc, 30, monitor);
                    if (dr.getDecompiledFunction() != null) {
                        String code = dr.getDecompiledFunction().getC();
                        // Extract relevant lines (containing source or sink calls)
                        StringBuilder snippet = new StringBuilder();
                        for (String line : code.split("\n")) {
                            String trimmed = line.trim();
                            for (String s : sources) {
                                if (trimmed.contains(s)) { snippet.append(trimmed).append("\\n"); break; }
                            }
                            for (String s : sinks) {
                                if (trimmed.contains(s)) { snippet.append(trimmed).append("\\n"); break; }
                            }
                        }
                        flow.append(",\"code_snippet\":").append(quote(snippet.toString()));
                    }
                } catch (Exception e) { /* skip decompilation */ }

                flow.append("}");
                flows.add(flow.toString());
                flowCount++;
            }

            // Check inter-procedural: source function's callers that also reach sinks
            if (flowCount < maxResults && !sources.isEmpty()) {
                Set<Function> callers = sourceFunc.getCallingFunctions(monitor);
                for (Function caller : callers) {
                    if (flowCount >= maxResults) break;
                    Set<Function> callerCallees = caller.getCalledFunctions(monitor);
                    List<String> callerSinks = new ArrayList<>();
                    for (Function cc : callerCallees) {
                        String name = cc.getName().replaceAll("^_+", "");
                        if (TAINT_SINKS.contains(name)) callerSinks.add(name);
                    }
                    if (!callerSinks.isEmpty()) {
                        StringBuilder flow = new StringBuilder();
                        flow.append("{");
                        flow.append("\"type\":\"interprocedural\",");
                        flow.append("\"source_function\":").append(quote(sourceFunc.getName())).append(",");
                        flow.append("\"sink_function\":").append(quote(caller.getName())).append(",");
                        flow.append("\"sink_address\":").append(quote(caller.getEntryPoint().toString())).append(",");
                        flow.append("\"sources\":").append(jsonArray(sources)).append(",");
                        flow.append("\"sinks\":").append(jsonArray(callerSinks)).append(",");
                        flow.append("\"chain\":[").append(quote(sourceFunc.getName()));
                        flow.append(",").append(quote(caller.getName())).append("],");
                        flow.append("\"severity\":").append(quote(scoreSeverity(sources, callerSinks)));
                        flow.append("}");
                        flows.add(flow.toString());
                        flowCount++;
                    }
                }
            }
        }

        decomp.dispose();

        // Build output
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"source_functions_analyzed\":").append(sourceFunctions.size()).append(",");
        json.append("\"total_flows\":").append(flows.size()).append(",");
        json.append("\"flows\":[");
        for (int i = 0; i < flows.size(); i++) {
            if (i > 0) json.append(",");
            json.append(flows.get(i));
        }
        json.append("]}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String scoreSeverity(List<String> sources, List<String> sinks) {
        // Remote source + memory sink = critical
        boolean remoteSource = false;
        for (String s : sources) {
            if (s.contains("recv") || s.contains("read") || s.contains("mach_msg")
                || s.contains("xpc_") || s.contains("http") || s.contains("xml")
                || s.contains("Image") || s.contains("Unarchiver")) {
                remoteSource = true;
                break;
            }
        }
        boolean dangerousSink = false;
        for (String s : sinks) {
            if (s.equals("memcpy") || s.equals("strcpy") || s.equals("sprintf")
                || s.equals("system") || s.equals("execve") || s.equals("malloc")) {
                dangerousSink = true;
                break;
            }
        }
        if (remoteSource && dangerousSink) return "critical";
        if (remoteSource || dangerousSink) return "high";
        return "medium";
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
