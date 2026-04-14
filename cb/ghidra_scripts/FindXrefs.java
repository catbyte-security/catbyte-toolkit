// Find cross-references to/from a function.
// Usage: analyzeHeadless ... -postScript FindXrefs.java <func_name_or_addr> <direction:to|from|both> <depth>
// @category CatByte

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindXrefs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printError("Usage: FindXrefs <function> <direction> <depth>");
            return;
        }

        String target = args[0];
        String direction = args.length > 1 ? args[1] : "both";
        int depth = args.length > 2 ? Integer.parseInt(args[2]) : 1;

        Function func = resolveFunction(target);
        if (func == null) {
            printError("Function not found: " + target);
            return;
        }

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"function\":").append(quote(func.getName())).append(",");
        json.append("\"address\":").append(quote(func.getEntryPoint().toString())).append(",");

        // Callers (xrefs TO this function)
        if (direction.equals("to") || direction.equals("both")) {
            json.append("\"callers\":");
            Set<String> visited = new HashSet<>();
            json.append(buildCallTree(func, true, depth, visited, 0));
            json.append(",");
        }

        // Callees (xrefs FROM this function)
        if (direction.equals("from") || direction.equals("both")) {
            json.append("\"callees\":");
            Set<String> visited = new HashSet<>();
            json.append(buildCallTree(func, false, depth, visited, 0));
            json.append(",");
        }

        // Data references to function entry
        json.append("\"data_refs\":[");
        ReferenceIterator refs = currentProgram.getReferenceManager()
            .getReferencesTo(func.getEntryPoint());
        int refCount = 0;
        while (refs.hasNext() && refCount < 50) {
            Reference ref = refs.next();
            if (refCount > 0) json.append(",");
            json.append("{\"from\":").append(quote(ref.getFromAddress().toString()));
            json.append(",\"type\":").append(quote(ref.getReferenceType().getName()));
            // Try to find containing function
            Function containing = getFunctionContaining(ref.getFromAddress());
            if (containing != null) {
                json.append(",\"from_function\":").append(quote(containing.getName()));
            }
            json.append("}");
            refCount++;
        }
        json.append("]");

        json.append("}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String buildCallTree(Function func, boolean callers, int maxDepth,
                                  Set<String> visited, int currentDepth) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("[");

        if (currentDepth >= maxDepth || visited.contains(func.getName())) {
            sb.append("]");
            return sb.toString();
        }
        visited.add(func.getName());

        Set<Function> related = callers ?
            func.getCallingFunctions(monitor) :
            func.getCalledFunctions(monitor);

        int i = 0;
        for (Function f : related) {
            if (i > 0) sb.append(",");
            sb.append("{\"name\":").append(quote(f.getName()));
            sb.append(",\"address\":").append(quote(f.getEntryPoint().toString()));
            sb.append(",\"size\":").append(f.getBody().getNumAddresses());

            if (currentDepth + 1 < maxDepth) {
                String childKey = callers ? "callers" : "callees";
                sb.append(",\"").append(childKey).append("\":");
                sb.append(buildCallTree(f, callers, maxDepth, visited, currentDepth + 1));
            }

            sb.append("}");
            i++;
            if (i >= 30) break; // Limit per level
        }

        sb.append("]");
        return sb.toString();
    }

    private Function resolveFunction(String target) {
        if (target.startsWith("0x") || target.startsWith("0X")) {
            try {
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(target);
                return getFunctionAt(addr);
            } catch (Exception e) {
                return null;
            }
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(target) || f.getName().contains(target)) {
                return f;
            }
        }
        return null;
    }

    private void printError(String msg) {
        println("###CB_JSON_START###");
        println("{\"error\":" + quote(msg) + "}");
        println("###CB_JSON_END###");
    }

    private String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
