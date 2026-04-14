// List all functions with size and complexity metrics.
// Usage: analyzeHeadless ... -postScript ListFunctions.java <sort_by> <min_size> <max_results> [filter_regex]
// @category CatByte

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import java.util.*;
import java.util.regex.*;

public class ListFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String sortBy = args.length > 0 ? args[0] : "size";
        int minSize = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        int maxResults = args.length > 2 ? Integer.parseInt(args[2]) : 50;
        String filter = args.length > 3 ? args[3] : null;
        Pattern filterPat = filter != null ? Pattern.compile(filter, Pattern.CASE_INSENSITIVE) : null;

        FunctionManager fm = currentProgram.getFunctionManager();
        List<Map<String, Object>> funcList = new ArrayList<>();

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            long size = f.getBody().getNumAddresses();
            if (size < minSize) continue;
            if (filterPat != null && !filterPat.matcher(f.getName()).find()) continue;

            Map<String, Object> info = new HashMap<>();
            info.put("name", f.getName());
            info.put("address", f.getEntryPoint().toString());
            info.put("size", size);
            info.put("param_count", f.getParameterCount());

            // Estimate cyclomatic complexity from basic blocks
            try {
                BasicBlockModel bbm = new BasicBlockModel(currentProgram);
                CodeBlockIterator blocks = bbm.getCodeBlocksContaining(f.getBody(), monitor);
                int blockCount = 0;
                int edgeCount = 0;
                while (blocks.hasNext()) {
                    CodeBlock block = blocks.next();
                    blockCount++;
                    CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                    while (dests.hasNext()) {
                        dests.next();
                        edgeCount++;
                    }
                }
                // CC = E - N + 2
                int complexity = edgeCount - blockCount + 2;
                info.put("complexity", Math.max(complexity, 1));
                info.put("block_count", blockCount);
            } catch (Exception e) {
                info.put("complexity", 1);
                info.put("block_count", 0);
            }

            // Check if it calls dangerous functions
            boolean callsDangerous = false;
            Set<Function> callees = f.getCalledFunctions(monitor);
            for (Function callee : callees) {
                String cn = callee.getName().toLowerCase();
                if (cn.contains("strcpy") || cn.contains("sprintf") || cn.contains("gets")
                    || cn.contains("strcat") || cn.contains("memcpy") || cn.contains("system")) {
                    callsDangerous = true;
                    break;
                }
            }
            info.put("calls_dangerous", callsDangerous);
            info.put("callees_count", callees.size());

            funcList.add(info);
        }

        // Sort
        Comparator<Map<String, Object>> cmp;
        switch (sortBy) {
            case "complexity":
                cmp = (a, b) -> ((Integer)b.get("complexity")).compareTo((Integer)a.get("complexity"));
                break;
            case "name":
                cmp = (a, b) -> ((String)a.get("name")).compareTo((String)b.get("name"));
                break;
            case "address":
                cmp = (a, b) -> ((String)a.get("address")).compareTo((String)b.get("address"));
                break;
            default: // size
                cmp = (a, b) -> Long.compare((Long)b.get("size"), (Long)a.get("size"));
        }
        funcList.sort(cmp);

        // Build JSON
        StringBuilder json = new StringBuilder();
        json.append("{\"total_functions\":").append(funcList.size()).append(",");
        json.append("\"functions\":[");
        int shown = Math.min(funcList.size(), maxResults);
        for (int i = 0; i < shown; i++) {
            if (i > 0) json.append(",");
            Map<String, Object> f = funcList.get(i);
            json.append("{");
            json.append("\"name\":").append(quote((String)f.get("name"))).append(",");
            json.append("\"address\":").append(quote((String)f.get("address"))).append(",");
            json.append("\"size\":").append(f.get("size")).append(",");
            json.append("\"complexity\":").append(f.get("complexity")).append(",");
            json.append("\"block_count\":").append(f.get("block_count")).append(",");
            json.append("\"param_count\":").append(f.get("param_count")).append(",");
            json.append("\"callees_count\":").append(f.get("callees_count")).append(",");
            json.append("\"calls_dangerous\":").append(f.get("calls_dangerous"));
            json.append("}");
        }
        json.append("]}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r")
                       .replace("\t", "\\t") + "\"";
    }
}
