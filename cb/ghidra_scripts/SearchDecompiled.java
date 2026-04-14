// Search decompiled code for regex patterns.
// Usage: analyzeHeadless ... -postScript SearchDecompiled.java <pattern> <max_results>
// @category CatByte

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;
import java.util.regex.*;

public class SearchDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printError("Usage: SearchDecompiled <regex_pattern> [max_results]");
            return;
        }

        String patternStr = args[0];
        int maxResults = args.length > 1 ? Integer.parseInt(args[1]) : 50;

        Pattern regex;
        try {
            regex = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        } catch (PatternSyntaxException e) {
            printError("Invalid regex: " + e.getMessage());
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);

        List<String> matches = new ArrayList<>();
        int totalSearched = 0;

        while (iter.hasNext() && matches.size() < maxResults && !monitor.isCancelled()) {
            Function func = iter.next();
            totalSearched++;

            // Skip very small functions (thunks etc)
            if (func.getBody().getNumAddresses() < 8) continue;

            try {
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                if (results.getDecompiledFunction() == null) continue;

                String code = results.getDecompiledFunction().getC();
                if (code == null) continue;

                Matcher m = regex.matcher(code);
                while (m.find() && matches.size() < maxResults) {
                    // Get context around match
                    int start = Math.max(0, m.start() - 50);
                    int end = Math.min(code.length(), m.end() + 50);
                    String snippet = code.substring(start, end).trim();

                    StringBuilder entry = new StringBuilder();
                    entry.append("{");
                    entry.append("\"function\":").append(quote(func.getName())).append(",");
                    entry.append("\"address\":").append(quote(func.getEntryPoint().toString())).append(",");
                    entry.append("\"match\":").append(quote(m.group())).append(",");
                    entry.append("\"snippet\":").append(quote(snippet)).append(",");
                    entry.append("\"match_offset\":").append(m.start());
                    entry.append("}");
                    matches.add(entry.toString());
                }
            } catch (Exception e) {
                // Skip functions that fail to decompile
                continue;
            }

            // Progress update every 100 functions
            if (totalSearched % 100 == 0) {
                monitor.setMessage("Searched " + totalSearched + " functions, " +
                                   matches.size() + " matches");
            }
        }

        decomp.dispose();

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"pattern\":").append(quote(patternStr)).append(",");
        json.append("\"functions_searched\":").append(totalSearched).append(",");
        json.append("\"total_matches\":").append(matches.size()).append(",");
        json.append("\"matches\":[");
        for (int i = 0; i < matches.size(); i++) {
            if (i > 0) json.append(",");
            json.append(matches.get(i));
        }
        json.append("]}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
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
