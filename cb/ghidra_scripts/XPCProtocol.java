// XPC Protocol Reverse Engineering Script for Ghidra
// Extracts XPC message dispatch tables, handler functions, and argument specs
// Usage: analyzeHeadless ... -postScript XPCProtocol.java [max_results]
//@category CatByte
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.util.regex.*;

public class XPCProtocol extends GhidraScript {

    private DecompInterface decomp;
    private int maxResults = 50;

    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length > 0) {
            try { maxResults = Integer.parseInt(scriptArgs[0]); }
            catch (NumberFormatException e) { /* use default */ }
        }

        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder json = new StringBuilder();
        json.append("{");

        // 1. Build XPC call map
        Map<String, List<String>> xpcCallMap = buildXPCCallMap();
        json.append("\"xpc_call_map\": {");
        int count = 0;
        for (Map.Entry<String, List<String>> entry : xpcCallMap.entrySet()) {
            if (count > 0) json.append(", ");
            json.append("\"").append(quote(entry.getKey())).append("\": [");
            for (int i = 0; i < entry.getValue().size() && i < 20; i++) {
                if (i > 0) json.append(", ");
                json.append("\"").append(quote(entry.getValue().get(i))).append("\"");
            }
            json.append("]");
            count++;
            if (count >= maxResults) break;
        }
        json.append("}, ");

        // 2. Find dispatch function
        String dispatchFunc = findDispatchFunction(xpcCallMap);
        json.append("\"dispatch_function\": \"").append(quote(dispatchFunc)).append("\", ");

        // 3. Extract message IDs from dispatch function
        List<Map<String, String>> messageIDs = new ArrayList<>();
        if (!dispatchFunc.isEmpty()) {
            messageIDs = extractMessageIDs(dispatchFunc);
        }
        json.append("\"message_ids\": [");
        for (int i = 0; i < messageIDs.size(); i++) {
            if (i > 0) json.append(", ");
            Map<String, String> mid = messageIDs.get(i);
            json.append("{\"id\": \"").append(quote(mid.getOrDefault("id", ""))).append("\", ");
            json.append("\"handler\": \"").append(quote(mid.getOrDefault("handler", ""))).append("\"}");
        }
        json.append("], ");

        // 4. Per-handler argument specs
        json.append("\"handler_specs\": [");
        int specCount = 0;
        Set<String> analyzedHandlers = new HashSet<>();
        for (Map<String, String> mid : messageIDs) {
            String handler = mid.getOrDefault("handler", "");
            if (handler.isEmpty() || analyzedHandlers.contains(handler)) continue;
            analyzedHandlers.add(handler);

            List<Map<String, String>> argSpec = extractHandlerArgs(handler);
            if (argSpec.isEmpty()) continue;

            if (specCount > 0) json.append(", ");
            json.append("{\"handler\": \"").append(quote(handler)).append("\", ");
            json.append("\"message_id\": \"").append(quote(mid.getOrDefault("id", ""))).append("\", ");
            json.append("\"args\": [");
            for (int j = 0; j < argSpec.size(); j++) {
                if (j > 0) json.append(", ");
                Map<String, String> arg = argSpec.get(j);
                json.append("{\"key\": \"").append(quote(arg.getOrDefault("key", ""))).append("\", ");
                json.append("\"type\": \"").append(quote(arg.getOrDefault("type", ""))).append("\"}");
            }
            json.append("]}");
            specCount++;
            if (specCount >= maxResults) break;
        }
        json.append("], ");

        // 5. NSXPCConnection protocol methods
        List<String> nsxpcMethods = findNSXPCProtocolMethods();
        json.append("\"nsxpc_protocol_methods\": [");
        for (int i = 0; i < nsxpcMethods.size(); i++) {
            if (i > 0) json.append(", ");
            json.append("\"").append(quote(nsxpcMethods.get(i))).append("\"");
        }
        json.append("]");

        json.append("}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private Map<String, List<String>> buildXPCCallMap() {
        Map<String, List<String>> callMap = new HashMap<>();
        String[] xpcGetters = {
            "xpc_dictionary_get_int64", "xpc_dictionary_get_uint64",
            "xpc_dictionary_get_string", "xpc_dictionary_get_data",
            "xpc_dictionary_get_bool", "xpc_dictionary_get_fd",
            "xpc_dictionary_get_value", "xpc_dictionary_get_array",
            "xpc_dictionary_get_dictionary"
        };

        SymbolTable symTable = currentProgram.getSymbolTable();
        for (String getter : xpcGetters) {
            SymbolIterator symbols = symTable.getSymbols(getter);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                Reference[] refs = getReferencesTo(sym.getAddress());
                for (Reference ref : refs) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        String callerName = caller.getName();
                        callMap.computeIfAbsent(callerName, k -> new ArrayList<>());
                        if (!callMap.get(callerName).contains(getter)) {
                            callMap.get(callerName).add(getter);
                        }
                    }
                }
            }
            // Also check for thunks with underscore prefix
            symbols = symTable.getSymbols("_" + getter);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                Reference[] refs = getReferencesTo(sym.getAddress());
                for (Reference ref : refs) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        String callerName = caller.getName();
                        callMap.computeIfAbsent(callerName, k -> new ArrayList<>());
                        if (!callMap.get(callerName).contains(getter)) {
                            callMap.get(callerName).add(getter);
                        }
                    }
                }
            }
        }
        return callMap;
    }

    private String findDispatchFunction(Map<String, List<String>> callMap) {
        // Dispatch function: calls xpc_dictionary_get_int64 and has high complexity
        String bestFunc = "";
        int bestScore = 0;

        for (Map.Entry<String, List<String>> entry : callMap.entrySet()) {
            String funcName = entry.getKey();
            List<String> calls = entry.getValue();

            boolean hasGetInt64 = calls.contains("xpc_dictionary_get_int64") ||
                                  calls.contains("xpc_dictionary_get_uint64");
            if (!hasGetInt64) continue;

            int score = calls.size(); // More XPC calls = more likely dispatch

            // Check function complexity (size as proxy)
            Function func = getFunction(funcName);
            if (func != null) {
                long size = func.getBody().getNumAddresses();
                if (size > 200) score += 10;
                if (size > 500) score += 10;
            }

            if (score > bestScore) {
                bestScore = score;
                bestFunc = funcName;
            }
        }
        return bestFunc;
    }

    private Function getFunction(String name) {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    private List<Map<String, String>> extractMessageIDs(String funcName) {
        List<Map<String, String>> ids = new ArrayList<>();
        Function func = getFunction(funcName);
        if (func == null) return ids;

        DecompileResults results = decomp.decompileFunction(func, 60, monitor);
        if (results == null || !results.decompileCompleted()) return ids;

        String code = results.getDecompiledFunction().getC();
        if (code == null) return ids;

        // Find case statements: case 0x1: or case 1:
        Pattern casePattern = Pattern.compile("case\\s+(0x[0-9a-fA-F]+|\\d+)\\s*:");
        Matcher m = casePattern.matcher(code);
        while (m.find()) {
            String msgId = m.group(1);
            // Try to find handler call after case
            int caseEnd = m.end();
            int nextCase = code.indexOf("case ", caseEnd);
            int breakPos = code.indexOf("break", caseEnd);
            int blockEnd = Math.min(
                nextCase > 0 ? nextCase : code.length(),
                breakPos > 0 ? breakPos : code.length()
            );
            String block = code.substring(caseEnd, Math.min(blockEnd, caseEnd + 500));

            // Find function calls in this case block
            Pattern callPat = Pattern.compile("(\\w+)\\s*\\(");
            Matcher cm = callPat.matcher(block);
            String handler = "";
            while (cm.find()) {
                String called = cm.group(1);
                if (!called.equals("break") && !called.equals("return") &&
                    !called.equals("if") && !called.equals("switch") &&
                    !called.startsWith("xpc_")) {
                    handler = called;
                    break;
                }
            }

            Map<String, String> entry = new HashMap<>();
            entry.put("id", msgId);
            entry.put("handler", handler);
            ids.add(entry);
        }

        // Also try == comparisons: if (msg_type == 0x5)
        Pattern eqPattern = Pattern.compile("==\\s*(0x[0-9a-fA-F]+|\\d+)");
        Matcher em = eqPattern.matcher(code);
        Set<String> seen = new HashSet<>();
        for (Map<String, String> id : ids) seen.add(id.get("id"));
        while (em.find()) {
            String msgId = em.group(1);
            if (seen.contains(msgId)) continue;
            seen.add(msgId);
            Map<String, String> entry = new HashMap<>();
            entry.put("id", msgId);
            entry.put("handler", "");
            ids.add(entry);
        }

        return ids;
    }

    private List<Map<String, String>> extractHandlerArgs(String funcName) {
        List<Map<String, String>> args = new ArrayList<>();
        Function func = getFunction(funcName);
        if (func == null) return args;

        DecompileResults results = decomp.decompileFunction(func, 60, monitor);
        if (results == null || !results.decompileCompleted()) return args;

        String code = results.getDecompiledFunction().getC();
        if (code == null) return args;

        // Find xpc_dictionary_get_* calls with key strings
        Pattern getterPat = Pattern.compile(
            "xpc_dictionary_get_(\\w+)\\s*\\([^,]+,\\s*\"([^\"]+)\"");
        Matcher m = getterPat.matcher(code);
        Set<String> seen = new HashSet<>();
        while (m.find()) {
            String type = m.group(1);
            String key = m.group(2);
            if (seen.contains(key)) continue;
            seen.add(key);

            Map<String, String> arg = new HashMap<>();
            arg.put("key", key);
            arg.put("type", mapXPCType(type));
            args.add(arg);
        }
        return args;
    }

    private String mapXPCType(String getter) {
        switch (getter) {
            case "int64": return "int64";
            case "uint64": return "uint64";
            case "string": return "string";
            case "data": return "data";
            case "bool": return "bool";
            case "fd": return "fd";
            case "value": return "any";
            case "array": return "array";
            case "dictionary": return "dictionary";
            default: return getter;
        }
    }

    private List<String> findNSXPCProtocolMethods() {
        List<String> methods = new ArrayList<>();
        // Search for NSXPCInterface initWithProtocol: calls
        SymbolTable symTable = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();

        // Look for ObjC selectors related to NSXPCInterface
        SymbolIterator allSyms = symTable.getAllSymbols(true);
        while (allSyms.hasNext()) {
            Symbol sym = allSyms.next();
            String name = sym.getName();
            if (name.contains("initWithProtocol") || name.contains("NSXPCInterface") ||
                name.contains("remoteObjectInterface") || name.contains("exportedInterface")) {
                methods.add(name);
                if (methods.size() >= maxResults) break;
            }
        }
        return methods;
    }

    private String quote(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
