// Compare functions between two program versions (used via external diffing).
// This script exports function hashes for comparison.
// Usage: analyzeHeadless ... -postScript DiffFunctions.java <max_results>
// @category CatByte

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.security.MessageDigest;
import java.util.*;

public class DiffFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int maxResults = args.length > 0 ? Integer.parseInt(args[0]) : 5000;

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);
        Memory mem = currentProgram.getMemory();

        StringBuilder json = new StringBuilder();
        json.append("{\"program\":").append(quote(currentProgram.getName())).append(",");
        json.append("\"functions\":[");

        int count = 0;
        while (iter.hasNext() && count < maxResults && !monitor.isCancelled()) {
            Function f = iter.next();
            long size = f.getBody().getNumAddresses();

            if (count > 0) json.append(",");

            // Compute hash of function bytes
            String hash = "unknown";
            try {
                byte[] bytes = new byte[(int) Math.min(size, 65536)];
                mem.getBytes(f.getEntryPoint(), bytes);
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digest = md.digest(bytes);
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                hash = sb.toString();
            } catch (Exception e) {
                // Skip hash on failure
            }

            json.append("{\"name\":").append(quote(f.getName()));
            json.append(",\"address\":").append(quote(f.getEntryPoint().toString()));
            json.append(",\"size\":").append(size);
            json.append(",\"hash\":").append(quote(hash));
            json.append("}");

            count++;
        }

        json.append("],\"total\":").append(count).append("}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
