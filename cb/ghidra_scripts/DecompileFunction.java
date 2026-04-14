// Decompile a single function and output JSON with callers/callees.
// Usage: analyzeHeadless ... -postScript DecompileFunction.java <func_name_or_0xAddr> [--assembly]
// @category CatByte

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printError("Usage: DecompileFunction <function_name_or_0xAddress> [--assembly]");
            return;
        }

        String target = args[0];
        boolean includeAssembly = args.length > 1 && args[1].equals("--assembly");

        Function func = resolveFunction(target);
        if (func == null) {
            printError("Function not found: " + target);
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        DecompileResults results = decomp.decompileFunction(func, 60, monitor);

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"function_name\":").append(quote(func.getName())).append(",");
        json.append("\"address\":").append(quote(func.getEntryPoint().toString())).append(",");
        json.append("\"size\":").append(func.getBody().getNumAddresses()).append(",");
        json.append("\"signature\":").append(quote(func.getSignature().getPrototypeString())).append(",");

        // Decompiled C code
        if (results.getDecompiledFunction() != null) {
            String cCode = results.getDecompiledFunction().getC();
            json.append("\"decompiled_c\":").append(quote(cCode)).append(",");
        } else {
            json.append("\"decompiled_c\":\"decompilation failed\",");
        }

        // Assembly listing
        if (includeAssembly) {
            StringBuilder asm = new StringBuilder();
            Listing listing = currentProgram.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);
            int count = 0;
            while (iter.hasNext() && count < 500) {
                Instruction insn = iter.next();
                asm.append(insn.getAddress().toString()).append(": ");
                asm.append(insn.toString()).append("\\n");
                count++;
            }
            json.append("\"assembly\":").append(quote(asm.toString())).append(",");
        }

        // Callers
        json.append("\"callers\":[");
        Set<Function> callers = func.getCallingFunctions(monitor);
        int i = 0;
        for (Function caller : callers) {
            if (i > 0) json.append(",");
            json.append("{\"name\":").append(quote(caller.getName()));
            json.append(",\"address\":").append(quote(caller.getEntryPoint().toString()));
            json.append("}");
            i++;
            if (i >= 50) break;
        }
        json.append("],");

        // Callees
        json.append("\"callees\":[");
        Set<Function> callees = func.getCalledFunctions(monitor);
        i = 0;
        for (Function callee : callees) {
            if (i > 0) json.append(",");
            json.append("{\"name\":").append(quote(callee.getName()));
            json.append(",\"address\":").append(quote(callee.getEntryPoint().toString()));
            json.append("}");
            i++;
            if (i >= 50) break;
        }
        json.append("],");

        // Parameters
        json.append("\"parameters\":[");
        Parameter[] params = func.getParameters();
        for (int p = 0; p < params.length; p++) {
            if (p > 0) json.append(",");
            json.append("{\"name\":").append(quote(params[p].getName()));
            json.append(",\"type\":").append(quote(params[p].getDataType().getName()));
            json.append("}");
        }
        json.append("],");

        json.append("\"callers_count\":").append(callers.size()).append(",");
        json.append("\"callees_count\":").append(callees.size());

        json.append("}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private Function resolveFunction(String target) {
        if (target.startsWith("0x") || target.startsWith("0X")) {
            try {
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(target);
                return getFunctionAt(addr);
            } catch (Exception e) {
                return null;
            }
        }
        // Search by name
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
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r")
                       .replace("\t", "\\t") + "\"";
    }
}
