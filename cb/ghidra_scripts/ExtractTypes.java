// Extract type/struct definitions from the program.
// Usage: analyzeHeadless ... -postScript ExtractTypes.java <max_results> [filter_regex]
// @category CatByte

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;
import java.util.regex.*;

public class ExtractTypes extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int maxResults = args.length > 0 ? Integer.parseInt(args[0]) : 50;
        String filter = args.length > 1 ? args[1] : null;
        Pattern filterPat = filter != null ?
            Pattern.compile(filter, Pattern.CASE_INSENSITIVE) : null;

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        List<String> types = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();

        while (iter.hasNext() && types.size() < maxResults) {
            DataType dt = iter.next();
            String name = dt.getName();

            if (filterPat != null && !filterPat.matcher(name).find()) continue;

            // Skip built-in primitive types
            if (dt instanceof BuiltInDataType) continue;

            StringBuilder entry = new StringBuilder();
            entry.append("{");
            entry.append("\"name\":").append(quote(name)).append(",");
            entry.append("\"category\":").append(quote(dt.getCategoryPath().toString())).append(",");
            entry.append("\"size\":").append(dt.getLength()).append(",");
            entry.append("\"kind\":").append(quote(getKind(dt))).append(",");

            if (dt instanceof Structure) {
                Structure st = (Structure) dt;
                entry.append("\"fields\":[");
                DataTypeComponent[] comps = st.getDefinedComponents();
                for (int i = 0; i < comps.length && i < 50; i++) {
                    if (i > 0) entry.append(",");
                    DataTypeComponent c = comps[i];
                    entry.append("{\"name\":").append(quote(c.getFieldName()));
                    entry.append(",\"type\":").append(quote(c.getDataType().getName()));
                    entry.append(",\"offset\":").append(c.getOffset());
                    entry.append(",\"size\":").append(c.getLength());
                    entry.append("}");
                }
                entry.append("],");
                entry.append("\"field_count\":").append(comps.length);
            } else if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
                entry.append("\"values\":[");
                String[] names = en.getNames();
                for (int i = 0; i < names.length && i < 30; i++) {
                    if (i > 0) entry.append(",");
                    entry.append("{\"name\":").append(quote(names[i]));
                    entry.append(",\"value\":").append(en.getValue(names[i]));
                    entry.append("}");
                }
                entry.append("],");
                entry.append("\"value_count\":").append(names.length);
            } else if (dt instanceof TypeDef) {
                TypeDef td = (TypeDef) dt;
                entry.append("\"base_type\":").append(quote(td.getBaseDataType().getName()));
            } else if (dt instanceof FunctionDefinition) {
                FunctionDefinition fd = (FunctionDefinition) dt;
                entry.append("\"return_type\":").append(quote(fd.getReturnType().getName())).append(",");
                entry.append("\"parameters\":[");
                ParameterDefinition[] params = fd.getArguments();
                for (int i = 0; i < params.length; i++) {
                    if (i > 0) entry.append(",");
                    entry.append("{\"name\":").append(quote(params[i].getName()));
                    entry.append(",\"type\":").append(quote(params[i].getDataType().getName()));
                    entry.append("}");
                }
                entry.append("]");
            }

            entry.append("}");
            types.add(entry.toString());
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"total_types\":").append(types.size()).append(",");
        json.append("\"types\":[");
        for (int i = 0; i < types.size(); i++) {
            if (i > 0) json.append(",");
            json.append(types.get(i));
        }
        json.append("]}");

        println("###CB_JSON_START###");
        println(json.toString());
        println("###CB_JSON_END###");
    }

    private String getKind(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof FunctionDefinition) return "function_type";
        if (dt instanceof Pointer) return "pointer";
        if (dt instanceof Array) return "array";
        return "other";
    }

    private String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
