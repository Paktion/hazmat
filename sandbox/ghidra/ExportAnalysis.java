// Export Ghidra's view of a program as one JSON file: program info, imports,
// functions (with callees and decompiled C) and defined strings.
//
// analyzeHeadless /tmp proj -import sample.bin -scriptPath /opt/hazmat/ghidra \
//     -postScript ExportAnalysis.java /work/ghidra.json [maxFunctions] -deleteProject
//
// @category Hazmat

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class ExportAnalysis extends GhidraScript {

    private static final int MAX_DECOMPILED_CHARS = 20_000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/work/ghidra.json";
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 200;

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"program\":{");
        field(sb, "name", currentProgram.getName()).append(",");
        field(sb, "format", currentProgram.getExecutableFormat()).append(",");
        field(sb, "language", currentProgram.getLanguageID().toString()).append(",");
        field(sb, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString()).append(",");
        field(sb, "image_base", currentProgram.getImageBase().toString()).append(",");
        field(sb, "sha256", currentProgram.getExecutableSHA256());
        sb.append("},");

        // Imports (external symbols)
        sb.append("\"imports\":[");
        boolean first = true;
        for (Symbol s : currentProgram.getSymbolTable().getExternalSymbols()) {
            if (s.getSymbolType() != SymbolType.FUNCTION && s.getSymbolType() != SymbolType.LABEL) {
                continue;
            }
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            field(sb, "name", s.getName()).append(",");
            field(sb, "library", s.getParentNamespace().getName());
            sb.append("}");
        }
        sb.append("],");

        // Functions, non-external, with callees and decompiled C
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        sb.append("\"functions\":[");
        first = true;
        int count = 0;
        int total = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            total++;
            if (count >= maxFunctions || monitor.isCancelled()) continue;
            count++;
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            field(sb, "name", f.getName()).append(",");
            field(sb, "entry", f.getEntryPoint().toString()).append(",");
            sb.append("\"size\":").append(f.getBody().getNumAddresses()).append(",");
            List<String> callees = new ArrayList<>();
            for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getName());
            sb.append("\"callees\":[");
            for (int i = 0; i < callees.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(quote(callees.get(i)));
            }
            sb.append("],");
            String c = "";
            DecompileResults r = decomp.decompileFunction(f, 30, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                c = r.getDecompiledFunction().getC();
                if (c.length() > MAX_DECOMPILED_CHARS) c = c.substring(0, MAX_DECOMPILED_CHARS);
            }
            field(sb, "decompiled", c);
            sb.append("}");
        }
        sb.append("],");
        sb.append("\"function_count\":").append(total).append(",");
        decomp.dispose();

        // Defined strings
        sb.append("\"strings\":[");
        first = true;
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (!d.hasStringValue()) continue;
            Object v = d.getValue();
            if (v == null) continue;
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            field(sb, "address", d.getAddress().toString()).append(",");
            field(sb, "value", v.toString());
            sb.append("}");
        }
        sb.append("]");
        sb.append("}");

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(sb.toString());
        }
        println("Hazmat export written to " + outPath + " (" + count + "/" + total + " functions)");
    }

    private static StringBuilder field(StringBuilder sb, String key, String value) {
        return sb.append(quote(key)).append(":").append(quote(value == null ? "" : value));
    }

    private static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20 || ch > 0x7e) out.append(String.format("\\u%04x", (int) ch));
                    else out.append(ch);
            }
        }
        return out.append("\"").toString();
    }
}
