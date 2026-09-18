import defpackage.CZRR4ZREoGNpLeGZze;
import java.nio.file.*;
public class Test6Full {
    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(json);
        while (m.find()) {
            String k = m.group(1);
            String exp = m.group(2);
            if (exp==null) continue;
            // Only check the 6 mismatched
            if (!k.equals("-17516911999494") && !k.equals("-16962861218310") && !k.equals("-16030853315078") && !k.equals("-15987903642118") && !k.equals("-12917002025478") && !k.equals("-1629827971590")) continue;
            long seed = Long.parseLong(k);
            String got = CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(seed);
            System.out.println(k + " exp len " + exp.length() + " got len " + got.length() + " equal " + exp.equals(got));
            System.out.println("  exp " + exp.substring(0, Math.min(50, exp.length())));
            System.out.println("  got " + got.substring(0, Math.min(50, got.length())));
            // Also check full equality via files
            Files.writeString(Path.of("tmp_"+k+".txt"), "exp: "+exp+"\ngot: "+got);
        }
    }
}
