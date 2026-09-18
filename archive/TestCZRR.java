import defpackage.CZRR4ZREoGNpLeGZze;
import java.nio.file.*;
public class TestCZRR {
    public static void main(String[] args) throws Exception {
        long seed = -9154610674182L;
        String result = CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(seed);
        System.out.println("Result len " + result.length());
        Files.writeString(Path.of("test_czrr_out.txt"), result);
        System.out.println("Result: " + result.substring(0, Math.min(30, result.length())));
        // Test all
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher m = p.matcher(json);
        int matches=0, mism=0;
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            String exp = null;
            if (!v.equals("null")) exp = m.group(3);
            else continue;
            long s = Long.parseLong(k);
            String g = CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(s);
            if (g.equals(exp)) matches++;
            else {
                mism++;
                if (out.length() < 5000) out.append(k + " exp " + exp + " got len " + g.length() + " got " + (g.length()>20?g.substring(0,20):g) + "\n");
            }
        }
        System.out.println("Matches " + matches + " Mism " + mism);
        Files.writeString(Path.of("test_czrr_result.txt"), out.toString() + "\nMatches " + matches + " Mism " + mism);
    }
}
