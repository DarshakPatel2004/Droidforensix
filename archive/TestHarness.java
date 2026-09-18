import defpackage.CZRR4ZREoGNpLeGZze;
public class TestHarness {
    public static void main(String[] args) throws Exception {
        long seed = -9154610674182L;
        String result = CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(seed);
        System.out.println("Result: " + result);
        System.out.println("Length: " + result.length());
        System.out.println("Expected: app_installation");
        // Also test all seeds from JSON
        String json = java.nio.file.Files.readString(java.nio.file.Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher m = p.matcher(json);
        int matches=0, mism=0, nulls=0;
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            String exp = null;
            if (!v.equals("null")) exp = m.group(3);
            else { nulls++; continue; }
            long s = Long.parseLong(k);
            String g = CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(s);
            if (g.equals(exp)) matches++;
            else mism++;
        }
        System.out.println("Matches " + matches + " Mism " + mism + " Nulls " + nulls);
    }
}
