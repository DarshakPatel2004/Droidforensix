import defpackage.VjAcb76OojLigvhwYH;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.regex.*;

public class TestTwo {
    static final String[] ARR = { loadPool() };
    static String loadPool() {
        try { return Files.readString(Path.of("cjk_pool_true.txt"), StandardCharsets.UTF_8); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static long step(int i, long j) {
        long j2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(j);
        return (((long) ARR[i / 0x1fff].charAt(i % 0x1fff)) << 32) ^ j2;
    }
    static String decode(long j) throws Exception {
        long a = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(0xffffffffL & j));
        long j2 = (a >>> 32) & 65535;
        long b = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(a);
        int i = (int) (((j >>> 32) ^ j2) ^ ((b >>> 16) & (-65536)));
        long e = step(i, b);
        int len = (int) ((e >>> 32) & 65535);
        char[] c = new char[len];
        for (int k = 0; k < len; k++) { e = step(i + k + 1, e); c[k] = (char) ((e >>> 32) & 65535); }
        return new String(c);
    }
    static String loadGT() throws Exception {
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"), StandardCharsets.UTF_8);
        Pattern p = Pattern.compile("\"(-12917002025478)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(json);
        if (m.find()) {
            String raw = m.group(2);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < raw.length(); i++) {
                char ch = raw.charAt(i);
                if (ch == '\\' && i + 1 < raw.length()) {
                    char n = raw.charAt(i + 1);
                    sb.append(n); i++;
                } else sb.append(ch);
            }
            return sb.toString();
        }
        return null;
    }
    public static void main(String[] args) throws Exception {
        String dec = decode(-12917002025478L);
        String gt = loadGT();
        System.out.println("dec len=" + dec.length() + " gt len=" + (gt == null ? -1 : gt.length()));
        int n = Math.min(dec.length(), gt == null ? 0 : gt.length());
        int diff = 0;
        for (int i = 0; i < n; i++) if (dec.charAt(i) != gt.charAt(i)) { diff++; if (diff<=5) System.out.println(" diff@" + i + " dec=" + Integer.toHexString(dec.charAt(i)) + " gt=" + Integer.toHexString(gt.charAt(i))); }
        System.out.println("diff count in common=" + diff + " (dec longer=" + (dec.length()>n) + " gt longer=" + (gt!=null && gt.length()>n) + ")");
        System.out.println("dec[start]=" + dec.substring(0, Math.min(40, dec.length())));
        if (gt != null) System.out.println("gt [start]=" + gt.substring(0, Math.min(40, gt.length())));
        // parse the whole json to reduce false mismatches for \A
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"), StandardCharsets.UTF_8);
        Pattern pm = Pattern.compile("\"(-1629827971590)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher mm = pm.matcher(json);
        String gt2 = null;
        if (mm.find()) {
            StringBuilder sbd = new StringBuilder();
            String raw = mm.group(2);
            for (int i = 0; i < raw.length(); i++) {
                char ch = raw.charAt(i);
                if (ch == '\\' && i + 1 < raw.length()) { sbd.append(raw.charAt(i + 1)); i++; }
                else sbd.append(ch);
            }
            gt2 = sbd.toString();
        }
        System.out.println("\nseed -1629827971590: dec=[" + decode(-1629827971590L) + "] gt2=[" + gt2 + "] eq=" + gt2.equals(decode(-1629827971590L)));
    }
}