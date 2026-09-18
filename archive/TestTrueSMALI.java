import defpackage.CZRR4ZREoGNpLeGZze;
import defpackage.FtpOxqekIibXASlT37;
import defpackage.VjAcb76OojLigvhwYH;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.regex.*;

/**
 * Replays FtpOxqekIibXASlT37.OhM1VWC9IUcLWN7TO0 exactly as the REAL smali does:
 * charAt uses literal 0x1fff, array index NOT wrapped by %strArr.length, and the
 * pool is EXACTLY the real single-element 4320-char string. OOB == real crash.
 */
public class TestTrueSMALI {

    static final String[] ARR = { loadPool() };
    static int poolLen;
    static int maxI;
    static int maxCharIdx;
    static boolean overPool;
    static boolean overArr;

    static String loadPool() {
        try {
            var s = Files.readString(Path.of("cjk_pool_true.txt"), StandardCharsets.UTF_8);
            poolLen = s.length();
            return s;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    // Exact port of FtpOxqekIibXASlT37.smali NkWaRdJEKEf58YYznc(I[Ljava/lang/String;J)J
    static long step(int i, long j) {
        long j2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(j);
        int v0 = i / 0x1fff;
        maxI = Math.max(maxI, i);
        if (v0 >= ARR.length || v0 < 0) overArr = true;
        String idx = ARR[v0];
        int ch = i % 0x1fff;
        maxCharIdx = Math.max(maxCharIdx, ch);
        if (ch >= poolLen || ch < 0) overPool = true;
        char c = idx.charAt(ch);
        return (((long) c) << 32) ^ j2;
    }

    static String decode(long j) throws Exception {
        long a = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(0xffffffffL & j));
        long j2 = (a >>> 32) & 65535;
        long b = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(a);
        int i = (int) (((j >>> 32) ^ j2) ^ ((b >>> 16) & (-65536)));
        long e = step(i, b);
        int len = (int) ((e >>> 32) & 65535);
        char[] cArr = new char[len];
        for (int k = 0; k < len; k++) {
            e = step(i + k + 1, e);
            cArr[k] = (char) ((e >>> 32) & 65535);
        }
        return new String(cArr);
    }

    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"), StandardCharsets.UTF_8);
        Pattern p = Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        Matcher m = p.matcher(json);
        int matches = 0, mism = 0, crash = 0;
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String v = m.group(2);
            if (v.equals("null")) continue;
            long s = Long.parseLong(m.group(1));
            String exp = m.group(3);
            try {
                String g = decode(s);
                if (g.equals(exp)) matches++;
                else {
                    mism++;
                    if (out.length() < 8000)
                        out.append(s + " exp [" + exp + "] got [" + g.substring(0, Math.min(25, g.length())) + "] (len " + g.length() + ")\n");
                }
            } catch (Exception ex) {
                crash++;
                if (out.length() < 8000) out.append(s + " CRASH: " + ex.getClass().getSimpleName() + " (exp [" + exp + "])\n");
            }
        }
        System.out.println("Matches " + matches + " Mism " + mism + " Crash " + crash);
        System.out.println("maxI=" + maxI + " maxCharIdx=" + maxCharIdx + " anyOverPool=" + overPool + " anyOverArr=" + overArr + " poolLen=" + poolLen);
        Files.writeString(Path.of("test_true_smali_result.txt"), out.toString());
    }
}