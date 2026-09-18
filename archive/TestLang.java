import defpackage.VjAcb76OojLigvhwYH;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.regex.*;

/** Same smali-exact port as TestTrueSMALI, but prints LanguageManager pairs. */
public class TestLang {

    static final String[] ARR = { loadPool() };
    static int poolLen;

    static String loadPool() {
        try {
            var s = Files.readString(Path.of("cjk_pool_true.txt"), StandardCharsets.UTF_8);
            poolLen = s.length();
            return s;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static long step(int i, long j) {
        long j2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(j);
        int v0 = i / 0x1fff;
        int ch = i % 0x1fff;
        char c = ARR[v0].charAt(ch);
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
        long[][] dflt = {
            {-11830375299590L, -11937749481990L}, {-12105253206534L, -12178267650566L},
            {-12251282094598L, -12320001571334L}, {-12517570066950L, -12556224772614L},
            {-12594879478278L, -12637829151238L}, {-12685073791494L, -12736613399046L},
            {-12852577516038L, -12917002025478L}, {-13471052806662L, -13514002479622L},
            {-13694391106054L, -13780290451974L}, {-13956384111110L, -13999333784070L},
            {-14042283457030L, -14072348228102L}, {-14102412999174L, -14184017377798L},
            {-14265621756422L, -14390175808006L}, {-14811082603014L, -14858327243270L},
        };
        long[][] es = {
            {-15043010836998L, -15150385019398L}, {-15369428351494L, -15442442795526L},
            {-15549816977926L, -15618536454662L}, {-15880529459718L, -15919184165382L},
            {-15944953969158L, -15987903642118L}, {-16030853315078L, -16082392922630L},
            {-16258486581766L, -16322911091206L}, {-16919911545350L, -16962861218310L},
            {-17177609583110L, -17263508929030L}, {-17473962326534L, -17516911999494L},
            {-17585631476230L, -17615696247302L}, {-17662940887558L, -17744545266182L},
            {-17843329513990L, -17967883565574L}, {-18461804804614L, -18509049444870L},
        };
        java.io.PrintStream out = new java.io.PrintStream(new java.io.FileOutputStream("test_lang_result.txt"), true, StandardCharsets.UTF_8);
        for (long[] pr : dflt) {
            out.printf("DF key %20d = %-34s | val %20d = %s%n", pr[0], decode(pr[0]), pr[1], decode(pr[1]));
        }
        for (long[] pr : es) {
            out.printf("ES key %20d = %-34s | val %20d = %s%n", pr[0], decode(pr[0]), pr[1], decode(pr[1]));
        }
        out.println("\nMismatch seed 3rd slot in GT: -1629827971590 -> " + decode(-1629827971590L));
        out.close();
        System.out.println("done len=" + poolLen);
    }
}