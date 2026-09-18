import defpackage.VjAcb76OojLigvhwYH;
import defpackage.FtpOxqekIibXASlT37;
import java.nio.file.*;
public class TestDebug3 {
    public static void main(String[] args) throws Exception {
        String[] czrrPool = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc;
        System.out.println("CZRR pool len " + czrrPool[0].length());
        long[] seeds = {-17516911999494L, -16962861218310L, -16030853315078L, -15987903642118L, -12917002025478L, -1629827971590L};
        for (long seed : seeds) {
            long low = seed & 0xFFFFFFFFL;
            long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
            long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
            long j2 = (t1 >>>32) &0xFFFF;
            long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
            long tmp = (t2 >>>16) &0xFFFF0000L;
            long seed_high = seed >>>32;
            long combined = seed_high ^ j2 ^ tmp;
            int i = (int)combined;
            System.out.println("seed " + seed + " i " + i + " i%8191 " + (i%8191) + " pool len " + czrrPool[0].length() + " charAt " + (i%8191 < czrrPool[0].length() ? Integer.toHexString(czrrPool[0].charAt(i%8191)) : "OOB"));
            String res = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(seed);
            System.out.println("  result len " + res.length() + " " + res.substring(0, Math.min(20, res.length())));
        }
    }
}
