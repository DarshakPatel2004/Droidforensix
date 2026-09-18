import defpackage.VjAcb76OojLigvhwYH;
public class TestDebug4 {
    public static void main(String[] args) throws Exception {
        long seed = -17516911999494L;
        long low = seed & 0xFFFFFFFFL;
        long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
        System.out.println("low " + Long.toHexString(low) + " t0 " + Long.toHexString(t0));
        long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
        System.out.println("t1 " + Long.toHexString(t1));
        long j2 = (t1 >>>32) &0xFFFF;
        long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
        System.out.println("t2 " + Long.toHexString(t2) + " j2 " + Long.toHexString(j2));
        long tmp = (t2 >>>16) &0xFFFF0000L;
        long seed_high = seed >>>32;
        long combined = seed_high ^ j2 ^ tmp;
        System.out.println("seed_high " + Long.toHexString(seed_high) + " tmp " + Long.toHexString(tmp) + " combined " + Long.toHexString(combined) + " int " + (int)combined);
    }
}
