import defpackage.VjAcb76OojLigvhwYH;
public class BruteVjAc {
    public static void main(String[] args) {
        int targetHigh = 0x4FB5;
        // Try t2 values near 0xFFFE3B6
        long t2base = 0xFFFFFFFFFFFE3B6L;
        for (long delta=-100000; delta<100000; delta++) {
            long t2 = t2base + delta;
            long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int high = (int)((v>>>32)&0xFFFF);
            if (high == targetHigh) {
                System.out.println("found t2 " + Long.toHexString(t2) + " gives high " + Integer.toHexString(high));
                break;
            }
        }
        // Also try brute force low 32
        for (int i=0; i<1000000; i++) {
            long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(i);
            int high = (int)((v>>>32)&0xFFFF);
            if (high == targetHigh) {
                System.out.println("found low " + i + " high " + Integer.toHexString(high));
                break;
            }
        }
    }
}
