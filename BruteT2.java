import defpackage.VjAcb76OojLigvhwYH;
public class BruteT2 {
    public static void main(String[] args) {
        int targetHigh = 0x4FA5 ^ 16; // 0x4FB5? Actually for pool 0x4FB5, need high = pool ^16 = 0x4FA5
        // For pool 0x4FA5 (original), need high = 0x4FA5 ^16 =0x4FB5
        // For pool 0x4FB5 (patched), need high =0x4FB5 ^16=0x4FA5
        // Let's try both
        for (long t2=0; t2< 0x100000000L; t2+=100000) {
            long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int high = (int)((v>>>32)&0xFFFF);
            if (high == 0x4FA5 || high == 0x4FB5) {
                System.out.println("found t2 " + Long.toHexString(t2) + " high " + Integer.toHexString(high));
                break;
            }
        }
        // Also try t2 near 0xFFFE3B6
        long base = 0xFFFE3B6L;
        for (long delta=-1000000; delta<1000000; delta++) {
            long t2 = base + delta;
            long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int high = (int)((v>>>32)&0xFFFF);
            if (high == 0x4FA5) {
                System.out.println("found near base t2 " + Long.toHexString(t2) + " high " + Integer.toHexString(high));
                break;
            }
        }
    }
}
