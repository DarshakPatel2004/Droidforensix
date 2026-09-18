import defpackage.VjAcb76OojLigvhwYH;
public class BruteVjAc2 {
    public static void main(String[] args) {
        int target = 0x4FB5;
        for (long t2=0; t2 < 0x100000000L; t2+=10000) {
            long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int high = (int)((v>>>32)&0xFFFF);
            if (high == target) {
                System.out.println("found t2 " + Long.toHexString(t2) + " high " + Integer.toHexString(high));
                break;
            }
        }
        System.out.println("done");
    }
}
