import defpackage.VjAcb76OojLigvhwYH;
public class TestDebug2 {
    public static void main(String[] args) throws Exception {
        long t2 = 0xFFFFFFFFFFFE3B6L; // as printed
        long v = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
        System.out.println("VjAc.NkWa(FFFE3B6) = " + Long.toHexString(v & 0xFFFFFFFFFFFFFFFFL) + " high " + Long.toHexString((v>>>32)&0xFFFF));
        // Also try with t2 as 0xFFFE3B6 unsigned
        long t2u = 0xFFFE3B6L;
        long v2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2u);
        System.out.println("VjAc.NkWa(FFFE3B6 unsigned) = " + Long.toHexString(v2 & 0xFFFFFFFFFFFFFFFFL));
        // Try with t2 as signed 32 0xFFFE3B6 = -117194
        long t2s = (long)(int)0xFFFE3B6;
        System.out.println("t2s " + Long.toHexString(t2s & 0xFFFFFFFFFFFFFFFFL));
        long v3 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2s);
        System.out.println("VjAc.NkWa(t2s) = " + Long.toHexString(v3 & 0xFFFFFFFFFFFFFFFFL));
    }
}
