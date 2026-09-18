import defpackage.VjAcb76OojLigvhwYH;
public class TestDebug {
    public static void main(String[] args) throws Exception {
        String poolStr = java.nio.file.Files.readString(java.nio.file.Path.of("cjk_pool.txt")).trim().replace("\r","").replace("\n","");
        // The pool file may be 4321, but we need to handle reading correctly
        // Actually cjk_pool.txt is 4321, but we need to ensure we read correctly
        // The file was written with 4321 chars, no newline, so trim is fine
        // But our earlier reading gave 4320, now 4321, let's just read raw
        String[] pool = new String[]{poolStr};
        System.out.println("Pool len " + pool[0].length());
        long j = -9154610674182L;
        long low = j & 4294967295L;
        long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
        System.out.println("t0 " + Long.toHexString(t0 & 0xFFFFFFFFFFFFFFFFL));
        long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
        System.out.println("t1 " + Long.toHexString(t1 & 0xFFFFFFFFFFFFFFFFL));
        long j2 = (t1 >>> 32) & 65535;
        System.out.println("j2 " + Long.toHexString(j2));
        long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
        System.out.println("t2 " + Long.toHexString(t2 & 0xFFFFFFFFFFFFFFFFL));
        long tmp = (t2 >>> 16) & 0xFFFF0000L;
        System.out.println("tmp " + Long.toHexString(tmp));
        long seed_high = j >>> 32;
        System.out.println("seed_high " + Long.toHexString(seed_high & 0xFFFFFFFFL));
        long combined = seed_high ^ j2 ^ tmp;
        System.out.println("combined " + Long.toHexString(combined & 0xFFFFFFFFFFFFFFFFL) + " as int " + (int)combined);
        int i = (int) combined;
        System.out.println("i " + i);
        long state3 = defpackage.FtpOxqekIibXASlT37.NkWaRdJEKEf58YYznc(i, pool, t2);
        System.out.println("state3 " + Long.toHexString(state3 & 0xFFFFFFFFFFFFFFFFL));
        int len = (int)((state3 >>>32) & 65535);
        System.out.println("len " + len);
        // Also try with pool as in CZRR
        String[] czrrPool = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc;
        System.out.println("CZRR pool len " + czrrPool[0].length());
        String[] pool2 = czrrPool;
        long state3b = defpackage.FtpOxqekIibXASlT37.NkWaRdJEKEf58YYznc(i, pool2, t2);
        System.out.println("state3b " + Long.toHexString(state3b & 0xFFFFFFFFFFFFFFFFL) + " len " + ((state3b>>>32)&65535));
        // Try calling CZRR directly
        String res = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc(j);
        System.out.println("CZRR result len " + res.length() + " result " + res);
        java.nio.file.Files.writeString(java.nio.file.Path.of("debug_out.txt"), "t0 "+Long.toHexString(t0)+" t1 "+Long.toHexString(t1)+" t2 "+Long.toHexString(t2)+" combined "+i+" len "+len);
    }
}
