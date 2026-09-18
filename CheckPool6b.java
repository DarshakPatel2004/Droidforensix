import defpackage.VjAcb76OojLigvhwYH;
public class CheckPool6b {
    public static void main(String[] args) throws Exception {
        String[] pool = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc;
        System.out.println("pool len "+pool[0].length());
        long[] seeds = {-17516911999494L, -16962861218310L, -16030853315078L, -15987903642118L, -12917002025478L, -1629827971590L};
        String[] exps = {"more_info","bug_fixes","Novedades","whats_new","We're always making changes \u0430\u0578\u0501 improvements t\u03bf this \u2a09\u9ce0\ud064\u64f0\u2a63\u9ca0\u4883\ub083\u4eee\ub6e0\u4f67\ub77c\u4ee0\ub6ad\u4ca2\ub4a8\u4ea5\ub6e0\u4cb0\ub4b6\u4eb2\ub6a5\u4ce3\ub080\u4d7f\ub6b5\u4ce3\ub4a7\u4eaf\ub6ae\u4ce4\ub4b7\u4ee0\ub6ad\u4caa\ub4b0\u4eb3\ub6e0\u4ca2\ub4e3\u4eb4\ub6a8\u4caa\ub4ad\u4ea7\ub6ec\u4ce3\ub4a9\u4eb5\ub6b3\u4cb7\ub4e3\u4eab\ub6a5\u4ca6\ub4b3\u4ee0\ub6b9\u4cac\ub4b6\u4eb2\ub6e0\u4c96\ub4b3\u4ea4\ub6a1\u4cb7\ub4a6\u4eb3\ub6e0\u4cb7\ub4b6\u4eb2\ub6ae\u4ca6","\\A"};
        for (int idx=0; idx<seeds.length; idx++) {
            long seed = seeds[idx];
            String exp = exps[idx];
            long low = seed & 0xFFFFFFFFL;
            long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
            long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
            long j2 = (t1 >>>32) &0xFFFF;
            long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
            long tmp = (t2 >>>16) &0xFFFF0000L;
            long seed_high = seed >>>32;
            long combined = seed_high ^ j2 ^ tmp;
            int i = (int)combined;
            int ci_len = i %8191; if (ci_len<0) ci_len+=8191;
            long ns_t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int req_len_char = exp.length() ^ (int)((ns_t2>>>32)&0xFFFF);
            char pool_c_len = pool[0].charAt(ci_len);
            System.out.println("seed "+seed+" i "+i+" exp len "+exp.length()+" req "+Integer.toHexString(req_len_char)+" pool "+Integer.toHexString(pool_c_len)+" match "+(pool_c_len==req_len_char));
            long state = (((long)req_len_char)<<32) ^ ns_t2;
            long ns2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(state);
            int ci2 = (i+1)%8191; if (ci2<0) ci2+=8191;
            char pool_c2 = pool[0].charAt(ci2);
            int req2 = exp.charAt(0) ^ (int)((ns2>>>32)&0xFFFF);
            System.out.println("  char0 ci "+ci2+" pool "+Integer.toHexString(pool_c2)+" req "+Integer.toHexString(req2)+" ch "+exp.charAt(0)+" match "+(pool_c2==req2));
        }
    }
}
