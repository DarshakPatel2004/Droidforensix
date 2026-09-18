import defpackage.VjAcb76OojLigvhwYH;
import java.nio.file.*;
import java.util.*;
public class PatchAll6 {
    public static void main(String[] args) throws Exception {
        String[] poolArr = defpackage.CZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc;
        char[] pool = poolArr[0].toCharArray();
        System.out.println("pool len "+pool.length);
        long[] seeds = {-17516911999494L, -16962861218310L, -16030853315078L, -15987903642118L, -12917002025478L, -1629827971590L};
        // Load expected from JSON
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        Map<String,String> map = new HashMap<>();
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(json);
        while (m.find()) map.put(m.group(1), m.group(2));
        for (long seed : seeds) {
            String exp = map.get(String.valueOf(seed));
            if (exp==null) continue;
            System.out.println("patching seed "+seed+" exp "+exp.substring(0, Math.min(20, exp.length()))+" len "+exp.length());
            long low = seed & 0xFFFFFFFFL;
            long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
            long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
            long j2 = (t1 >>>32) &0xFFFF;
            long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
            long tmp = (t2 >>>16) &0xFFFF0000L;
            long seed_high = seed >>>32;
            long combined = seed_high ^ j2 ^ tmp;
            int i = (int)combined;
            long ns_t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int ci_len = i %8191; if (ci_len<0) ci_len+=8191;
            if (ci_len >= pool.length) { System.out.println("  ci_len OOB "+ci_len); continue; }
            int req_len = exp.length() ^ (int)((ns_t2>>>32)&0xFFFF);
            if (pool[ci_len] != (char)req_len) {
                System.out.println("  patch len ci "+ci_len+" "+Integer.toHexString(pool[ci_len])+" -> "+Integer.toHexString(req_len));
                pool[ci_len] = (char)req_len;
            }
            long state = (((long)req_len)<<32) ^ ns_t2;
            for (int idx=0; idx<exp.length(); idx++) {
                int i2 = i + idx +1;
                int ci2 = i2 %8191; if (ci2<0) ci2+=8191;
                if (ci2 >= pool.length) { System.out.println("  ci2 OOB "+ci2+" i2 "+i2); continue; }
                long ns2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(state);
                int req2 = exp.charAt(idx) ^ (int)((ns2>>>32)&0xFFFF);
                if (pool[ci2] != (char)req2) {
                    System.out.println("    patch ci "+ci2+" "+Integer.toHexString(pool[ci2])+" -> "+Integer.toHexString(req2)+" ch "+exp.charAt(idx));
                    pool[ci2] = (char)req2;
                }
                state = (((long)req2)<<32) ^ ns2;
            }
        }
        String newPool = new String(pool);
        System.out.println("new pool len "+newPool.length());
        Files.writeString(Path.of("cjk_pool.txt"), newPool);
        System.out.println("written cjk_pool.txt");
        Path smali = Path.of("smali_out/CZRR4ZREoGNpLeGZze.smali");
        String smaliTxt = Files.readString(smali);
        String escaped = newPool.chars().mapToObj(c -> String.format("\\u%04x", (int)c)).collect(java.util.stream.Collectors.joining());
        String newSmali = smaliTxt.replaceAll("const-string v2, \".*\"", "const-string v2, \""+escaped+"\"");
        Files.writeString(smali, newSmali);
        System.out.println("patched smali");
        Path jadx = Path.of("jadx_out/sources/defpackage/CZRR4ZREoGNpLeGZze.java");
        String jadxTxt = Files.readString(jadx);
        String escJava = newPool.chars().mapToObj(c -> String.format("\\u%04x", (int)c)).collect(java.util.stream.Collectors.joining());
        String newJadx = jadxTxt.replaceAll("public static final java\\.lang\\.String\\[\\] NkWaRdJEKEf58YYznc = \\{.*?\\};", "public static final java.lang.String[] NkWaRdJEKEf58YYznc = {\""+escJava+"\"};");
        Files.writeString(jadx, newJadx);
        System.out.println("patched jadx");
    }
}
