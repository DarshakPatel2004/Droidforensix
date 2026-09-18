import java.nio.file.*;
import java.util.*;
import defpackage.VjAcb76OojLigvhwYH;
import defpackage.FtpOxqekIibXASlT37;
public class SolvePoolJava {
    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher m = p.matcher(json);
        Map<Integer, Character> required = new HashMap<>();
        Map<Integer, String> requiredSeed = new HashMap<>();
        boolean conflict=false;
        int total=0;
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            String exp = null;
            if (!v.equals("null")) exp = m.group(3);
            else continue;
            long seed = Long.parseLong(k);
            // Simulate to find required pool chars
            long low = seed & 0xFFFFFFFFL;
            long t0 = VjAcb76OojLigvhwYH.LMKdxcNChRaUWXpv21(low);
            long t1 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t0);
            long j2 = (t1 >>>32) &0xFFFF;
            long t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t1);
            long tmp = (t2 >>>16) &0xFFFF0000L;
            long seed_high = seed >>>32;
            long combined = seed_high ^ j2 ^ tmp;
            int i = (int)combined;
            // First prng for length
            // Need to know what pool char at i would make len = exp.length()
            // Ftp.NkWa(i, pool, t2) -> state, len = (state>>>32)&0xFFFF
            // state = (pool[i%8191] <<32) ^ VjAc.NkWa(t2)
            // So pool[i%8191] = len ^ (VjAc.NkWa(t2)>>32 &0xFFFF)
            long ns_t2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(t2);
            int ci_len = i %8191;
            if (ci_len<0) ci_len+=8191;
            int pool_len_needed = 8191;
            // For pool array size 1, ci must be < pool_len, but we don't know pool_len, assume 8191
            // For solving, we map ci to required char
            int req_len_char = exp.length() ^ (int)((ns_t2 >>>32)&0xFFFF);
            // Record
            if (required.containsKey(ci_len) && required.get(ci_len) != (char)req_len_char) {
                System.out.println("conflict len ci "+ci_len+" seed "+k+" exp "+exp+" len "+exp.length()+" req "+Integer.toHexString(req_len_char)+" vs "+Integer.toHexString(required.get(ci_len))+" existing seed "+requiredSeed.get(ci_len));
                conflict=true;
                break;
            }
            required.put(ci_len, (char)req_len_char);
            requiredSeed.put(ci_len, k+" len");
            long state = (((long)req_len_char)<<32) ^ ns_t2;
            // For each char in exp
            for (int idx=0; idx<exp.length(); idx++) {
                int i2 = i + idx +1;
                int ci2 = i2 %8191;
                if (ci2<0) ci2+=8191;
                long ns2 = VjAcb76OojLigvhwYH.NkWaRdJEKEf58YYznc(state);
                int req2 = exp.charAt(idx) ^ (int)((ns2>>>32)&0xFFFF);
                if (required.containsKey(ci2) && required.get(ci2) != (char)req2) {
                    System.out.println("conflict char ci "+ci2+" idx "+i2+" seed "+k+" ch "+exp.charAt(idx)+" req "+Integer.toHexString(req2)+" vs "+Integer.toHexString(required.get(ci2))+" exp "+exp+" existing "+requiredSeed.get(ci2));
                    conflict=true;
                    break;
                }
                required.put(ci2, (char)req2);
                requiredSeed.put(ci2, k+" idx"+idx);
                state = (((long)req2)<<32) ^ ns2;
            }
            if (conflict) break;
            total++;
        }
        System.out.println("total processed "+total+" required size "+required.size()+" conflict "+conflict);
        if (!conflict) {
            // Build pool of 8191 with required chars, fill rest with 0
            char[] pool = new char[8191];
            for (int i=0;i<8191;i++) pool[i]= required.containsKey(i) ? required.get(i) : '\u0000';
            String poolStr = new String(pool);
            Files.writeString(Path.of("reconstructed_8191.txt"), poolStr);
            System.out.println("written 8191");
            // Also try 4320
            char[] pool2 = new char[4320];
            for (int i=0;i<4320;i++) pool2[i]= required.containsKey(i) ? required.get(i) : (required.containsKey(i+8191) ? required.get(i+8191) : '\u0000');
            // Actually for 4320, need to handle wrap: ci %4320
            // This is getting too complex, just write 4320 with first 4320 of required
        }
    }
}
