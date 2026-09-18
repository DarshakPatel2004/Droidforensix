import java.nio.file.*;
import java.util.*;
import java.io.*;

public class Replay {
    static short rotate_S(short v, int shift) {
        int v_int = v;
        int shl = v_int << shift;
        int r = 32 - shift;
        int ushr = v_int >>> r;
        int res = shl | ushr;
        return (short)res;
    }
    static long LMK(long x) {
        long v = (x >>> 33) ^ x;
        x = v;
        x *= 7109453100751455733L;
        v = (x >>> 28) ^ x;
        x = v;
        x *= -3808689974395783757L;
        x = x >>> 32;
        return x;
    }
    static long NkWa(long j) {
        short s = (short) (j & 65535);
        short s2 = (short) ((j >>> 16) & 65535);
        short OhM1VWC9IUcLWN7TO0 = (short) (OhM1VWC9IUcLWN7TO0((short) (s + s2), 9) + s);
        short s3 = (short) (s2 ^ s);
        return ((OhM1VWC9IUcLWN7TO0(s3, 10) | (OhM1VWC9IUcLWN7TO0 << 16)) << 16) | ((short) (((short) (OhM1VWC9IUcLWN7TO0(s, 13) ^ s3)) ^ (s3 << 5)));
    }
    static short OhM1VWC9IUcLWN7TO0(short s, int i) {
        return (short) ((s >>> (32 - i)) | (s << i));
    }
    static long prng_step(int idx, String[] pool, long state) {
        long ns = NkWa(state);
        int pool_idx = idx / 8191;
        int char_idx = idx % 8191;
        // Java's / and % for negative: trunc towards zero, remainder sign of dividend
        // In Java, -1/8191=0, -1%8191=-1
        // Need to handle negative idx: char_idx negative would be out of bounds
        // For now, handle negative by wrapping
        if (pool_idx <0 || pool_idx >= pool.length) {
            pool_idx = 0;
            if (char_idx <0) char_idx += 8191;
            if (char_idx >= pool[0].length()) char_idx %= pool[0].length();
        } else if (char_idx <0 || char_idx >= pool[pool_idx].length()) {
            // wrap negative
            if (char_idx <0) {
                // Java would throw, but we wrap
                char_idx = ((char_idx % pool[pool_idx].length()) + pool[pool_idx].length()) % pool[pool_idx].length();
            } else {
                char_idx %= pool[pool_idx].length();
            }
        }
        char c = pool[pool_idx].charAt(char_idx);
        long c_long = ((long)c) << 32;
        long res = c_long ^ ns;
        return res;
    }
    static String decode(long seed, String[] pool) {
        long low32 = seed & 0xFFFFFFFFL;
        long t0 = LMK(low32);
        long t1 = NkWa(t0);
        long v3 = (t1 >>> 32) & 0xFFFFL;
        long t2 = NkWa(t1);
        long tmp = (t2 >>> 16) & 0xFFFF0000L;
        long seed_high = seed >>> 32;
        long combined = seed_high ^ v3 ^ tmp;
        int combined_int = (int)combined;
        long state = prng_step(combined_int, pool, t2);
        int length = (int)((state >>> 32) & 0xFFFFL);
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<length; i++) {
            int idx = combined_int + i + 1;
            state = prng_step(idx, pool, state);
            int c_val = (int)((state >>> 32) & 0xFFFFL);
            sb.append((char)c_val);
        }
        return sb.toString();
    }
    public static void main(String[] args) throws Exception {
        String poolStr = Files.readString(Path.of("cjk_pool.txt"));
        // poolStr may contain newlines, take first line that is long
        String[] lines = poolStr.split("\\R");
        String poolCandidate = "";
        for (String l : lines) if (l.length() > 1000) poolCandidate = l;
        if (poolCandidate.isEmpty()) poolCandidate = poolStr.trim().replace("\r","").replace("\n","");
        String[] pool = new String[]{poolCandidate};
        System.out.println("Pool len " + pool[0].length());
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        // very simple parse
        Map<String,String> map = new LinkedHashMap<>();
        // use org.json if available, else manual
        // We'll manually parse with simple logic: split by ":
        // Instead use javax
        // For now, just test single seed
        long testSeed = -9154610674182L;
        String exp = "app_installation";
        String got = decode(testSeed, pool);
        System.out.println("Test seed " + testSeed + " exp " + exp + " got len " + got.length() + " got " + got.substring(0, Math.min(20, got.length())));
        System.out.println("Got full length " + got.length());
        // Write to file to avoid console encoding
        Files.writeString(Path.of("java_single_test.txt"), "exp " + exp + "\ngot " + got + "\nlen " + got.length());
        // Now test all
        // Parse JSON manually: use simple regex
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher m = p.matcher(json);
        int matches=0, mism=0, nulls=0;
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            String exp2 = null;
            if (!v.equals("null")) exp2 = m.group(3);
            else { nulls++; continue; }
            long seed = Long.parseLong(k);
            String g = decode(seed, pool);
            if (g.equals(exp2)) matches++;
            else {
                mism++;
                if (out.length() < 5000) out.append("MISMATCH " + k + " exp " + exp2 + " got " + g.substring(0, Math.min(30,g.length())) + " len " + g.length() + "\n");
            }
        }
        System.out.println("Matches " + matches + " Mism " + mism + " Nulls " + nulls);
        Files.writeString(Path.of("java_replay_result.txt"), out.toString() + "\nMatches " + matches + " Mism " + mism);
    }
}
