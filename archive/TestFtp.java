import java.nio.file.*;
import defpackage.FtpOxqekIibXASlT37;
public class TestFtp {
    public static void main(String[] args) throws Exception {
        String poolStr = Files.readString(Path.of("cjk_pool.txt"));
        // pool is single line, but file may have been written with 4321 chars
        String[] pool = new String[]{poolStr.trim().replace("\r","").replace("\n","")};
        System.out.println("Pool len " + pool[0].length());
        long seed = -9154610674182L;
        String result = FtpOxqekIibXASlT37.OhM1VWC9IUcLWN7TO0(seed, pool);
        System.out.println("Result len " + result.length());
        System.out.println("Result: " + result);
        // Write to file to avoid console encoding
        Files.writeString(Path.of("test_ftp_out.txt"), result);
        // Also test via JSON
        String json = Files.readString(Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher m = p.matcher(json);
        int matches=0, mism=0;
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            String exp = null;
            if (!v.equals("null")) exp = m.group(3);
            else continue;
            long s = Long.parseLong(k);
            String g = FtpOxqekIibXASlT37.OhM1VWC9IUcLWN7TO0(s, pool);
            if (g.equals(exp)) matches++;
            else {
                mism++;
                if (out.length() < 5000) out.append(k + " exp " + exp + " got " + g.substring(0, Math.min(20,g.length())) + "\n");
            }
        }
        System.out.println("Matches " + matches + " Mism " + mism);
        Files.writeString(Path.of("test_ftp_result.txt"), out.toString() + "\nMatches " + matches + " Mism " + mism);
    }
}
