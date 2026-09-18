import java.nio.file.*;
import defpackage.FtpOxqekIibXASlT37;
public class TestFtp2 {
    public static void main(String[] args) throws Exception {
        String poolStr = Files.readString(Path.of("cjk_pool.txt"));
        String[] pool = new String[]{poolStr.trim().replace("\r","").replace("\n","")};
        System.out.println("Pool len " + pool[0].length());
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
            if (g.equals(exp)) {
                matches++;
                out.append("MATCH " + k + " " + exp + "\n");
            } else {
                mism++;
                if (out.length() < 10000) out.append("MISMATCH " + k + " exp " + exp + " got len " + g.length() + " got " + (g.length()>20?g.substring(0,20):g) + "\n");
            }
        }
        System.out.println("Matches " + matches + " Mism " + mism);
        Files.writeString(Path.of("test_ftp2_out.txt"), out.toString() + "\nMatches " + matches + " Mism " + mism);
    }
}
