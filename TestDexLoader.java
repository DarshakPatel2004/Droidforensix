import dalvik.system.DexClassLoader;
import java.lang.reflect.Method;
import java.io.File;
public class TestDexLoader {
    public static void main(String[] args) throws Exception {
        String dexPath = "D:\\DroidForensix\\uploads\\44b10841-c0ac-4d21-8979-7227d154896f\\rto_extracted\\phase4_payload\\installer_extracted\\classes.dex";
        String outDir = ".";
        DexClassLoader loader = new DexClassLoader(dexPath, outDir, null, TestDexLoader.class.getClassLoader());
        Class<?> czrr = loader.loadClass("LCZRR4ZREoGNpLeGZze;");
        // Actually class name is "LCZRR4ZREoGNpLeGZze;" is internal, need "defpackage.CZRR..."? No, the class is "LCZRR4ZREoGNpLeGZze;" is the internal name, but Java name is "CZRR4ZREoGNpLeGZze" in default package? In smali it's "LCZRR4ZREoGNpLeGZze;" in default package, not defpackage.
        // The jadx decompiled shows "defpackage.CZRR..." but smali shows "LCZRR..." in default.
        // Let's try both
        try {
            czrr = loader.loadClass("CZRR4ZREoGNpLeGZze");
            System.out.println("Loaded CZRR4ZREoGNpLeGZze");
        } catch (Exception e) {
            System.out.println("Failed CZRR: " + e);
            czrr = loader.loadClass("defpackage.CZRR4ZREoGNpLeGZze");
            System.out.println("Loaded defpackage.CZRR");
        }
        Method m = czrr.getMethod("NkWaRdJEKEf58YYznc", long.class);
        long seed = -9154610674182L;
        String result = (String) m.invoke(null, seed);
        System.out.println("Result for -915: " + result);
        // Test all
        String json = java.nio.file.Files.readString(java.nio.file.Path.of("rto_analysis/phase2/installer_deobfuscated_strings.json"));
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"(-?\\d+)\"\\s*:\\s*(null|\"([^\"]*)\")");
        java.util.regex.Matcher matcher = p.matcher(json);
        int matches=0, mism=0;
        while (matcher.find()) {
            String k = matcher.group(1);
            String v = matcher.group(2);
            String exp = null;
            if (!v.equals("null")) exp = matcher.group(3);
            else continue;
            long s = Long.parseLong(k);
            String g = (String) m.invoke(null, s);
            if (g.equals(exp)) matches++;
            else mism++;
        }
        System.out.println("Matches " + matches + " Mism " + mism);
    }
}
