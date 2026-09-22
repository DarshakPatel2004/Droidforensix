import pathlib, zipfile, sys
sys.stdout.reconfigure(line_buffering=True)

roots = [pathlib.Path(r"PENDRIVE DATA\PENDRIVE DATA\apk fraud"),
         pathlib.Path(r"PENDRIVE DATA\PENDRIVE DATA\new apk files")]
seen = set()
for root in roots:
    for apk in root.rglob("*.apk"):
        key = apk.stat().st_size
        if key in seen:
            continue
        seen.add(key)
        try:
            zf = zipfile.ZipFile(apk)
            names = set(i.filename for i in zf.infolist()
                        if i.filename.endswith(".so"))
        except Exception:
            continue
        markers = [
            "ijm_lib", "IJMDal.Data", "ijiami",
            "libexec.so", "libexecmain.so", "libjiagu.so",
            "libSecShell.so", "libBangcle", "libtup.so", "libprotectclass.so",
            "libDexHelper.so", "libsgmain.so", "libegis.so",
            "libshell.so", "libDexHelper", "flipper", "libyten.so", "libmobisec.so",
        ]
        hits = [m for m in markers if any(m.lower() in n.lower() for n in names)]
        if not hits:
            continue
        so = sorted(n for n in names if "sec" in n.lower() or "jiagu" in n.lower()
                    or "ijm" in n.lower() or "shell" in n.lower()
                    or "exec" in n.lower() or "tup" in n.lower()
                    or "protect" in n.lower() or "dexhelper" in n.lower()
                    or "sg" in n.lower() or "yten" in n.lower())[:10]
        print("%-45s %9d %s" % (apk.name[:45], apk.stat().st_size, sorted(set(hits))))
        for s in so:
            info = zf.getinfo(s)
            print("        %8d %s" % (info.file_size, s))