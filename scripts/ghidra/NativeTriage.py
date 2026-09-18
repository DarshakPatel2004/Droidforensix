# NativeTriage.py - Ghidra headless triage: functions, crypto constants, string seeds
# Jython-safe (no f-strings, no typing).
from ghidra.program.model.symbol import RefType

fm = currentProgram.getFunctionManager()
print("=== FUNCTIONS (%d) ===" % fm.getFunctionCount())
for f in fm.getFunctions(True):
    if f.isExternal() or f.isThunk():
        continue
    body = f.getBody().getNumAddresses()
    if body > 64:
        print("%s @ %s (%d bytes)" % (f.getName(), f.getEntryPoint(), body))

print("=== CRYPTO / KEY MATERIAL STRINGS ===")
listing = currentProgram.getListing()
needle = ("AES", "Rijndael", "SHA", "sha1", "sha256", "RC4", "mbedtls", "BoringSSL",
          "http://", "https://", "socket", "connect", ".dex", "PK\x03\x04", "assets",
          "bootstrap", "javax/crypto", "SecretKeySpec", "PBKDF", "EVP_")
definedStrings = listing.getDefinedData(True)
count = 0
for d in definedStrings:
    try:
        val = d.getValue()
        if val is None:
            continue
        s = str(val)
        if s and any(n in s for n in needle):
            print("%s : %r" % (d.getAddress(), s[:100]))
            count += 1
            if count > 120:
                break
    except Exception:
        pass
print("=== DONE ===")
