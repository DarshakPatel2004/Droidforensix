"""Unit tests for Cipher.doFinal tracing (synthetic AES smali vectors)."""

import base64


from analysis.cipher_tracing import (
    derived_key_candidates,
    emulate_key_chain,
    parse_transformation,
    solve_file,
    trace_cipher_in_apk,
)
from analysis.step4_decoding import decode_payload, extract_artifacts


PLAINTEXT_URL = "https://evil-c2.example.com/beacon"
AES_KEY = "0123456789abcdef"  # 16 bytes
AES_IV = "abcdef9876543210"  # 16 bytes


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad_len = block - len(data) % block
    return data + bytes([pad_len]) * pad_len


def _aes_cbc_b64(plaintext: str, key: str, iv: str) -> str:
    from Crypto.Cipher import AES

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return base64.b64encode(cipher.encrypt(_pkcs7_pad(plaintext.encode()))).decode()


def _aes_ecb_b64(plaintext: str, key: str) -> str:
    from Crypto.Cipher import AES

    cipher = AES.new(key.encode(), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(_pkcs7_pad(plaintext.encode()))).decode()


def _smali_cbc(blob_b64: str) -> str:
    return (
        ".class public Lcom/evil/Crypt;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static decrypt()V\n"
        "    .locals 5\n"
        '    const-string v0, "AES/CBC/PKCS5Padding"\n'
        "    invoke-static {v0}, "
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
        "    move-result-object v1\n"
        f'    const-string v2, "{AES_KEY}"\n'
        "    invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B\n"
        "    move-result-object v2\n"
        "    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;\n"
        '    const-string v4, "AES"\n'
        "    invoke-direct {v3, v2, v4}, "
        "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
        f'    const-string v2, "{AES_IV}"\n'
        "    new-instance v3, Ljavax/crypto/spec/IvParameterSpec;\n"
        "    invoke-direct {v3, v2}, "
        "Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V\n"
        f'    const-string v2, "{blob_b64}"\n'
        "    invoke-virtual {v1, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
        "    return-void\n"
        ".end method\n"
    )


def _smali_ecb(blob_b64: str) -> str:
    return (
        ".class public Lcom/evil/CryptEcb;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static decrypt()V\n"
        "    .locals 3\n"
        '    const-string v0, "AES/ECB/PKCS5Padding"\n'
        "    invoke-static {v0}, "
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
        "    move-result-object v1\n"
        f'    const-string v2, "{AES_KEY}"\n'
        "    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;\n"
        "    invoke-virtual {v1, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
        "    return-void\n"
        ".end method\n"
        f'    # blob {blob_b64}\n'
    )


def _write_smali(tmp_path, name: str, content: str) -> str:
    smali_file = tmp_path / "smali" / "com" / "evil" / name
    smali_file.parent.mkdir(parents=True, exist_ok=True)
    smali_file.write_text(content, encoding="utf-8")
    return str(smali_file)


class TestParseTransformation:
    def test_aes_cbc(self):
        assert parse_transformation("AES/CBC/PKCS5Padding") == ("AES", "CBC", "PKCS5Padding")

    def test_bare_aes(self):
        assert parse_transformation("AES") == ("AES", "", "")

    def test_tripledes_alias(self):
        algo, _, _ = parse_transformation("TripleDES/ECB/PKCS5Padding")
        assert algo == "DESede"


class TestSolveFile:
    def test_cbc_solves_to_url(self):
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        solved, has_dofinal, found_key = solve_file(
            _smali_cbc(blob), "Crypt.smali", True
        )
        assert has_dofinal is True
        assert found_key is True
        assert len(solved) == 1
        enc = solved[0]
        assert enc["type"] == "cipher_aes"
        assert PLAINTEXT_URL in enc["decoded_preview"]
        assert enc["cipher_iv_present"] is True
        assert enc["validation_status"] == "valid"

    def test_ecb_without_iv(self):
        blob = _aes_ecb_b64(PLAINTEXT_URL, AES_KEY)
        smali = _smali_ecb("AAAAAAAAAAAAAAAAAAAAAA==") + _smali_cbc(blob).replace(
            "AES/CBC/PKCS5Padding", "AES/ECB/PKCS5Padding"
        )
        solved, _, _ = solve_file(smali, "CryptEcb.smali", True)
        assert any(PLAINTEXT_URL in s["decoded_preview"] for s in solved)

    def test_unsolved_when_key_via_args(self):
        # Transformation + doFinal present, but no const key of valid
        # length (key arrives via method args at runtime).
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        smali = (
            ".class public Lcom/evil/Dynamic;\n"
            ".method public static d([B)V\n"
            '    const-string v0, "AES/CBC/PKCS5Padding"\n'
            "    invoke-static {v0}, "
            "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
            '    const-string v1, "short"\n'
            f'    const-string v2, "{blob}"\n'
            "    invoke-virtual {v0, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
            ".end method\n"
        )
        solved, has_dofinal, found_key = solve_file(smali, "Dynamic.smali", True)
        assert solved == []
        assert has_dofinal is True
        assert found_key is False

    def test_no_cipher_no_site(self):
        solved, has_dofinal, _ = solve_file(
            'const-string v0, "hello world plaintext"\n', "Plain.smali", True
        )
        assert solved == []
        assert has_dofinal is False


class TestEmulateKeyChain:
    def test_getbytes_chain(self):
        body = (
            ".method public static k()V\n"
            "    .locals 3\n"
            f'    const-string v0, "{AES_KEY}"\n'
            "    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B\n"
            "    move-result-object v0\n"
            "    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v2, "AES"\n'
            "    invoke-direct {v1, v0, v2}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        derived = emulate_key_chain(body)
        assert derived and derived[0][0] == AES_KEY.encode()

    def test_base64_decode_chain(self):
        import base64 as _b64

        key_b64 = _b64.b64encode(AES_KEY.encode()).decode()
        body = (
            ".method public static k()V\n"
            "    .locals 3\n"
            f'    const-string v0, "{key_b64}"\n'
            "    const/4 v1, 0x0\n"
            "    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B\n"
            "    move-result-object v0\n"
            "    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v2, "AES"\n'
            "    invoke-direct {v1, v0, v2}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        derived = emulate_key_chain(body)
        assert derived and derived[0][0] == AES_KEY.encode()

    def test_register_reuse_before_use_resolves(self):
        # v0 is reused as a counter after the key moved on: backward slice
        # takes the nearest write, so reuse does not poison the chain.
        body = (
            ".method public static k()V\n"
            "    .locals 3\n"
            f'    const-string v0, "{AES_KEY}"\n'
            "    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B\n"
            "    move-result-object v1\n"
            "    const/4 v0, 0x0\n"
            "    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v0, "AES"\n'
            "    invoke-direct {v2, v1, v0}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        derived = emulate_key_chain(body)
        assert derived and derived[0][0] == AES_KEY.encode()

    def test_concat_then_getbytes_chain(self):
        half = len(AES_KEY) // 2
        first, second = AES_KEY[:half], AES_KEY[half:]
        body = (
            ".method public static k()V\n"
            "    .locals 4\n"
            "    new-instance v0, Ljava/lang/StringBuilder;\n"
            "    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V\n"
            f'    const-string v1, "{first}"\n'
            "    invoke-virtual {v0, v1}, "
            "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n"
            "    move-result-object v0\n"
            f'    const-string v1, "{second}"\n'
            "    invoke-virtual {v0, v1}, "
            "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n"
            "    move-result-object v0\n"
            "    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n"
            "    move-result-object v0\n"
            "    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B\n"
            "    move-result-object v0\n"
            "    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v2, "AES"\n'
            "    invoke-direct {v1, v0, v2}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        derived = emulate_key_chain(body)
        assert derived and derived[0][0] == AES_KEY.encode()

    def test_dynamic_field_yields_nothing(self):
        body = (
            ".method public k()V\n"
            "    .locals 2\n"
            "    iget-object v0, p0, Lcom/x/C;->key:[B\n"
            "    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v2, "AES"\n'
            "    invoke-direct {v1, v0, v2}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            "    return-void\n"
            ".end method\n"
        )
        assert emulate_key_chain(body) == []

    def test_solve_file_with_derived_key(self):
        import base64 as _b64

        key_b64 = _b64.b64encode(AES_KEY.encode()).decode()
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        smali = (
            ".class public Lcom/evil/CryptT;\n"
            ".super Ljava/lang/Object;\n"
            ".method public static decrypt()V\n"
            "    .locals 5\n"
            '    const-string v0, "AES/CBC/PKCS5Padding"\n'
            "    invoke-static {v0}, "
            "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
            f'    const-string v2, "{key_b64}"\n'
            "    const/4 v3, 0x0\n"
            "    invoke-static {v2, v3}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B\n"
            "    move-result-object v2\n"
            "    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v4, "AES"\n'
            "    invoke-direct {v3, v2, v4}, "
            "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            f'    const-string v2, "{AES_IV}"\n'
            "    new-instance v3, Ljavax/crypto/spec/IvParameterSpec;\n"
            "    invoke-direct {v3, v2}, "
            "Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V\n"
            f'    const-string v2, "{blob}"\n'
            "    invoke-virtual {v0, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
            "    return-void\n"
            ".end method\n"
        )
        # Bare-const solver alone must fail (no valid-length const key present).
        assert derived_key_candidates(smali, "AES")
        solved, _, found_key = solve_file(smali, "CryptT.smali", True)
        assert found_key is True
        assert any(PLAINTEXT_URL in s["decoded_preview"] for s in solved)

    def test_multiline_invoke_target_solves(self):
        blob = _aes_ecb_b64(PLAINTEXT_URL, AES_KEY)
        smali = (
            ".class public Lcom/evil/CryptM;\n"
            ".super Ljava/lang/Object;\n"
            ".method public static decrypt()V\n"
            "    .locals 3\n"
            '    const-string v0, "AES/ECB/PKCS5Padding"\n'
            "    invoke-static {v0}, "
            "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
            f'    const-string v2, "{AES_KEY}"\n'
            "    invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B\n"
            "    move-result-object v2\n"
            "    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;\n"
            '    const-string v4, "AES"\n'
            "    invoke-direct {v3, v2, v4},\n"
            "        Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V\n"
            f'    const-string v2, "{blob}"\n'
            "    invoke-virtual {v0, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
            "    return-void\n"
            ".end method\n"
        )
        solved, _, _ = solve_file(smali, "CryptM.smali", True)
        assert any(PLAINTEXT_URL in s["decoded_preview"] for s in solved)


class TestTraceInApk:
    def test_end_to_end_apk_dir(self, tmp_path):
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        _write_smali(tmp_path, "Crypt.smali", _smali_cbc(blob))
        result = trace_cipher_in_apk({"apktool_output_dir": str(tmp_path)})
        assert result["total_sites"] == 1
        assert result["solved"] == 1
        assert result["traced_unsolved"] == 0
        assert result["encodings"][0]["type"] == "cipher_aes"

    def test_unsolved_counted(self, tmp_path):
        smali = (
            'const-string v0, "AES/CBC/PKCS5Padding"\n'
            "invoke-static {v0}, "
            "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
            'const-string v1, "short"\n'
            "invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B\n"
        )
        _write_smali(tmp_path, "Dynamic.smali", smali)
        result = trace_cipher_in_apk({"apktool_output_dir": str(tmp_path)})
        assert result["total_sites"] == 1
        assert result["solved"] == 0
        assert result["traced_unsolved"] == 1

    def test_empty_apk_info(self):
        assert trace_cipher_in_apk({})["total_sites"] == 0


class TestStep4Integration:
    def test_decode_payload_roundtrip(self, tmp_path):
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        _write_smali(tmp_path, "Crypt.smali", _smali_cbc(blob))
        enc = trace_cipher_in_apk({"apktool_output_dir": str(tmp_path)})["encodings"][0]
        plaintext = decode_payload(enc)
        assert plaintext is not None
        assert PLAINTEXT_URL in plaintext.decode("utf-8")

    def test_artifacts_find_c2_url(self, tmp_path):
        blob = _aes_cbc_b64(PLAINTEXT_URL, AES_KEY, AES_IV)
        _write_smali(tmp_path, "Crypt.smali", _smali_cbc(blob))
        enc = trace_cipher_in_apk({"apktool_output_dir": str(tmp_path)})["encodings"][0]
        plaintext = decode_payload(enc)
        artifacts = extract_artifacts(plaintext, enc["type"])
        assert any(
            a["type"] == "url" and "evil-c2.example.com" in a["value"]
            for a in artifacts
        )
