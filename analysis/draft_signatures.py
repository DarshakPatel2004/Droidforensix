"""
Drafted signature rules for the 48 no-signature family-ID gap samples.

Mined from lean static features of the actual samples (see gap_signature_mining.py
and gap_signal_report.json). Each rule follows the backend/family_id.py v3
conventions: a family claim must rest on a discriminating signal (family
string / C2 domain); shape-only signals (class range, native:no) can never
satisfy a match by themselves.

Status legend:
  STRONG  - unique family string / C2 domain found in the samples
  MEDIUM  - distinctive but single-sample evidence, or a shared-SDK domain
  WEAK    - single sample, generic strings, or ad-SDK domain (FP risk)

Operationalized state (see backend/family_id.py "Gap-recovery signatures"):
  COMMITTED  - validated over the full 359-sample corpus with zero false
               positives and moved into FAMILY_SIGNATURES:
               Secapk*, Adsms, FaceNiff, SmForw, Typstu, NickiSpy, Boogr,
               Hamob, SpyHasb, Dougalek*  (* = tuned during validation:
               Secapk dropped the generic "addprovider"/"chmod 755" strings
               and raised min_matches to 4; Dougalek gained require_c2=True)
  HELD       - kept here for future work, single generic C2 or FP risk:
               FakeTimer, Lemon, Stiniter, Nandrobox

Unsignable families are documented in gap_signal_report.json:
  - statically unrecoverable (encrypted/corrupt/hollow DEX): CraxsRAT, Mirax,
    UKP, GhostBat (3/4), Android/Agent (1/2), BankBot (1/3)
  - generic AV labels / ad-SDK repackages with no discriminator: Airpush,
    AdLibrary, AppRisk, Bian, Cnzz, FakeApp, FakeTimer, SMSreg, SmsSend,
    Spitmo, Wooboo (weak), Nandrobox (weak), Lemon (weak), Stiniter (weak)
  - existing signature that missed its samples: BankBot, DroidDream, Zsone,
    FakeRun (see "existing signature diagnosis" in the validation summary)

Validation: python analysis/gap_signature_mining.py --validate
"""

from typing import List

from backend.family_id import C2MatchMode, C2Pattern, FamilySignature, PermissionSig

# Families moved into backend/family_id.py after 359-sample validation; kept in
# this list so analysis scripts can tell committed drafts from held ones.
COMMITTED_FAMILIES = {
    "Secapk", "Adsms", "FaceNiff", "SmForw", "Typstu",
    "NickiSpy", "Boogr", "Hamob", "SpyHasb", "Dougalek",
    # Discriminator-string commit (Option A):
    "KungFu", "Bian", "Cnzz", "Nandrobox", "SMSreg", "SmsSend",
    # Held draft commit (Phase 1 — 3 safe drafts, 0 FP):
    "FakeTimer", "Lemon", "Stiniter",
}


DRAFT_SIGNATURES: List[FamilySignature] = [
    # ------------------------------------------------------------------
    # Secapk — Chinese APK packer (2 samples, both recovered).
    # Decodes an embedded classes.jar, spawns a child process and chmods
    # the unpacked file ("chmod 755"). The packer strings are unique to
    # SecAPK builds and absent from every other sample in the corpus.
    #   STRONG — COMMITTED. Tuned during validation: "addprovider" and
    #   "chmod 755" were dropped (generic dex-loading strings that fired on
    #   unrelated samples) and min_matches raised to 4 so a SecAPK string
    #   is mandatory.
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Secapk",
        string_patterns=["classesjarfile", "jarfilename"],
        c2_patterns=[],
        permission_sigs=[
            PermissionSig("SYSTEM_ALERT_WINDOW", 0.8),
            PermissionSig("READ_PHONE_STATE", 0.7),
        ],
        class_count_min=1, class_count_max=60,
        has_native_libs=True,
        min_matches=4, confidence=0.75,
    ),

    # ------------------------------------------------------------------
    # Adsms — DREBIN-era SMS/ad trojan (1 sample recovered).
    # Every recovered C2 domain literally starts with "adsms.":
    #   adsms.itodo.cn, adsms.yywo.cn, adsms.1oo86.net
    #   STRONG (family-named C2)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Adsms",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("adsms.", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("SEND_SMS", 0.9),
            PermissionSig("RECEIVE_SMS", 0.85),
            PermissionSig("WRITE_APN_SETTINGS", 0.8),
        ],
        class_count_min=1, class_count_max=80,
        has_native_libs=False,
        require_c2=True,
        min_matches=2, confidence=0.80,
    ),

    # ------------------------------------------------------------------
    # FaceNiff — session-hijacking tool (1 sample). The app literally
    # contains the string "faceniff" plus "wifi not enabled!".
    #   STRONG (family string)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="FaceNiff",
        string_patterns=["faceniff"],
        c2_patterns=[],
        permission_sigs=[
            PermissionSig("INTERNET", 0.9),
            PermissionSig("ACCESS_WIFI_STATE", 0.9),
            PermissionSig("WAKE_LOCK", 0.6),
        ],
        class_count_min=10, class_count_max=100,
        has_native_libs=False,
        min_matches=4, confidence=0.80,
    ),

    # ------------------------------------------------------------------
    # SmForw — SMS forwarder trial (1 sample). Strings reference
    # "smsforwardertrial" / "smsforwarder" and a licensing endpoint.
    #   STRONG-ish (product-named strings)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="SmForw",
        string_patterns=["smsforwarder"],
        c2_patterns=[],
        permission_sigs=[
            PermissionSig("SEND_SMS", 1.0),
            PermissionSig("RECEIVE_SMS", 0.9),
            PermissionSig("READ_SMS", 0.8),
        ],
        class_count_min=1, class_count_max=30,
        has_native_libs=False,
        min_matches=4, confidence=0.75,
    ),

    # ------------------------------------------------------------------
    # Typstu — Typ3Studios repackaged apps (1 sample). Contains
    # "typ3studios" strings and pixeltrack66.com tracking URLs.
    #   STRONG
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Typstu",
        string_patterns=["typ3studios", "pixeltrack66"],
        c2_patterns=[
            C2Pattern("pixeltrack66.com", C2MatchMode.SUBSTRING),
            C2Pattern("typ3studios.com", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("INTERNET", 0.9),
            PermissionSig("READ_PHONE_STATE", 0.7),
        ],
        class_count_min=5, class_count_max=60,
        has_native_libs=False,
        min_matches=4, confidence=0.75,
    ),

    # ------------------------------------------------------------------
    # NickiSpy — audio-recording spyware (1 sample). Distinctive dynamic
    # C2 (jin.56mo.com) plus a recorder string cluster and RECORD_AUDIO.
    #   MEDIUM (single sample, but family-named behavior)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="NickiSpy",
        string_patterns=["recordlen", "issms", "smstype"],
        c2_patterns=[
            C2Pattern("jin.56mo.com", C2MatchMode.EXACT),
        ],
        permission_sigs=[
            PermissionSig("RECORD_AUDIO", 1.0),
            PermissionSig("PROCESS_OUTGOING_CALLS", 0.8),
            PermissionSig("READ_SMS", 0.7),
        ],
        class_count_min=10, class_count_max=100,
        has_native_libs=False,
        require_c2=True,
        min_matches=2, confidence=0.70,
    ),

    # ------------------------------------------------------------------
    # Boogr — tunneling C2 malware (1 sample). C2 rides a Cloudflare
    # quick-tunnel (representation-certified-accomplish-existed.
    # trycloudflare.com) plus ru.whoosh.app.
    #   MEDIUM (trycloudflare is a legit service; rare in apps)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Boogr",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("trycloudflare.com", C2MatchMode.SUBSTRING),
            C2Pattern("whoosh.app", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("INTERNET", 0.9),
            PermissionSig("QUERY_ALL_PACKAGES", 0.7),
        ],
        class_count_min=500, class_count_max=4000,
        has_native_libs=False,
        require_c2=True,
        min_matches=3, confidence=0.65,
    ),

    # ------------------------------------------------------------------
    # Hamob — GCM-driven SMS stealer (1 sample). The "application mode"
    # toggle strings (appmode / applicationmode / getapplicationmode) are
    # the family's documented trademark; unusual C2D_MESSAGE+PLUGIN perms.
    #   MEDIUM
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Hamob",
        string_patterns=["applicationmode", "appmode"],
        c2_patterns=[],
        permission_sigs=[
            PermissionSig("C2D_MESSAGE", 0.9),
            PermissionSig("PLUGIN", 0.8),
            PermissionSig("INTERNET", 0.6),
        ],
        class_count_min=50, class_count_max=250,
        has_native_libs=False,
        min_matches=4, confidence=0.65,
    ),

    # ------------------------------------------------------------------
    # SpyHasb — dynamic-DNS spyware (1 sample). C2 on appserver3l.no-ip.biz
    # (no-ip dynamic DNS is the classic mobile-spyware C2 pattern).
    #   MEDIUM
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="SpyHasb",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("no-ip.biz", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("INTERNET", 0.9),
            PermissionSig("ACCESS_COARSE_LOCATION", 0.8),
        ],
        class_count_min=1, class_count_max=60,
        has_native_libs=False,
        require_c2=True,
        min_matches=2, confidence=0.65,
    ),

    # ------------------------------------------------------------------
    # Dougalek — Japanese SMS trojan (1 sample). "gamedouga" class package
    # plus C2 depot.bulks.jp.
    #   MEDIUM — COMMITTED. Tuned during validation: require_c2=True added
    #   (the READ_CONTACTS+READ_PHONE_STATE+INTERNET trio is near-universal
    #   and fired the signature on 68 unrelated samples).
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Dougalek",
        string_patterns=["gamedouga"],
        c2_patterns=[
            C2Pattern("depot.bulks.jp", C2MatchMode.EXACT),
        ],
        permission_sigs=[
            PermissionSig("READ_CONTACTS", 0.8),
            PermissionSig("READ_PHONE_STATE", 0.7),
            PermissionSig("INTERNET", 0.6),
        ],
        class_count_min=1, class_count_max=40,
        has_native_libs=False,
        require_c2=True,
        min_matches=2, confidence=0.65,
    ),

    # ------------------------------------------------------------------
    # Lemon — Chinese SMS/APN trojan (1 sample). C2 kaixinai.com with
    # WRITE_APN_SETTINGS + SEND_SMS + mmsc.monternet.com (China Mobile).
    #   WEAK - HELD for future work (single sample, single C2)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Lemon",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("kaixinai.com", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("SEND_SMS", 1.0),
            PermissionSig("WRITE_APN_SETTINGS", 0.9),
            PermissionSig("RECEIVE_SMS", 0.7),
        ],
        class_count_min=100, class_count_max=600,
        has_native_libs=False,
        require_c2=True,
        min_matches=3, confidence=0.60,
    ),

    # ------------------------------------------------------------------
    # Nandrobox — DREBIN-era SMS/click-fraud (1 sample). C2
    # mobilehotdog.com / wap.casee.cn plus Domob ad SDK (r.domob.cn).
    #   WEAK - HELD for future work (ad-SDK adjacent, single sample)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Nandrobox",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("mobilehotdog.com", C2MatchMode.SUBSTRING),
            C2Pattern("casee.cn", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("SEND_SMS", 0.9),
            PermissionSig("READ_LOGS", 0.8),
            PermissionSig("RECEIVE_SMS", 0.7),
        ],
        class_count_min=400, class_count_max=2000,
        has_native_libs=False,
        require_c2=True,
        min_matches=3, confidence=0.60,
    ),

    # ------------------------------------------------------------------
    # Stiniter — media-player trojan (1 sample). C2 dangpao.com.
    #   WEAK - HELD for future work (single sample, no permissions)
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="Stiniter",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("dangpao.com", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[],
        class_count_min=50, class_count_max=150,
        has_native_libs=False,
        require_c2=True,
        min_matches=3, confidence=0.55,
    ),

    # ------------------------------------------------------------------
    # FakeTimer — DREBIN-era fake timer (1 sample). C2 erotte.com.
    #   WEAK - HELD for future work
    # ------------------------------------------------------------------
    FamilySignature(
        family_name="FakeTimer",
        string_patterns=[],
        c2_patterns=[
            C2Pattern("erotte.com", C2MatchMode.SUBSTRING),
        ],
        permission_sigs=[
            PermissionSig("SEND_SMS", 0.9),
            PermissionSig("ACCESS_FINE_LOCATION", 0.7),
        ],
        class_count_min=1, class_count_max=40,
        has_native_libs=False,
        require_c2=True,
        min_matches=3, confidence=0.55,
    ),
]
