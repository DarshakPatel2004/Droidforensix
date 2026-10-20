"""Single source of truth for malware-family label semantics.

Three modules used to carry three different catch-all lists (evaluation
scoring, GT repair, campaign clustering), so any two reported numbers could
disagree purely by definition. Everything label-related imports from here:

  - CATCH_ALL_LABELS / is_catch_all(): vendor-generic labels with no
    family-level identity (category names, parse artifacts, packer E-codes).
  - VENDOR_ALIASES: same family, different vendor naming (Drebin vs
    Kaspersky). One direction per pair, GT side as key.
  - LINEAGE_CANONICAL: vendor splits of one kit scored as one family
    (premium-SMS fraud kit: shared certs/packages/code across labels).
  - is_correct(): scoring predicate (exact, alias, or lineage match).

Stdlib only: importable from analysis, backend, evaluation, and scripts
without circular-import risk.
"""

import re
from typing import Dict

# Vendor-generic labels: no family-level identity exists to match.
# Includes Master-Key E-codes (commercial-packer limits, not model misses).
CATCH_ALL_LABELS = frozenset({
    "unknown", "androidos", "generic", "gen", "agent", "banker", "adware",
    "backdoor", "linux", "detected", "dropper", "trojan-banker",
    "trojan-dropper", "exploit", "hacktool", "application", "general",
    "android/packed", "evo-gen [trj]", "heur", "generickd", "a",
    "33107585", "40094400",
    "e-native-noentry", "e-native-no-recovery", "e-native-lazy-decrypt",
    "e-native-nullcall", "e-java-runtime-delivery", "e-java-no-ioc",
    "e-oracle-fault", "e-arm32-envargs", "e-zipcrypto-runtime",
    "e_native_noentry", "e_native_no_recovery", "e_java_runtime_delivery",
    # Bare vendor generics shared with the GT-repair list.
    "trojan", "spyware", "andraware", "andro",
    # SDKs, ad networks, and packers are not families: rows labeled with
    # them (Cnzz analytics, SecApk packer, SMSreg/AdLibrary SDKs) carry no
    # family identity. Verified by review: "Cnzz"-clustered samples are
    # unrelated apps (e.g. a racing game) sharing an analytics SDK.
    "cnzz", "secapk", "smsreg", "adlibrary",
})

# VT-style "Trojan (<hash>)" labels are catch-alls too — matched structurally.
_ARTIFACT_PREFIXES = ("trojan (", "trojan-", "pua.", "riskware.", "adware.")


def is_catch_all(family: str) -> bool:
    """True for labels with no family-level identity.

    Strips a vendor platform prefix first, so Kaspersky-style
    "Android/Agent" matches the same rule as bare "Agent".
    """
    if not family:
        return True
    lowered = family.strip().lower()
    lowered = re.sub(r"^android[./]", "", lowered)
    if lowered in CATCH_ALL_LABELS:
        return True
    return lowered.startswith(_ARTIFACT_PREFIXES)


# Same family, different vendor naming. GT side as key (scorer direction).
VENDOR_ALIASES: Dict[str, str] = {
    "KungFu": "DroidKungFu",
    "Andr/NGate-G": "NGate",
    "Andr/Banker-HDY": "BankBot",
    "FakeInstaller": "FakeInst",
    "FakeInst": "FakeInstaller",
}

# Vendor splits of one kit, scored as one family (canonical member maps to
# itself so normalization is total over the lineage).
LINEAGE_CANONICAL: Dict[str, str] = {
    "fakeinst": "fakeinst",
    "fakeinstaller": "fakeinst",
    "opfake": "fakeinst",
}


def canonical_family(family: str) -> str:
    """Lineage-canonical form (identity outside known lineages)."""
    key = (family or "").strip().lower()
    return LINEAGE_CANONICAL.get(key, (family or "").strip())


def is_correct(prediction: str, ground_truth: str) -> bool:
    """Scoring predicate: exact, vendor-alias, or lineage match."""
    pred = (prediction or "").strip()
    truth = (ground_truth or "").strip()
    if pred.casefold() == truth.casefold():
        return True
    if VENDOR_ALIASES.get(truth, "").casefold() == pred.casefold():
        return True
    canon_truth = LINEAGE_CANONICAL.get(truth.casefold())
    canon_pred = LINEAGE_CANONICAL.get(pred.casefold())
    return canon_truth is not None and canon_truth == canon_pred
