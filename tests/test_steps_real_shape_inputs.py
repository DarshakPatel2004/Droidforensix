"""Steps 12 and 17 must read the apk_info shape that step 1 really produces.

Step 1 stores the apktool tree as `apktool_output_dir`. Before the fix these steps looked for
`extracted_path` / `work_dir` only and silently returned nothing on real pipeline input.
"""

from analysis.step12_reflective_tracing import find_reflective_calls
from analysis.step17_family_clustering import cluster_family

SMALI_WITH_REFLECTION = """.class public Lcom/x/A;
.method public run()V
    const-string v0, "android.telephony.SmsManager"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    return-void
.end method
"""

SMALI_TWO_METHODS = """.class public Lcom/x/A;
.method public run()V
    return-void
.end method
.method public stop()V
    return-void
.end method
"""


def _apktool_tree(tmp_path, smali_text):
    smali_dir = tmp_path / "smali" / "com" / "x"
    smali_dir.mkdir(parents=True)
    (smali_dir / "A.smali").write_text(smali_text, encoding="utf-8")
    return {"apktool_output_dir": str(tmp_path)}


def test_step12_finds_reflection_via_apktool_output_dir(tmp_path):
    result = find_reflective_calls(_apktool_tree(tmp_path, SMALI_WITH_REFLECTION))
    assert len(result["reflective_calls"]) >= 1


def test_step17_extracts_methods_via_apktool_output_dir(tmp_path):
    result = cluster_family("sample", _apktool_tree(tmp_path, SMALI_TWO_METHODS), {"sample_id": "sample"})
    assert result["total_methods_extracted"] == 2
