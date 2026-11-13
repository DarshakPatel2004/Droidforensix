"""B2-03: the code view receives androguard disassembly, not Java source."""
from backend.code_analysis import _parse_method_bodies

DISASM = """// Disassembled DEX Class via Androguard
class com.x.Y {

    public <init>()V {
        invoke-direct   {v0}, Ljava/lang/Object;-><init>()V
        return-void
    }

    static <clinit>()V {
        const-string    v0, "/system/bin/su"
    }

    private sendSms(Ljava/lang/String;)V {
        invoke-static   {v0}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    }
}
"""


def test_parses_disassembly_headers_including_init_and_clinit():
    methods = _parse_method_bodies(DISASM)
    names = [m["name"] for m in methods]
    assert names == ["<init>", "<clinit>", "sendSms"]
    assert "getDefault" in methods[2]["body"]
    assert methods[1]["start_line"] < methods[2]["start_line"]


def test_java_source_still_parses():
    java = "public class A {\n    public void run() {\n        go();\n    }\n}\n"
    assert [m["name"] for m in _parse_method_bodies(java)] == ["run"]
