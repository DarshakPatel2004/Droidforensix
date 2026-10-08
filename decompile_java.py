from androguard.misc import AnalyzeDex
from androguard.decompiler.decompiler import DecompilerDAD
import logging
logging.disable(logging.CRITICAL)
a,d,dx=AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')
# Find the three classes
for cls_name in ['LCZRR4ZREoGNpLeGZze;', 'LFtpOxqekIibXASlT37;', 'LVjAcb76OojLigvhwYH;']:
    for c in dx.get_classes():
        if c.get_class().get_name()==cls_name:
            print(f"Class {cls_name}")
            dad=DecompilerDAD(dx, c)
            # dad.process()
            # print(dad.get_source())
            # Try to get method source
            for m in c.get_class().get_methods():
                print(f" Method {m.get_name()} {m.get_descriptor()}")
                try:
                    ms = c.get_method_analysis(m)
                    # ms is MethodAnalysis
                    # try to get decompiled
                    pass
                except Exception:
                    # Narrowed from a bare except: this must not swallow
                    # KeyboardInterrupt and stop the operator cancelling.
                    pass
            # Use dx's get_method?
            break
