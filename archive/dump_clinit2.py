from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)
a,d,dx=AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')
with open('clinit2.txt','w',encoding='utf-8',errors='ignore') as out:
    for c in dx.get_classes():
        if c.get_class().get_name()=='LCZRR4ZREoGNpLeGZze;':
            for m in c.get_class().get_methods():
                if m.get_name()=='<clinit>':
                    code=m.get_code()
                    bc=code.get_bc()
                    for ins in bc.get_instructions():
                        out.write(f"{ins.get_name()} {ins.get_output()}\n")
                        if 'const-string' in ins.get_name():
                            try:
                                s=ins.get_string()
                                out.write(f"  -> len {len(s)} {s[:50]!r}\n")
                            except Exception as e:
                                out.write(f"  err {e}\n")
