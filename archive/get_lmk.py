from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)
a,d,dx=AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')
with open('lmk2.txt','w',encoding='utf-8',errors='ignore') as out:
    for c in dx.get_classes():
        if c.get_class().get_name()=='LVjAcb76OojLigvhwYH;':
            for m in c.get_class().get_methods():
                out.write(f"{m.get_name()} {m.get_descriptor()}\n")
                code=m.get_code()
                if code:
                    for ins in code.get_bc().get_instructions():
                        out.write(str(ins)+"\n")
                    out.write("---\n")
