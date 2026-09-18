from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)

a, d, dx = AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')

# Find the LCZRR4ZREoGNpLeGZze class and its <clinit>
with open('clzrr_clinit.txt', 'w', encoding='utf-8') as f:
    for c in dx.get_classes():
        cls = c.get_class()
        name = cls.get_name()
        if name == 'LCZRR4ZREoGNpLeGZze;':
            f.write(f'Found class: {name}\n')
            for method in cls.get_methods():
                mname = method.get_name()
                if mname == '<clinit>':
                    f.write(f'Method: {mname} {method.get_descriptor()}\n')
                    code = method.get_code()
                    if code:
                        bc = code.get_bc()
                        for ins in bc.get_instructions():
                            f.write(str(ins) + '\n')
                    break
            break