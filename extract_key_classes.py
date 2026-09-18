from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)

a, d, dx = AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')

# Find the key classes
with open('key_classes.txt', 'w') as f:
    for c in dx.get_classes():
        cls = c.get_class()
        name = cls.get_name()
        if name in ['LVjAcb76OojLigvhwYH;', 'LFtpOxqekIibXASlT37;', 'LCZRR4ZREoGNpLeGZze;']:
            f.write('Found class: ' + name + '\n')
            for method in cls.get_methods():
                mname = method.get_name()
                if 'NkWaRdJEKEf58YYznc' in mname or 'OhM1VWC9IUcLWN7TO0' in mname:
                    f.write('Method: ' + mname + ' ' + method.get_descriptor() + '\n')
                    code = method.get_code()
                    if code:
                        bc = code.get_bc()
                        for ins in bc.get_instructions():
                            f.write(str(ins) + '\n')
            f.write('\n')
        
        # Also find the CJK pool static field
        if name == 'LCZRR4ZREoGNpLeGZze;':
            for field in cls.get_fields():
                fname = field.get_name()
                f.write('Field: ' + fname + ' ' + field.get_descriptor() + '\n')