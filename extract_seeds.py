from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)

a, d, dx = AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')

# Find all const-wide values used in calls to the decoder
with open('seed_constants.txt', 'w') as f:
    for c in dx.get_classes():
        cls = c.get_class()
        # Check if it's an external class
        cls_name = cls.get_name()
        if cls_name.startswith('L') and cls_name.endswith(';') and len(cls_name) < 100:
            # Likely internal
            pass
        for method in cls.get_methods():
            if hasattr(method, 'get_code'):
                code = method.get_code()
                if code is not None:
                    bc = code.get_bc()
                    insns = list(bc.get_instructions())
                    for i, ins in enumerate(insns):
                        ins_str = str(ins)
                        if 'invoke-static' in ins_str and 'LCZRR4ZREoGNpLeGZze;->NkWaRdJEKEf58YYznc' in ins_str:
                            # Look backwards for const-wide
                            for j in range(max(0, i-10), i):
                                prev = str(insns[j])
                                if 'const-wide' in prev:
                                    f.write(f'{cls.get_name()} {method.get_name()}: {prev} -> {ins_str}\n')
                                    break