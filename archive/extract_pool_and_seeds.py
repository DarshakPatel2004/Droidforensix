from androguard.misc import AnalyzeDex
import logging
logging.disable(logging.CRITICAL)

a, d, dx = AnalyzeDex(r'D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload\installer_extracted\classes.dex')

# Extract the CJK pool from LCZRR4ZREoGNpLeGZze static field
with open('cjk_pool.txt', 'w', encoding='utf-8') as f:
    for c in dx.get_classes():
        cls = c.get_class()
        name = cls.get_name()
        if name == 'LCZRR4ZREoGNpLeGZze;':
            for field in cls.get_fields():
                fname = field.get_name()
                if fname == 'NkWaRdJEKEf58YYznc':
                    # Get the static field value
                    # We need to parse the DEX for the encoded array
                    f.write('Field: ' + fname + ' ' + field.get_descriptor() + '\n')
                    # Get the initial value from the class
                    fval = field.get_value()
                    if fval:
                        f.write('Value: ' + str(fval) + '\n')

# Also find all const-wide values used in calls to the decoder
# Search for invoke-static to LCZRR4ZREoGNpLeGZze.NkWaRdJEKEf58YYznc
with open('seed_constants.txt', 'w') as f:
    for c in dx.get_classes():
        cls = c.get_class()
        for method in cls.get_methods():
            code = method.get_code()
            if code:
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