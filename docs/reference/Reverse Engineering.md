# Trimmed Reverse Engineering

---

**Page 1**

x86 and x64

The x86 is little-endian architecture based on the Intel 8086 processor. For the
purpose of our chapter, x86 is the 32-bit implementation of the Intel architecture
(IA-32) as defined in the Intel Software Development Manual. Generally speaking,
it can operate in two modes: real and protected. Real mode is the processor state
when it is first powered on and only supports a 16-bit instruction set. Protected
mode is the processor state supporting virtual memory, paging, and other
features; it is the state in which modern operating systems execute. The 64-bit
extension of the architecture is called x64 or x86-64. This chapter discusses the
x86 architecture operating in protected mode.

x86 supports the concept of privilege separation through an abstraction called
ring level. The processor supports four ring levels, numbered from 0 to 3. (Rings
1 and 2 are not commonly used so they are not discussed here.) Ring 0 is the
highest privilege level and can modify all system settings. Ring 3 is the lowest
privileged level and can only read/modify a subset of system settings. Hence,
modern operating systems typically implement user/kernel privilege separation

---

**Page 2**

Chapter 1 = x86 and x64

by having user-mode applications run in ring 3, and the kernel in ring 0. The
ring level is encoded in the cs register and sometimes referred to as the current
privilege level (CPL) in official documentation.

This chapter discusses the x86/IA-32 architecture as defined in the Intel 64
and IA-32 Architectures Software Developer’s Manual, Volumes 1-3 (www. intel
.com/ content /www/us/en/processors/architectures-software-developer-

manuals.html).

Register Set and Data Types

When operating in protected mode, the x86 architecture has eight 32-bit general-
purpose registers (GPRs): EAX, EBX, ECX, EDX, EDI, ESI, EBP, and ESP. Some of
them can be further divided into 8- and 16-bit registers. The instruction pointer
is stored in the EIP register. The register set is illustrated in Figure 1-1. Table 1-1
describes some of these GPRs and how they are used.

31 15 7 0 31 15 0

| EAX | | EBP |
| AX | | BP |

[AH | AL | ESP |
ES| | | SP |

| S| | | EIP |

| ED| [ | EFLAGS |

DI |
Figure 1-1

Table 1-1: Some GPRs and Their Usage

REGISTER PURPOSE

ECX Counter in loops

ESI Source in string/memory operations
EDI Destination in string/memory operations
EBP Base frame pointer

ESP Stack pointer

---

**Page 3**

Chapter 1 = x86 and x64

The common data types are as follows:
m Bytes—8 bits. Examples: AL, BL, CL
m Word—16 bits. Examples: ax, Bx, cx
m Double word—32 bits. Examples: EAX, EBX, ECX

m™ Quad word—464 bits. While x86 does not have 64-bit GPRs, it can combine
two registers, usually EDx: EAX, and treat them as 64-bit values in some sce-
narios. For example, the RDTSC instruction writes a 64-bit value to EDX: EAX.

The 32-bit EFLAGS register is used to store the status of arithmetic operations
and other execution states (e.g., trap flag). For example, if the previous “add”
operation resulted in a zero, the zF flag will be set to 1. The flags in EFLAGS are
primarily used to implement conditional branching.

In addition to the GPRs, E1P, and EFLAGS, there are also registers that control
important low-level system mechanisms such as virtual memory, interrupts, and
debugging. For example, cro controls whether paging is on or off, cR2 contains
the linear address that caused a page fault, cR3 is the base address of a paging
data structure, and cr4 controls the hardware virtualization settings. DRO-DR7
are used to set memory breakpoints. We will come back to these registers later
in the “System Mechanism” section.

kee Although there are seven debug registers, the system allows only four mem-
ory breakpoints (DRO-DR3). The remaining registers are used for status.

There are also model-specific registers (MSRs). As the name implies, these
registers may vary between different processors by Intel and AMD. Each MSR
is identified by name and a 32-bit number, and read/written to through the
RDMSR/WRMSR instructions. They are accessible only to code running in ring 0 and
typically used to store special counters and implement low-level functionality.
For example, the SYSENTER instruction transfers execution to the address stored
in the IA32_SYSENTER_EIP MSR (0x176), which is usually the operating system’s
system call handler. MSRs are discussed throughout the book as they come up.

Instruction Set

The x86 instruction set allows a high level of flexibility in terms of data move-
ment between registers and memory. The movement can be classified into five
general methods:

m Immediate to register
m Register to register

m Immediate to memory

---

**Page 4**

Chapter 1 = x86 and x64

m Register to memory and vice versa

m Memory to memory

The first four methods are supported by all modern architectures, but the last
one is specific to x86. A classical RISC architecture like ARM can only read/write
data from/to memory with load/store instructions (LDR and STR, respectively);
for example, a simple operation like incrementing a value in memory requires
three instructions:

1. Read the data from memory to a register (LDR).

2. Add one to the register (ADD).

3. Write the register to memory (STR).

On x86, such an operation would require only one instruction (either INC or

ADD) because it can directly access memory. The Movs instruction can read and
write memory at the same time.

ARM
O01: 1B 68 LDR R3, [R3]
; read the value at address R3
02: 5A 1C ADDS R2, R3, #1
; add 1 to it
03: 1A 60 STR R2, [R3]

; write updated value back to address R3

x86

O01: FF 00 inc dword ptr [eax]
; directly increment value at address EAX

Another important characteristic is that x86 uses variable-length instruction
size: the instruction length can range from 1 to 15 bytes. On ARM, instructions
are either 2 or 4 bytes in length.

Syntax

Depending on the assembler/disassembler, there are two syntax notations for
x86 assembly code, Intel and AT&T:

Intel

mov ecx, AABBCCDDh
mov ecx, [eax]

mMOv €CX, E€axX

AT&T
movl SOxAABBCCDD, %ecx
movl (%eax), %ecx

movl %eax, %ecx

---

**Page 5**

Chapter 1 = x86 and x64

It is important to note that these are the same instructions but written differ-
ently. There are several differences between Intel and AT&T notation, but the
most notable ones are as follows:

m AT&T prefixes the register with %, and immediates with $. Intel does not
do this.

m AT&T adds a prefix to the instruction to indicate operation width. For
example, Movi (long), Movs (byte), etc. Intel does not do this.

m AT&T puts the source operand before the destination. Intel reverses the
order.

Disassemblers/assemblers and other reverse-engineering tools (IDA Pro,
OllyDbg, MASM, etc.) on Windows typically use Intel notation, whereas those
on UNIX frequently follow AT&T notation (GCC). In practice, Intel notation is
the dominant form and is used throughout this book.

Data Movement

Instructions operate on values that come from registers or main memory. The
most common instruction for moving data is Mov. The simplest usage is to move
a register or immediate to register. For example:

O01: BE 3F 00 OF OO mov esi, OFOO3Fh ; set ESI OxF003
02: 8B FL mov esi, ecx ; set ESI = ECX

The next common usage is to move data to/from memory. Similar to other
assembly language conventions, x86 uses square brackets ([] ) to indicate memory
access. (The only exception to this is the LEA instruction, which uses [] but does
not actually reference memory.) Memory access can be specified in several dif-
ferent ways, so we will begin with the simplest case:

Assembly

01: C7 00 01 00 00+ mov dword ptr [eax], 1
; set the memory at address EAX to 1

02: 8B 08 mov ecx, [eax]

; set ECX to the value at address EAX

03: 89 18 mov [eax], ebx

; set the memory at address EAX to EBX

04: 89 46 34 mov [esi+34h], eax

; set the memory address at (ESI+34) to EAX
05: 8B 46 34 mov eax, [esi+34h]

; set EAX to the value at address (EAX+34)
06: 8B 14 O1 mov edx, [ecx+eax]

; set EDX to the value at address (ECX+EAX)

---

**Page 6**

6 Chapter 1 = x86 and x64

Pseudo C
Ol: *eax = 1;
02: ecx = *eax;
03: *eax = ebx;
04: *(esi+34) = eax;
05: eax = *(e8i+34);

06: edx = *(ecx+eax) ;

These examples demonstrate memory access through a base register and
offset, where offset can be a register or immediate. This form is commonly used
to access structure members or data buffers at a location computed at runtime.
For example, suppose that Ecx points to a structure of type KDPc with the layout

kd> dt nt! KDPC

+0x000 Type

+0x001 Importance
+0x002
+0x004
+0x00C
+0x010
+0x014
+0x018
+0x01c

Number
DpchListEntry
DeferredRoutine
DeferredContext
SystemArgumentl
SystemArgument2
DpcData

UChar

UChar

Uint2B
_LIST_ENTRY
Ptr32
Ptr32
Ptr32
Ptr32
Ptr32

void
Void
Void
Void
Void

and used in the following context:

Assembly
O01: 8B 45 OC mov
02: 83 61 1C 00 and
03: 89 41 0C mov
04: 8B 45 10 mov
05: C7 01 13 01 00+ mov
06: 89 41 10 mov

Pseudo C

KDPC *p = ...;

NULL;
p->DeferredRoutine = ...;
*(int *)p = 0x113;
p->DeferredContext = ...;

p->DpcData =

[ebp+0Ch]
dword ptr [ecx+1Ch], 0
[ecx+0Ch], eax
[ebp+10h]
dword ptr
[ecx+10h] ,

eax,

eax,
[ecx], 113h

eax

Line 1 reads a value from memory and stores it in EAX. The DeferredRout ine
field is set to this value in line 3. Line 2 clears the DpcData field by AND’ing it

---

**Page 7**

Chapter 1 = x86 and x64

with 0. Line 4 reads another value from memory and stores it in EAX. The
DeferredContext field is set to this value in line 6.

Line 5 writes the double-word value 0x113 to the base of the structure. Why
does it write a double-word value at the base if the first field is only 1 byte in
size? Wouldn't that implicitly set the Importance and Number fields as well? The
answer is yes. Figure 1-2 shows the result of converting 0x113 to binary.

00000000 00000000 eaacc007 00010011
00000000 00000000 00000001 00010011
Number Importance Type
Figure 1-2

The Type field is set to 0x13 (bold bits), Importance is set to 0x1 (underlined
bits), and Number is set to 0x0 (the remaining bits). By writing one value, the code
managed to initialize three fields with a single instruction! The code could have
been written as follows:

O01: 8B 45 OC mov eax, [ebp+0Ch]

02: 83 61 1C 00 and dword ptr [ecx+1Ch], 0
03: 89 41 OC mov [ecx+0Ch], eax

04: 8B 45 10 mov eax, [ebp+10h]

05: Cé 01 13 mov byte ptr [ecx],13h

06: C6 41 01 01 mov byte ptr [ecx+1],1

07: 66 C7 41 02 00+ mov word ptr [ecx+2],0

08: 89 41 10 mov [ecx+10h], eax

The compiler decided to fold three instructions into one because it knew
the constants ahead of time and wants to save space. The three-instruction
version occupies 13 bytes (the extra byte in line 7 is not shown), whereas the
one-instruction version occupies 6 bytes. Another interesting observation is
that memory access can be done at three granularity levels: byte (line 5-6),
word (line 6), and double-word (line 1-4, 8). The default granularity is 4 bytes,
which can be changed to 1 or 2 bytes with an override prefix. In the example,
the override prefix bytes are C6 and 66 (italicized). Other prefixes are discussed
as they come up.

The next memory access form is commonly used to access array-type objects.
Generally, the format is as follows: [Base + Index * scale]. This is best understood
through examples:

01: 8B 34 B5 40 05+ mov esi, _KdLogBuffer [esi*4]

; always written as mov esi, [ KdLogBuffer + esi * 4]

; _KdLogBuffer is the base address of a global array and

; ESI is the index; we know that each element in the array
; is 4 bytes in length (hence the scaling factor)

---

**Page 8**

8

Chapter 1 = x86 and x64

02:

89

04 F7

mov [edi+esi*8], eax

; here is EDI is the array base address; ESI is the array

; index;

element size is 8.

In practice, this is observed in code looping over an array. For example:

Ol:
02:
03:
O04:
O05:
06:
O7:

08:
09:

Line 2 reads a double-word from offset +4 from EDI and then uses it as the
base address into an array in line 3; hence, you know that EDT is likely a struc-
ture that has an array at +4. Line 7 increments the index. Line 8 compares the
index against a value at offset +0 in the same structure. Given this info, this

8B
8B
85

74

43

3B
7C

47 04
04 98
Co

14

1F
DD

loop_start:
mov eax, [edi+4]
mov eax, [eax+ebx*4]
test eax, eax

jz short loc_7F627F
loc _7F627F:
inc ebx

cmp ebx, [edi]
31 short loop start

small loop can be decompiled as follows:

typedef struct _FOO

{

} FOO, *PFOO;

DWORD size;

// +0x00

DWORD array[...]; // +0x04

PFOO bar =

for

The MovsB/MOVSW/MOVSD instructions move data with 1-, 2-, or 4-byte granu-
larity between two memory addresses. They implicitly use EDI/ESI as the
destination/source address, respectively. In addition, they also automatically
update the source/destination address depending on the direction flag (DF) flag
in EFLAGS. If DF is 0, the addresses are decremented; otherwise, they are incre-
mented. These instructions are typically used to implement string or memory
copy functions when the length is known at compile time. In some cases, they
are accompanied by the REP prefix, which repeats an instruction up to ECx times.

(i
if

i < bar->size; i++) {

(bar->array[i] != 0) {

Consider the following example:

---

**Page 9**

Chapter 1 = x86 and x64

Assembly

01: BE 28 BS 41 00 mov esi, offset _RamdiskBootDiskGuid
; ESI = pointer to RamdiskBootDiskGuid

02: 8D BD 40 FF FF+ lea edi, [ebp-0Coh]

; EDI is an address somewhere on the stack

03: AS movsd

; copies 4 bytes from EDI to ESI; increment each by 4
04: AS movsd

; Same as above

05: AS movsd

; Save as above

06: A5 movsd

; same as above

Pseudo C
/* a GUID is 16-byte structure */
GUID RamDiskBootDiskGuid = ...; // global
GUID foo;

memcpy (&foo, &RamdiskBootDiskGuid, sizeof (GUID) );

Line 2 deserves some special attention. Although the LEA instruction uses
[], it actually does not read from a memory address; it simply evaluates the
expression in square brackets and puts the result in the destination register.
For example, if EBP were 0x1000, then EDI would be 0xF40 (=0x1000 — 0xC0)
after executing line 2. The point is that LEA does not access memory, despite
the misleading syntax.

The following example, from nt !KiInitSystem, uses the REP prefix:

O01: 6A 08 push 8 ; push 8 on the stack (will explain stacks
; later)

O02: ...

03: 59 pop ecx ; pop the stack. Basically sets ECX to 8.

04: oe

05: BE 00 44 61 00 mov esi, offset _KeServiceDescriptorTable

06: BF CO 43 61 00 mov edi, offset _KeServiceDescriptorTableShadow

07: F3 A5 rep movsd ; copy 32 bytes (movsd repeated 8 times)

; from this we can deduce that whatever these two objects are, they are
; likely to be 32 bytes in size.

The rough C equivalent of this would be as follows:

memcpy (&KeServiceDescriptorTableShadow, &KeServiceDescriptorTable, 32);

---

**Page 10**

10 Chapter 1 = x86 and x64

The final example, nt !MmInitializeProcessAddressSpace, uses a combina-
tion of these instructions because the copy size is not a multiple of 4:

01: 8D BO 70 01 00+ lea esi, [eax+170h]

; EAX is likely the base address of a structure. Remember what we said

; about LEA ...

02: 8D BB 70 01 00+ lea edi, [ebx+170h]

; EBX is likely to be base address of another structure of the same type

03: A5 movsd
04: AS movsd
05: A5 movsd
06: 66 A5 movsw
O07: A4 movsb

After lines 1-2, you know that £ax and EBx are likely to be of the same type
because they are being used as source/destination and the offset is identical.
This code snippet simply copies 15 bytes from one structure field to another.
Note that the code could also have been written using the Movss instruction
with a REP prefix and Ecx set to 15; however, that would be inefficient because
it results in 15 reads instead of only five.

Another class of data movement instructions with implicit source and destina-
tion includes the scas and sTos instructions. Similar to Movs, these instructions
can operate at 1-, 2-, or 4-byte granularity. Scas implicitly compares AL/AX/EAX
with data starting at the memory address EDI; EDI is automatically incremented/
decremented depending on the DF bit in FLAGS. Given its semantic, SCAS is com-
monly used along with the REP prefix to find a byte, word, or double-word in
a buffer. For example, the C strlen() function can be implemented as follows:

01: 30 CO xor al, al

; set AL to 0 (NUL byte). You will frequently observe the XOR reg, reg
; pattern in code.

02: 89 FB mov ebx, edi

; save the original pointer to the string

03: F2 AE repne scasb

; repeatedly scan forward one byte at a time as long as AL does not match the
; byte at EDI when this instruction ends, it means we reached the NUL byte in
; the string buffer

04: 29 DF sub edi, ebx

; edi is now the NUL byte location. Subtract that from the original pointer

; to the length.

STos is the same as scas except that it writes the value AL/AX/EAX to EDI. It
is commonly used to initialize a buffer to a constant value (such as memset () ).
Here is an example:

01: 33 CO xor eax, eax
; set EAX to 0
02: 6A 09 push 9

; push 9 on the stack
03: 59 pop ecx
; pop it back in ECX. Now ECX = 9.

---

**Page 11**

Chapter 1 = x86 and x64

11

04: 8B FE mov edi, esi
; set the destination address
05: F3 AB rep stosd

; write 36 bytes of zero to the destination buffer (STOSD repeated 9 times)
; this is equivalent lent to memset (edi, 0, 36)

LODS is another instruction from the same family. It reads a 1-, 2-, or 4-byte
value from ESI and stores it in AL, AX, or EAX.

Exercise

1. This function uses a combination scas and sTos to do its work. First, explain
what is the type of the [EBP+8] and [EBP+C] in line 1 and 8, respectively.
Next, explain what this snippet does.

01: 8B 7D 08 mov edi, [ebp+8]
02: 8B D7 mov edx, edi

03: 33 CO xor eax, eax

04: 83 C9 FF or ecx, OFFFFFFFFh
05: F2 AE repne scasb

06: 83 Cl 02 add ecx, 2

07: F7 D9 neg ecx

08: 8A 45 OC mov al, [ebp+0Ch]
09: 8B FA mov edi, edx

10: F3 AA rep stosb

11: 8B C2 mov eax, edx

Arithmetic Operations

Fundamental arithmetic operations such as addition, subtraction, multiplication,
and division are natively supported by the instruction set. Bit-level operations
such as AND, OR, XOR, NOT, and left and right shift also have native corresponding
instructions. With the exception of multiplication and division, the remain-
ing instructions are straightforward in terms of usage. These operations are
explained with the following examples:

O01: 83 C4 14 add esp, 14h ; esp = esp + 0x14

02: 2B C8 sub ecx, eax 7; ecx = ecx - eax

03: 83 EC OC sub esp, OCh ; esp = esp - OxC

04: 41 inc ecx ; ecx = ecx +1

05: 4F dec edi ; edi = edi - 1

06: 83 C8 FF or eax, OFFFFFFFFh ; eax = eax | OxXFFFFFFFF
07: 83 El O07 and ecx, 7 ; eck = ecx & 7

08: 33 CO xor eax, eax ; eax = eax * eax

09: F7 D7 not edi ; edi = ~edi

10: CO El 04 shl cl, 4 ; cl =cl << 4

11: Dl E9 shr ecx, 1 ; eck = ecx >> 1

12: CO CO 03 rol al, 3 ; rotate AL left 3 positions

13: DO C8 ror al, 1 ; rotate AL right 1 position

---

**Page 12**

12

Chapter 1 = x86 and x64

The left and right shift instructions (lines 11-12) merit some explanation, as
they are frequently observed in real-life code. These instructions are typically
used to optimize multiplication and division operations where the multiplicand
and divisor are a power of two. This type of optimization is sometimes known
as strength reduction because it replaces a computationally expensive operation
with a cheaper one. For example, integer division is relatively a slow operation,
but when the divisor is a power of two, it can be reduced to shifting bits to the
right; 100/2 is the same as 100>>1. Similarly, multiplication by a power of two
can be reduced to shifting bits to the left; 100*2 is the same as 100<<1.

Unsigned and signed multiplication is done through the mut and IMuL instruc-
tions, respectively. The MUL instruction has the following general form: MUL reg/
memory. That is, it can only operate on register or memory values. The register
is multiplied with AL, Ax, or EAX and the result is stored in Ax, DX: AX, Or EDX: EAX,
depending on the operand width. For example:

Ol: F7 El mul ecx ; EDX:EAX = EAX * ECX

02: F7 66 04 mul dword ptr [esi+4] ; EDX:EAX = EAX * dword_at (ESI+4)
03: Fé El mul cl ; AX = AL * CL

04: 66 F7 E2 mul dx ; DX:AX = AX * DX

Consider a few other concrete examples:

01: B8 03 00 00 O00 mov eax,3 ; set EAX=3
02: BO 22 22 22 22 mov ecx,22222222h ; set ECX=0x22222222
03: F7 El mul ecx ; EDX:EAX = 3 * 0X22222222 =
; 0x66666666
; hence, EDX=0, EAX=0x66666666
04: B8 03 00 00 OO mov eax,3 ; set EAX=3
05: B9 00 00 00 80 mov ecx,80000000h ; set ECX=0x80000000
06: F7 EL mul ecx ; EDX:EAX = 3 * 0x80000000 =
; 0x180000000

; hence, EDX=1, EAX=0x80000000

The reason why the result is stored in EDx: Ax for 32-bit multiplication is
because the result potentially may not fit in one 32-bit register (as demonstrated
in lines 4-6).

IMUL has three forms:

m IMUL reg/mem — Same as MUL

m IMUL regl1, reg2/mem — regi = reg1 * reg2/mem

m IMUL reg, reg2/mem, imm — regi = reg2 * imm
Some disassemblers shorten the parameters. For example:

Ol: F7 E9 imul ecx ; EDX:EAX = EAX * ECX
02: 69 F6é AO 01 00+ imul esi, 1A0h ; ESI = ESI * O0x1A0

---

**Page 13**

Chapter 1 = x86 and x64

13

03: OF AF CE imul ecx, esi ; ECX = ECX * ESI

Unsigned and signed division is done through the Div and IDIv instructions,
respectively. They take only one parameter (divisor) and have the following
form: DIV/IDIv reg/mem. Depending on the divisor’s size, DIv will use either
AX, DX: AX, Or EDX: EAX as the dividend, and the resulting quotient/remainder
pair are stored in AL/AH, AX/DX, Or EAX/EDX. For example:

O01: F7 Fl div ecx ; EDX:EAX / ECX, quotient in EAX,

02: F6 Fl div cl ; AX / CL, quotient in AL, remainder in AH

03: F7 76 24 div dword ptr [esi+24h] ; see line 1

04: Bl 02 mov cl,2 ; set CL = 2

05: B8 OA 00 O00 O00 mov eax,O0Ah ; set EAX = OxA

06: F6 Fl div el ; AX/CL = A/2 = 5 in AL (quotient),
; AH = 0 (remainder)

07: Bl 02 mov cl,2 ; set CL = 2

08: B8 09 00 00 O00 mov eax,09h ; set EAX = 0x9

09: F6 Fl div cl ; AX/CL = 9/2 = 4 in AL (quotient),
; AH = 1 (remainder)

Stack Operations and Function Invocation

The stack is a fundamental data structure in programming languages and operat-
ing systems. For example, local variables in C are stored on the functions’ stack
space. When the operating system transitions from ring 3 to ring 0, it saves state
information on the stack. Conceptually, a stack is a last-in first-out data structure
supporting two operations: push and pop. Push means to put something on top
of the stack; pop means to remove an item from the top. Concretely speaking,
on x86, a stack is a contiguous memory region pointed to by Esp and it grows
downwards. Push/pop operations are done through the PUSH/POP instruc-
tions and they implicitly modify Esp. The PUSH instruction decrements Esp
and then writes data at the location pointed to by Esp; POP reads the data and
increments ESP. The default auto-increment/decrement value is 4, but it can be
changed to 1 or 2 with a prefix override. In practice, the value is almost always
4 because the OS requires the stack to be double-word aligned.

Suppose that Esp initially points to 0xb20000 and you have the following code:

; initial ESP = 0xb20000

01: B8 AA AA AA AA mov eax, OAAAAAAAAN
02: BB BB BB BB BB mov ebx, OBBBBBBBBh
03: B9 CC CC CC CC mov ecx, OCCCCCCCCh
04: BA DD DD DD DD mov edx, ODDDDDDDDh
05: 50 push eax

; address Oxbifffc will contain the value OxAAAAAAAA and ESP
; will be Oxblifffc (=0xb20000-4)

---

**Page 14**

14 Chapter 1 = x86 and x64

06: 53 push ebx
; address Oxbifff8 will contain the value OxBBBBBBBB and ESP
; will be Oxbifff8 (=0xbifffc-4)

07: 5E pop esi

; ESI will contain the value OxBBBBBBBB and ESP will be Oxbifffc
; (=Oxb1lf£££8+4)

08: 5SF pop edi

; EDI will contain the value OxAAAAAAAA and ESP will be 0xb20000
; (=Oxblfffic+4)

Figure 1-3 illustrates the stack layout.

ESP “eo N ESP
0420000 Ts aoe ogy LAAAAAAAA ae eee. BBBBBBBB
x Xx. Cc
push eax push ebx 0xb20000 AAAAAAAA
—>- ee ——————_- vee
>
<
ESP ESP
Oxbifff
0xb20000 — x Cc AAAAAAAA
0xb20000
op edi
pop
Figure 1-3

ESP can also be directly modified by other instructions, such as ADD and SUB.

While high-level programming languages have the concept of functions that
can be called and returned from, the processor does not provide such abstrac-
tion. At the lowest level, the processor operates only on concrete objects, such
as registers or data coming from memory. How are functions translated at the
machine level? They are implemented through the stack data structure! Consider
the following function:

Cc
int

__cdecl addme(short a, short b)

{

return a+b;

}

Assembly

O01: 004113A0 55 push ebp

---

**Page 15**

Chapter 1 = x86 and x64

15

02: 004113A1 8B EC mov ebp, esp

O03: ...

04: 004113BE OF BF 45 08 movsx eax, word ptr [ebp+8]
05: 004113C2 OF BF 4D 0C movsx ecx, word ptr [ebp+0Ch]

06: 004113C6 03 Cl add eax, eCX
O7: ...

08: 004113CB 8B E5 mov esp, ebp
09: 004113CD 5D pop ebp

10: 004113CE C3 retn

The function is invoked with the following code:

Cc
sum = addme(x, y);

Assembly
O01: 004129F3 50 push eax
O02: ...
03: 004129F8 51 push ecx
04: 004129F9 E8 Fl E7 FF FF call addme
05: 004129FE 83 C4 08 add esp, 8

Before going into the details, first consider the CALL/RET instructions and
calling conventions. The CALL instruction performs two operations:

1. It pushes the return address (address immediately after the CALL instruc-
tion) on the stack.

2. It changes EIP to the call destination. This effectively transfers control to
the call target and begins execution there.

RET simply pops the address stored on the top of the stack into EIP and trans-
fers control to it (literally like a “Pop EIp” but such instruction sequence does
not exist on x86). For example, if you want to begin execution at 0x12345678,
you can just do the following:

O1: 68 78 56 34 12 push 0x12345678
02: C3 ret

A calling convention is a set of rules dictating how function calls work at the
machine level. It is defined by the Application Binary Interface (ABI) for a par-
ticular system. For example, should the parameters be passed through the stack,
in registers, or both? Should the parameters be passed in from left-to-right or
right-to-left? Should the return value be stored on the stack, in registers, or both?
There are many calling conventions, but the popular ones are CDECL, STDCALL,
THISCALL, and FASTCALL. (The compiler can also generate its own custom call-
ing convention, but those will not be discussed here.) Table 1-2 summarizes
their semantic.

---

**Page 16**

16

Chapter 1 = x86 and x64

Table 1-2: Calling Conventions

CDECL STDCALL FASTCALL

Parameters Pushed on the Same as CDECL First two parameters are
stack from right- except that the passed in ECX and EDX. The
to-left. Caller must — callee must clean rest are on the stack.

cleanup thestack — the stack.
after the call.

Return value Stored in FAX. Stored in FAX. Stored in EAX.
Non-volatile EBP, ESP, EBX, EBP, ESP, EBX, EBP, ESP, EBX, EST, EDI.
registers ESI, EDI. ESI, EDI.

We now return to the code snippet to discuss how the function addme is
invoked. In line 1 and 3, the two parameters are pushed on the stack; Ecx and
EAX are the first and second parameter, respectively. Line 4 invokes the addme
function with the cALL instruction. This immediately pushes the return address,
0x4129FE, on the stack and begins execution at 0x4113A0. Figure 1-4 illustrates
the stack layout after line 4 is executed.

ESP
0041 29FE
ECX
EAX
Figure 1-4

After line 4 executes, we are now in the addme function body. Line 1 pushes
EBP on the stack. Line 2 sets EBP to the current stack pointer. This two-instruction
sequence is typically known as the function prologue because it establishes a new
function frame. Line 4 reads the value at address EBP+8, which is the first param-
eter on the stack; line 5 reads the second parameter. Note that the parameters
are accessed using EBP as the base register. When used in this context, EBP is
known as the base frame pointer (see line 2) because it points to the stack frame
for the current function, and parameters/locals can be accessed relative to it.
The compiler can also be instructed to generate code that does not use EBP as
the base frame pointer through an optimization called frame pointer omission.
With such optimization, access to local variables and parameters is done rela-
tive to ESP, and EBP can be used as a general register like EAX, EBX, ECX, and so
on. Line 6 adds the numbers and saves the result in EAx. Line 8 sets the stack
pointer to the base frame pointer. Line 9 pops the saved EBP from line 1 into

---

**Page 17**

Chapter 1 = x86 and x64

17

EBP. This two-instruction sequence is commonly referred to as the function epi-
logue because it is at the end of the function and restores the previous function
frame. At this point, the top of the stack contains the return address saved by
the CALL instruction at 0x4129P9. Line 10 performs a RET, which pops the stack
and resumes execution at 0x4129FE. Line 5 in the snippet shrinks the stack by
8 because the caller must clean up the stack per CDECL's calling convention.

If the function addme had local variables, the code would need to grow the
stack by subtracting Esp after line 2. All local variables would then be accessible
through a negative offset from EBP.

Exercises

1. Given what you learned about cALL and RET, explain how you would read
the value of EIP? Why can’t you just do Mov EAX, EIP?

2. Come up with at least two code sequences to set EIP to OXAABBCCDD.

3. In the example function, addme, what would happen if the stack pointer
were not properly restored before executing RET?

4. In all of the calling conventions explained, the return value is stored in a
32-bit register (EAx). What happens when the return value does not fit ina
32-bit register? Write a program to experiment and evaluate your answer.
Does the mechanism change from compiler to compiler?

Control Flow

This section describes how the system implements conditional execution for
higher-level constructs like if/else, switch/case, and while/for. All of these are
implemented through the cmp, TEST, UMP, and Jcc instructions and EFLAGS reg-
ister. The following list summarizes the common flags in EFLAGS:

m ZF/Zero flag—Set if the result of the previous arithmetic operation is zero.
m SF/Sign flag—Set to the most significant bit of the result.

m CF/Carry flag—Set when the result requires a carry. It applies to unsigned
numbers.

m OF/Overflow flag—Set if the result overflows the max size. It applies to
signed numbers.

Arithmetic instructions update these flags based on the result. For example,
the instruction SUB EAX, EAX would cause ZF to be set. The Jcc instructions,
where “cc” is a conditional code, changes control flow depending on these

---

**Page 18**

18

Chapter

1= x86 and x64

flags. There can be up to 16 conditional codes, but the most common ones are
described in Table 1-3.

Table 1-3: Common Conditional Codes

CONDITIONAL MACHINE
CODE ENGLISH DESCRIPTION DESCRIPTION
B/NAE Below/Neither Above nor Equal. Used for CF=1
unsigned operations.
NB/AE Not Below/Above or Equal. Used for CF=0
unsigned operations.
E/Z Equal/Zero ZF=1
NE/NZ Not Equal/Not Zero ZF=0
L Less than/Neither Greater nor Equal. Used (SF 4 OF) =1
for signed operations.
GE/NL Greater or Equal/Not Less than. Used for (SF 4 OF) =0
signed operations.
G/NLE Greater/Not Less nor Equal. Used for ((SF 4 OF) | ZF) =0

signed operations.

Because assembly language does not have a defined type system, one of the
few ways to recognize signed/unsigned types is through these conditional codes.
The cmp instruction compares two operands and sets the appropriate condi-
tional code in EFLAGS; it compares two numbers by subtracting one from another
without updating the result. The TEST instruction does the same thing except
it performs a logical AND between the two operands.

If-Else

If-else constructs are quite simple to recognize because they involve a compare/
test followed by a Jcc. For example:

Assembly

Ol:
02:
03:
04:
O05:
06:
O7:
08:
09:
10:

mov
mov
test
jz
mov
call
and
lea
push
call

esi, [ebp+8]

edx, [esi]

edx, edx

short loc_4E31F9

ecx, offset _FsRtlFastMutexLookasideList
_ExFreeToNPagedLookasideList@8

dword ptr [esi], 0

eax, [esi+4]

eax

_FsRtlUninitializeBaseMcb@4

11: loc_4E31F9:

---

**Page 19**

Chapter 1 = x86 and x64

19

12: pop esi

13: pop ebp

14: retn 4

15: FsRtlUninitializeLargeMcb@4 endp

Pseudo C

if (*esi == 0) {
return;

}

ExFreeToNPagedLookasideList(...);

*esi = 0;
return;

OR

if (*esi != 0) {

ExFreeToNPagedLookasideList(...);
*esi = 0;

}

return;

Line 2 reads a value at location ESI and stores it in EDx. Line 3 ANDs EDX with
itself and sets the appropriate flags in EFLacs. Note that this pattern is commonly
used to determine whether a register is zero. Line 4 jumps to loc_4E31F9 (line 12)
if ZF=1. If ZF=0, then it executes line 5 and continues until the function returns.

Note that there are two slightly different but logically equivalent C transla-
tions for this snippet.

Switch-Case

A switch-case block is a sequence of if/else statements. For example:

Switch-Case
switch(ch) {

case 'c!:
handle _C();
break;

case 'h':
handle_H();
break;

default:
break;

}

domore () ;

---

**Page 20**

20 Chapter 1 = x86 and x64

If-Else

if (ch == 'c') {
handle _C()j;

} else

if (ch == th') {
handle _H();

}

domore () ;

Hence, the machine code translation will be a series if/else. The following
simple example illustrates the idea:

Assembly
Ol: push ebp
02: mov ebp, esp
03: mov eax, [ebp+8]
04: sub eax, 41h
OS: jz short loc_caseA
06: dec eax
O07: jz short loc_caseB
08: dec eax
09: jz short loc_caseC
10: mov al, 5Ah
11: movzx eax, al

12: pop ebp

13: retn

14: loc_caseC:

15: mov al, 43h
16: movzx eax, al

17: pop ebp

18: retn

19: loc_caseB:

20: mov al, 42h
21: movzx eax, al

22: pop ebp

23: retn

24: loc_caseA:

25: mov al, 41h
26: movzx eax, al

27: pop ebp
28: retn

unsigned char switchme(int a)

{

unsigned char res;

---

**Page 21**

Chapter 1

x86 and x64

21

Real-life switch-case statements can be more complex, and compilers commonly

switch(a) {
case 0x41:
res = 'A';
break;
case 0x42:
res = 'B';
break;
case 0x43:
res = 'C';
break;
default:
res = 'Z';
break;

}

return res;

build a jump table to reduce the number of comparisons and conditional jumps.
The jump table is essentially an array of addresses, each pointing to the handler
for a specific case. This pattern can be observed in Sample J in sub_10001110:

Assembly
Ol: cmp edi, 5
02: ja short loc_10001141
03: jmp ds:off_100011A4 [edi*4]
04: loc_10001125:
05: mov esi, 40h
06: jmp short loc_10001145
07: loc_1000112¢c:
08: mov esi, 20h
09: jmp short loc_10001145
10: loc_10001133:
11: mov esi, 38h
12: jmp short loc_10001145
13: loc_1000113A:
14: mov esi, 30h
15: jmp short loc_10001145
16: loc_10001141:
17: mov esi, [esp+0Ch]
18: ...
19: off 100011A4 dd offset loc_10001125
20: dd offset loc_10001125
21: dd offset loc_1000113A
22: dd offset loc_1000112C
23: dd offset loc_10001133
24: dd offset loc_1000113A

---

**Page 22**

22 Chapter 1 = x86 and x64

Pseudo C
switch(edi) {

case 0:

case 1:
// goto loc_10001125;
esi = 0x40;
break;

case 2:

case 5:
// goto loc_1000113A;
esi = 0x30;
break;

case 3:
// goto loc_1000112C;
esi = 0x20;
break;

case 4:
// goto loc_10001133;
esi = 0x38;
break;

default:
// goto loc_10001141;
esi = *(esp+0xC)
break;

Here, the compiler knows that there are only five cases and the case value
is consecutive; hence, it can construct the jump table and index into it directly
(line 3). Without the jump table, there would be 10 additional instructions to
test each case and branch to the handler. (There are other forms of switch/case
optimizations, but we will not cover them here.)

Loops

At the machine level, loops are implemented using a combination of Jcc and
JMP instructions. In other words, they are implemented using if/else and goto
constructs. The best way to understand this is to rewrite a loop using only if/
else and goto. Consider the following example:

Using for

for (int i=0; i<10; i++) {
print£("Sd\n", i);

}

printf ("done!\n") ;

---

**Page 23**

Chapter 1 = x86 and x64

23

Using if/else and goto
int i = 0;
loop_start:
if (i < 10) {
printf ("Sd\n", i);
L++;
goto loop start;

}

printf ("done!n") ;

When compiled, both versions are identical at the machine-code level:

01: 00401002 mov edi, ds: imp _ printf
02: 00401008 xor esi, esi
03: 0040100A lea ebx, [ebx+0]

04: 00401010 loc 401010:
05: 00401010 push esi

06: 00401011 push offset Format ; "Sd\n"
07: 00401016 call edi ; __imp_ printf

08: 00401018 inc esi

09: 00401019 add esp, 8

10: 0040101C cmp esi, OAh

11: 0040101F ji short loc_401010

12: 00401021 push offset aDone ; "done!\n"
13: 00401026 call edi ; __imp_ printf

14: 00401028 add esp, 4

Line 1 sets EDI to the printf function. Line 2 sets ESI to 0. Line 4 begins
the loop; however, note that it does not begin with a comparison. There is no
comparison here because the compiler knows that the counter was initialized
to 0 (see line 2) and is obviously going to be less than 10 so it skips the check.
Lines 5-7 call the print£ function with the right parameters (format specifier
and our number). Line 8 increments the number. Line 9 cleans up the stack
because printf uses the CDECL calling convention. Line 10 checks to see if the
counter is less than OxA. If it is, it jumps back to loc_401010. If the counter is
not less than OxA, it continues execution at line 12 and finishes with a print é£.

One important observation to make is that the disassembly allowed us to
infer that the counter is a signed integer. Line 11 uses the “less than” conditional
code (JL), so we immediately know that the comparison was done on signed
integers. Remember: If “above/below,” it is unsigned; if “less than/greater than,”
it is signed. Sample L has a small function, sub_1000AE3B, with the following
interesting loop:

Assembly

01: sub_1000AE3B proc near
02: push edi

---

**Page 24**

24 Chapter 1 = x86 and x64

03: push esi

04: call ds:lstrlenA

05: mov edi, eax

06: xor ecx, eCx

O7: xor edx, edx

O08: test edi, edi

09: jie short loc_1000AE5B
10: loc_1000AE4D:

11: mov al, [edx+esi]

12: mov [ecx+esi], al

13: add edx, 3

14: inc ecx

15: cmp edx, edi

16: ji short loc_1000AE4D
17: loc_1000AES5B:

18: mov byte ptr [ecx+esi], 0
19: mov eax, esi

20: pop edi

21: retn

22: sub_1000AE3B endp

char *sub_1000AE3B (char *str)

{
int len, i=0, j=0;
len = lstrlenA(str);
if (len <= 0) {
str[j] = 0;
return str;

}

while (j < len) {
str[i] = str{[jl;
J = j+3;
i = itl;

}

str[i] = 0;

return str;

The sub_1000AE3B function has one parameter passed using a custom calling
convention (ESI holds the parameter). Line 2 saves EDI. Line 3 calls lstrlena
with the parameter; hence, you immediately know that Es1 is of type char *.
Line 5 saves the return value (string length) in Epr1. Lines 6—7 clear Ecx and
EDx. Lines 8-9 check to see if the string length is less than or equal to zero. If it
is, control is transferred to line 18, which sets the value at ECX+ESI to O. If it is
not, then execution is continued at line 11, which is the start of a loop. First, it
reads the character at ESI+EDx (line 11), and then it stores it at ESI+Ecx (line 12).

---

**Page 25**

Chapter 1 = x86 and x64

25

Next, it increments the EDx and Ecx by three and one, respectively. Lines 15-16
check to see if EDx is less than the string length; if so, execution goes back to
the loop start. If not, execution is continued at line 18.

It may seem convoluted at first, but this function takes an obfuscated string
whose deobfuscated value is every third character. For example, the string sx]
OTYFKPTY*W\\aAFKRW\\E is actually SorTwaRE. The purpose of this function
is to prevent naive string scanners and evade detection. As an exercise, you
should decompile this function so that it looks more “natural” (as opposed to
our literal translation).

Outside of the normal Jcc constructs, certain loops can be implemented using
the Loop instruction. The Loop instruction executes a block of code up to Ecx
time. For example:

Assembly
O01: 8B CA mov ecx, edx
02: loc_CFB8F:
03: AD lodsd
04: F7 DO not eax
05: AB stosd
06: E2 FA loop loc_CFB8F
Rough C
while (ecx != 0) {
eax = *edi;
edi++;
*esi = ~eax;

esit++;
eCX--;

}

Line 1 reads the counter from Ebx. Line 3 is the loop start; it reads in a double-
word at the memory address EDI and saves that in £Ax; it also increments EDI
by 4. Line 4 performs the Not operator on the value just read. Line 5 writes the
modified value to the memory address Es1 and increments EsI by 4. Line 6
checks to see if Ecx is 0; if not, execution is continued at the loop start.

System Mechanism

The previous sections explain mechanisms and instructions that are available to
code running at all privilege levels. To get a better appreciation of the architec-
ture, this section discusses two fundamental system-level mechanisms: virtual
address translation and exception/interrupt handling. You may skip this section on
a first read.

---

**Page 26**

26

Chapter 1 = x86 and x64

Address Translation

The physical memory on a computer system is divided into 4KB units called
pages. (A page can be more than 4KB, but we will not discuss the other sizes
here.) Memory addresses are divided into two categories: virtual and physical.
Virtual addresses are those used by instructions executed in the processor when
paging is enabled. For example:
O01: Al 78 56 34 12 mov eax, [0x12345678]; read memory at the virtual
; address 0x12345678

01: 89 08 mov [eax], ecx ; write ECX at the virtual
; address EAX

Physical addresses are the actual memory locations used by the processor
when accessing memory. The processor’s memory management unit (MMU)
transparently translates every virtual address into a physical address before
accessing it. While a virtual address may seem like just another number to the
user, there is a structure to it when viewed by the MMU. On x86 systems with
physical address extension (PAE) support, a virtual memory address can be
divided into indices into three tables and offset: page directory pointer table
(PDPT), page directory (PD), page table (PT), and page table entry (PTE). A PDPT
is an array of four 8-byte elements, each pointing to a PD. A PD is an array of
512 8-byte elements, each pointing to a PT. A PT is an array of 512 8-byte ele-
ments each containing a PTE. For example, the virtual address 0xBF80EE6B can
be understood as shown in Figure 1-5.

OxBF80EE6B
10111111 10000000 11101110 01101011
10 (0x2) 111111 100 00000 1110 (0xE) 1110 01101011
(Ox1FC) (OxE6B)
2 bits 9 bits 9 bits 12 bits
Index into PDPT Index into PD Index into PT Page offset

Figure 1-5

The 8-byte elements in these tables contain data about the tables, memory
permission, and other memory characteristics. For example, there are bits that
determine whether the page is read-only or readable/writable, executable or
non-executable, accessible by user or not, and so on.

The address translation process revolves around these three tables and the
CR3 register. CR3 holds the physical base address of the PDPT. The rest of this
section walks through the translation of the virtual address 0xBF80EE6B on a
real system (refer to Figure 1-5):

kd> r @cr3 ; CR3 is the physical address for the base of a PDPT
cr3=085c01e0
kd> !dq @cr3+2*8 Ll ; read the PDPT entry at index 2

# 85c01£0 00000000°>0d66e001

---

**Page 27**

Chapter 1 = x86 and x64

27

Per the documentation, the bottom 12 bits of a PDPT entry are flags/reserved
bits, and the remaining ones are used as the physical address of the PD base.
Bit 63 is the nx flag in PAE, so you will also need to clear that as well. In this
particular example, we did not clear it because it is already 0. (We are looking
at code pages that are executable.)

; 0x00000000-0d66e001 = 00001101 01100110 11100000 00000001

; after clearing the bottom 12 bits, we have

; Ox0d66e000 = 00001101 01100110 11100000 00000000

; This tells us that the PD base is at physical address 0x0d66e000
kd> !dq 0d66e000+0x1fc*8 Lil ; read the PD entry at index 0x1FC

# d6é6efed0 00000000°0964b063

Again, per the documentation, the bottom 12 bits of a PD entry are used for
flags/reserved bits, and the remaining ones are used as the base for the PT:

; 0x0964b063 = 00001001 01100100 10110000 01100011

; after clearing the bottom 12 bits, we get

; 0x0964b000 = 00001001 01100100 10110000 00000000

; This tells us that the PT base is at 0x0964b000

kd> !dq 0964b000+e*8 L1 ; read the PT entry at index OxE
# 964b070 00000000~ 06694021

Again, the bottom 12 bits can be cleared to get to the base of a page entry:

; 0x06694021 = 00000110 01101001 01000000 00100001

; after clearing bottom 12 bits, we get

; 0x06694000 = 00000110 01101001 01000000 00000000

; This tells us that the page entry base is at 0x06694000

kd> !db 06694000+e6b L8 ; read 8 bytes from the page entry at offset

OxE6B

# 6694e6b 8b ff 55 8b ec 83 ec Oc ..U..... [) te... ; our data at that
; physical page

kd> db bf80ee6b L8 ; read 8 bytes from the virtual address

bf80ee6b 8b ££ 55 8b ec 83 ec ..U..... [) .t.... ; same data!

After the entire process, it is determined that the virtual address OxBF80EE6B
translates to the physical address 0x6694E6B.

Modern operating systems implement process address space separation using
this mechanism. Every process is associated with a different cRr3, resulting in
process-specific virtual address translation. It is the magic behind each pro-
cess’s illusion that it has its own address space. Hopefully you will have more
appreciation for the processor the next time your program accesses memory!

Interrupts and Exceptions

This section briefly discusses interrupts and exceptions, as complete implemen-
tation details can be found in Chapter 3, “The Windows Kernel.”

In contemporary computing systems, the processor is typically connected to
peripheral devices through a data bus such as PCI Express, FireWire, or USB.

---

**Page 28**

28

Chapter 1 = x86 and x64

When a device requires the processor’s attention, it causes an interrupt that
forces the processor to pause whatever it is doing and handle the device’s request.
How does the processor know how to handle the request? At the highest level,
one can think of an interrupt as being associated with a number that is then
used to index into an array of function pointers. When the processor receives
the interrupt, it executes the function at the index associated with the interrupt
and resumes execution at wherever it was before the interrupt occurred. These
are called hardware interrupts because they are generated by hardware devices.
They are asynchronous by nature.

When the processor is executing an instruction, it may run into exceptions.
For example, an instruction could generate a divide-by-zero error, reference an
invalid address, or trigger a privilege level transition. For the purpose of this
discussion, exceptions can be classified into two categories: faults and traps. A
fault is a correctable exception. For example, when the processor executes an
instruction that references a valid memory address but the data is not present
in main memory (it was paged out), a page fault exception is generated. The
processor handles this by saving the current execution state, calling the page
fault handler to correct this exception (by paging in the data), and re-executing
the same instruction (which should no longer cause a page fault). A trap is an
exception caused by executing special kinds of instructions. For example, the
instruction SYSENTER causes the processor to begin executing the generic system
call handler; after the handler is done, execution is resumed at the instruction
immediately after SYSENTER. Hence, the major difference between a fault and
a trap is where execution resumes. Operating systems commonly implement
system calls through the interrupt and exception mechanism.

Walk-Through

We finish the chapter with a walk-through of a function with fewer than 100
instructions. It is Sample J’s D11Main routine. This exercise has two objectives.
First, it applies almost every concept covered in the chapter (except for switch-
case). Second, it teaches an important requirement in the practice of reverse
engineering: reading technical manuals and online documentation. Here is
the function:

Ol: ; BOOL __stdcall D1llMain(HINSTANCE hinstDLL, DWORD fdwReason,
; LPVOID lpvReserved)

02: _D11Main@12 proc near

03: 55 push ebp

04: 8B EC mov ebp, esp

05: 81 EC 30 01 00+ sub esp, 130h

06: 57 push edi

07: OF 01 4D F8 sidt fword ptr [ebp-8]

08: 8B 45 FA mov eax, [ebp-6]

09: 3D 00 F4 03 80 cmp eax, 8003F400h

---

**Page 29**

Chapter 1

x86 and x64

29

10:
11:
12:
13:
14:
15:
16:
17:
18:
19:
20:
21:
22:
23:
24:
25:
26:
27:
28:
29:
30:
31:
32:
33:
34:
35:
36:
37:
38:
39:
40:
41:
42:
43:
44;
45;
46:
47:
48:
49:
50:
51:
52:
53:
54:
55:
56:
57:
58:
59:
60:
61:
62:
63:

76
3D
73
33
5F
8B
5D
C2

33
B9
8D
C7
50
6A
F3
E8
8B
83
75
33
5F
8B
5D
C2

8D
56
50
57
C7
E8
85
74
8B
8D
68
51
FF
83
85
74

8D
52
57
E8
85
74
8D
68
50
FF
83

10
00
09
co

E5

oc

co
49
BD
85

02
AB
2D
F8
FF
09
co

E5

oc

85

85
FF
co
4F
35
8D
50

D6
C4
Co
26

95

CD
co
23
85
50

D6
C4

jbe

74 04 80 cmp

00
D4
DO

2F

FF

DO

DO
2E

co
F4
7C

08

DO

2E

F4
7C

08

00
FE
FE

00

FE

FE
00

50
FE
00

FE

00

FE
00

jnb
xor
pop
mov
pop
retn

short loc_10001C88 (line 18)
eax, 80047400h

short loc_10001C88 (line 18)
eax, eax

edi

esp, ebp

ebp

0Ch

loc_10001C88:

xoOr
00 mov
FF+ lea
FF+ mov
push
push

eax, eax

ecx, 49h

edi, [ebp-12Ch]

dword ptr [ebp-130h], 0
eax

2

rep stosd

00 call
mov
cmp
jnz
xor
pop
mov
pop
retn

CreateToolhelp32Snapshot
edi, eax

edi, OFFFFFFFFh

short loc_10001CB9 (line 35)
eax, eax

edi

esp, ebp

ebp

0Ch

loc_10001CB9:

FF+ lea
push
push
push

FF+ mov

00 call
test
jz

00+ mov

FF+ lea

10 push
push
call
add
test

jz

eax, [ebp-130h]

esi

eax

edi

dword ptr [ebp-130h], 128h
Process32First

eax, eax

short loc_10001D24 (line 70)
esi, ds: _stricmp

ecx, [ebp-10Ch]

10007C50h

ecx

esi ; _stricmp
esp, 8

eax, eax
short loc_10001D16 (line 66)

loc_10001CFO:

FF+ lea
push
push

00 call
test
jz

FF+ lea

10 push
push
call
add

edx, [ebp-130h]

edx

edi

Process32Next

eax, eax

short loc_10001D24 (line 70)
eax, [ebp-10Ch]

10007C50h
eax
esi ; _stricmp

esp, 8

---

**Page 30**

30

Chapter 1 = x86 and x64

64: 85 CO test eax, eax

65: 75 DA jnz short loc_10001CFO (line 52)
66: loc_10001D16:

67: 8B 85 E8 FE FF+ mov eax, [ebp-118h]

68: 8B 8D D8 FE FF+ mov ecx, [ebp-128h]

69: EB 06 jmp short loc_10001D2A (line 73)
70: loc_10001D24:

71: 8B 45 OC mov eax, [ebp+0Ch]

72: 8B 4D 0C mov ecx, [ebp+0Ch]

73: loc_10001D2A:

74: 3B Cl cmp eax, eCx

75: 5E pop esi

76: 75 09 jnz short loc_10001D38 (line 82)
77: 33 CO xor eax, eax

78: SF pop edi

79: 8B E5 mov esp, ebp

80: 5D pop ebp

81: C2 OC 00 retn O0Ch

82: loc_10001D38:

83: 8B 45 0C mov eax, [ebp+0Ch]

84: 48 dec eax

85: 75 15 jnz short loc_10001D53 (line 93)
86: 6A 00 push 0

87: 6A 00 push 0

88: 6A 00 push 0

89: 68 DO 32 00 10 push 100032D0h

90: 6A 00 push 0

91: 6A 00 push 0

92: FF 15 20 50 00+ call ds:CreateThread

93: loc_10001D53:

94: B8 O01 00 00 OO mov eax, 1

95: 5F pop edi

96: 8B E5 mov esp, ebp

97: 5D pop ebp

98: C2 0C 00 retn 0Ch

99: _D11Main@12 endp

Lines 3-4 set up the function prologue, which saves the previous base frame
pointer and establishes a new one. Line 5 reserves 0x130 bytes of stack space.
Line 6 saves EDI. Line 7 executes the SIDT instruction, which writes the 6-byte
IDT register to a specified memory region. Line 8 reads a double-word at EBP-6
and saves it in EAx. Lines 9-10 check if Zax is below-or-equal to 0x8003F400. If it
is, execution is transferred to line 18; otherwise, it continues executing at line 11.
Lines 11-12 do a similar check except that the condition is not-below 0x80047400.
If it is, execution is transferred to line 18; otherwise, it continues executing at
line 13. Line 13 clears Eax. Line 14 restores the saved EDI register in line 6. Lines
15-16 restore the previous base frame and stack pointer. Line 17 adds OxC bytes
to the stack pointer and then returns to the caller.

Before discussing the next area, note a few things about these first 17 lines.
The sipT instruction (line 7) writes the content of the IDT register to a 6-byte

---

**Page 31**

Chapter 1 = x86 and x64

31

memory location. What is the IDT register? The Intel/AMD reference manual
states that IDT is an array of 256 8-byte entries, each containing a pointer to an
interrupt handler, segment selector, and offset. When an interrupt or exception
occurs, the processor uses the interrupt number as an index into the IDT and
calls the entry’s specified handler. The IDT register is a 6-byte register; the top
4 bytes contain the base of the IDT array/table and the bottom 2 bytes store the
table limit. With this in mind, you now know that line 8 is actually reading the
IDT base address. Lines 9 and 11 check whether the base address is in the range
(0x8003F400, 0x80047400). What is special about these seemingly random con-
stants? If you search the Internet, you will note that 0x8003F400 is an IDT base
address on Windows XP on x86. This can be verified in the kernel debugger:

0: kd> vertarget

Windows XP Kernel Version 2600 (Service Pack 3) MP (2 procs) Free x86 compat-
ible

Built by: 2600.xpsp.080413-2111

0: kd> r @idtr
idtr=8003f400
0: kd> ~1

1: kd> r @idtr
idtr=bab3c590

Why does the code check for this behavior? One possible explanation is that the
developer assumed that an IDT base address falling in that range is considered
“invalid” or may be the result of being virtualized. The function automatically
returns zero if the IDTR is “invalid.” You can decompile this code to C as follows:

typedef struct _IDTR {
DWORD base;
SHORT limit;
} IDTR, *PIDTR;
BOOL __stdcall D11Main (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvRe-
served)

{

IDTR idtr;

__ sidt (&idtr) ;

if (idtr.base > 0x8003F400 && idtr.base < 0x80047400h) { return FALSE; }
//line 18

If you read the manual closely, you'll note that each processor has its own
IDT and hence IDTR. Therefore, on a multi-core system, IDTR will be different for each
core. Clearly, 0x8003F400 is valid only for core 0 on Windows XP. If the instruction
were to be scheduled to run on another core, the IDTR would be 0xBAB3C590. On later
versions of Windows, the IDT base addresses change between reboots; hence, the
practice of hardcoding base addresses will not work.

---

**Page 32**

32

Chapter 1 = x86 and x64

If the IDT base seems valid, the code continues execution at line 18. Lines
19-20 clear EAX and set ECx to 0x49. Line 21 uses sets EDI to whatever EBP-0x12C
is; since EBP is the base frame pointer, EBP-0x12C is the address of a local vari-
able. Line 22 writes zero at the location pointed to by EBP-0x130. Lines 23-24
push £ax and 2 on the stack. Line 25 zeroes a 0x124-byte buffer starting from
EBP-0x12c. Line 26 calls CreateToolhelp32Snapshot:

HANDLE WINAPI CreateToolhelp32Snapshot (
_In_ DWORD dwFlags,
_In_ DWORD th32ProcessID

i

This Win32 API function takes two integer parameters. As a general rule,
Win32 API functions follow sTpcaLL calling convention. Hence, the dwFlags
and th32ProcessId parameters are 0x2 (line 24) and 0x0 (line 23). This func-
tion enumerates all processes on the system and returns a handle to be used in
Process32Next. Lines 27-28 save the return value in EDI and check if it is -1. If
it is, the return value is set to 0 and it returns (lines 30-34); otherwise, execution
continues at line 35. Line 36 sets EAx to the address of the local variable previ-
ously initialized to 0 in line 22; line 40 initializes it to 0x128. Lines 37-39 push
ESI, EAX, and EDI on the stack. Line 41 calls Process32First:

Function prototype
BOOL WINAPI Process32First (
_In_ HANDLE hSnapshot,

_Inout_ LPPROCESSENTRY32 lppe
di

Relevant structure definition

typedef struct tagPROCESSENTRY32 {

DWORD dwSize;

DWORD cntUsage;

DWORD th32ProcessID;
ULONG_PTR th32DefaultHeapID;
DWORD th32ModuleID;

DWORD cntThreads;

DWORD th32ParentProcessID;
LONG pcPriClassBase;
DWORD dwFlags;

TCHAR szExeFile [MAX _PATH] ;

} PROCESSENTRY32, *PPROCESSENTRY32;

00000000 PROCESSENTRY32 struc ; (sizeof=0x128)
00000000 dwSize dd ?

00000004 cntUsage dd ?

00000008 th32ProcessID dd ?

---

**Page 33**

Chapter 1 = x86 and x64 33

0000000C th32DefaultHeapID dd ?
00000010 th32ModuleID dd ?
00000014 cntThreads dd ?

00000018 th32ParentProcessID dd ?
0000001C pcPriClassBase dd ?
00000020 dwFlags dd ?

00000024 szExeFile db 260 dup(?)
00000128 PROCESSENTRY32 ends

Because this API takes two parameters, hSnapshot is EDI (line 39, previously
the returned handle from Creat eToolhelp32Snapshot in line 27), and lppe is the
address of a local variable (EBP-0x130). Because lppe points to a PROCESSENTRY32
structure, we immediately know that the local variable at EBP-0x130 is of the
same type. It also makes sense because the documentation for Process32First
states that before calling the function, the dwSize field must be set to the size
of a PROCESSENTRY32 structure (which is 0x128). We now know that lines 19-25
were simply initializing this structure to 0. In addition, we can say that this
local variable starts at EBP-0x130 and ends at EBP- 0x8.

Line 42 tests the return value of Process32Next. If it is zero, execution begins at
line 70; otherwise, it continues at line 43. Line 44 saves the address of the stricmp
function in Est. Line 45 sets Ecx to the address of a local variable (EBP-0x10C),
which happens to be a field in PROCESSENTRY32 (See the previous paragraph).
Lines 46-48 push 0x10007C50/Ecx on the stack and call stricmp. We know
that stricmp takes two character strings as arguments; hence, Ecx must be the
szExeFile field in PROCESSENTRY32 and 0x10007C50 is the address of a string:

.data:10007C50 65 78 70 6C 6F+Str2 db 'explorer.exe',0

Line 49 cleans up the stack because stricmp uses CDECL calling convention.
Line 50 checks stricmp’s return value. If it is zero, meaning that the string
matched "explorer.exe", execution begins at line 66; otherwise, it continues
execution at line 52. We can now decompile lines 18-51 as follows:

HANDLE h;

PROCESSENTRY32 procentry;

h = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0) ;
if (h == INVALID HANDLE VALUE) { return FALSE; }

memset (&procentry, 0, sizeof (PROCESSENTRY32) ) ;
procentry.dwSize = sizeof (procentry); // 0x128

if (Process32Next (h, &procentry) == FALSE) {
// line 70

}

if (stricmp(procentry.szExeFile, "explorer.exe") == 0) {
// line 66

}

// line 52

---

**Page 34**

34

Chapter 1 = x86 and x64

Lines 52-65 are nearly identical to the previous block except that they form
a loop with two exit conditions. The first exit condition is when Process32Next
returns FALSE (line 58) and the second is when stricmp returns zero. We can
decompile lines 52-65 as follows:

while (Process32Next (h, &procentry) != FALSE) {
if (stricmp(procentry.szExeFile, "explorer".exe") == 0)
break;

After the loop exits, execution resumes at line 66. Lines 67—68 save the match-
ing PROCESSENTRY32’S th32Parent ProcessID/th32ProcessID in EAX/ECx and
continue execution at 37. Notice that Line 66 is also a jump target in line 43.

Lines 70-74 read the £dwReason parameter of D11Main (EBP+C) and check
whether it is 0 (DLL_PROCESS DETACH). If it is, the return value is set to 0 and
it returns; otherwise, it goes to line 82. Lines 82-85 check if the fdwReason is
ereater than 1 (i.e., DLL_THREAD_ATTACH, DLL_THREAD_DETACH). If it is, the return
value is set to 1 and it returns; otherwise, execution continues at line 86. Lines
86-92 call createThread:

HANDLE WINAPI CreateThread (

_In_opt_ LPSECURITY_ ATTRIBUTES lpThreadAttributes,
_In_ SIZE_T dwStackSize,
_In_ LPTHREAD START ROUTINE lpStartAddress,
_In_opt_ LPVOID lpParameter,

In DWORD dwCreationFlags,

_Out_opt_ LPDWORD lpThreadId
i

with lpStartAddress as 0x100032D0. This block can be decompiled as follows:

if (fdwReason == DLL PROCESS DETACH) { return FALSE; }

if (fdwReason == DLL THREAD ATTACH || fdwReason == DLL THREAD DETACH) {
return TRUE; }

CreateThread(0, 0, (LPTHREAD START _ROUTINE) 0x100032D0, 0, 0, 0);

return TRUE;

Having analyzed the function, we can deduce that the developer’s original
intention was this:

1. Detect whether the target machine has a “sane” IDT.

2. Check whether “explorer.exe” is running on the system—i.e., someone
logged on.

3. Create a main thread that infects the target machine.

---

**Page 35**

Chapter 1 = x86 and x64

35

Exercises

. Repeat the walk-through by yourself. Draw the stack layout, including
parameters and local variables.

. In the example walk-through, we did a nearly one-to-one translation of
the assembly code to C. As an exercise, re-decompile this whole function
so that it looks more natural. What can you say about the developer’s skill
level/experience? Explain your reasons. Can you do a better job?

. Insome of the assembly listings, the function name has a @ prefix followed
by a number. Explain when and why this decoration exists.

. Implement the following functions in x86 assembly: strlen, strchr, mem-

cpy, memset, strcmp, strset.

. Decompile the following kernel routines in Windows:

M KeInitializeDpc
M KeInitializeApc

m ObFastDereferenceObject (and explain its calling convention)
M@ KelInitializeQueue

mM KxWaitForLockChainValid

M KeReadyThread

M@ KilnitializeTSs

M RtlValidateUnicodeString

. Sample H. The function sub_13846 references several structures whose types
are not entirely clear. Your task is to first recover the function prototype
and then try to reconstruct the structure fields. After reading Chapter 3,
return to this exercise to see if your understanding has changed. (Note:
This sample is targeting Windows XP x86.)

. Sample H. The function sub_10BB6 has a loop searching for something.
First recover the function prototype and then infer the types based on the
context. Hint: You should probably have a copy of the PE specification
nearby.

. Sample H. Decompile sub_11732 and explain the most likely programming
construct used in the original code.

. Sample L. Explain what function sub_1000cEA0 does and then decompile
it back to C.

---

**Page 36**

36

Chapter 1 = x86 and x64

10. If the current privilege level is encoded in CS, which is modifiable by
user-mode code, why can’t user-mode code modify CS to change CPL?

11. Read the Virtual Memory chapter in Intel Software Developer Manual,
Volume 3 and AMD64 Architecture Programmer’s Manual, Volume 2: System
Programming. Perform a few virtual address to physical address transla-
tions yourself and verify the result with a kernel debugger. Explain how
data execution prevention (DEP) works.

12. Bruce’s favorite x86/x64 disassembly library is BeaEngine by Beatrix
(www. beaengine.org). Experiment with it by writing a program to disas-
semble a binary at its entry point.

x64

x64 is an extension of x86, so most of the architecture properties are the same,
with minor differences such as register size and some instructions are unavail-
able (like pusHaD). The following sections discuss the relevant differences.

Register Set and Data Types

The register set has 18 64-bit GPRs, and can be illustrated as shown in
Figure 1-6. Note that 64-bit registers have the “R” prefix.

63 0 63 0
| RAX | RBP
EAX EBP
31 AX 31 BP
AH| AL 15 | PL
15 7 7
Figure 1-6

While RBP can still be used as the base frame pointer, it is rarely used for that
purpose in real-life compiler-generated code. Most x64 compilers simply treat
RBP as another GPR, and reference local variables relative to RSP.

Data Movement

x64 supports a concept referred to as RIP-relative addressing, which allows instruc-
tions to reference data at a relative position to RIP. For example:

01: 0000000000000000 48 8B 05 00 00+ mov rax, qword ptr cs:loc A
02: ; originally written as "mov rax,

03: 0000000000000007 loc_A:

---

**Page 37**

Chapter 1 = x86 and x64

37

04: 0000000000000007 48 31 CO xor rax, rax
05: OODDDDD0D00000000A 90 nop

Line 1 reads the address of 1oc_a (which is 0x7) and saves it in RAX. RIP-
relative addressing is primarily used to facilitate position-independent code.
Most arithmetic instructions are automatically promoted to 64 bits even
though the operands are only 32 bits. For example:
48 B8 88 77 66+ mov rax, 1122334455667788h
31 CO xor eax, eax ; will also clear the upper 32bits of RAX.
; i.e., RAX=0 after this

48 C7 CO FF FF+ mov rax, OFFFFFFFFFFFFFFFFh
FF CO ine eax ; RAX=0 after this

Canonical Address

On x64, virtual addresses are 64 bits in width, but most processors do not sup-
port a full 64-bit virtual address space. Current Intel/AMD processors only use
48 bits for the address space. All virtual memory addresses must be in canonical
form. A virtual address is in canonical form if bits 63 to the most significant
implemented bit are either all 1s or Os. In practical terms, it means that bits 48-63
need to match bit 47. For example:
Oxff£££801~>c9c11000 = 11111111 11111111 11111000 00000001 11001001 11000001
00010000 00000000 ; canonical
0x000007£7~bdb67000 = 00000000 00000000 00000111 11110111 10111101 10110110
01110000 00000000 ; canonical
Oxf£f££0800~00000000 = 11111111 11111111 00001000 00000000 00000000 00000000
00000000 00000000 ; non-canonical
Oxff££8000~00000000 = 11111111 11111111 10000000 00000000 00000000 00000000
00000000 00000000 ; canonical

Oxff£F£FL£960~000989fO = 11111111 11111111 11111001 01100000 00000000 00001001
10001001 11110000 ; canonical

If code tries to dereference a non-canonical address, the system will cause
an exception.

Function Invocation

Recall that some calling conventions require parameters to be passed on the
stack on x86. On x64, most calling conventions pass parameters through reg-
isters. For example, on Windows x64, there is only one calling convention and
the first four parameters are passed through Rcx, RDx, R8, and R9; the remaining
are pushed on the stack from right to left. On Linux, the first six parameters are
passed on RDI, RSI, RDX, RCX, R8, and R9.

kee For more information regarding x64 ABI on Windows, see the “x64 Software
Conventions” section on MSDN (http: //msdn.microsoft.com/en-us
/library/7kcdté6fy.aspx).

---

**Page 38**

38 Chapter 1 = x86 and x64

Exercises

1. Explain two methods to get the instruction pointer on x64. At least one of
the methods must use RIP addressing.

2. Perform a virtual-to-physical address translation on x64. Were there any
major differences compared to x86?

---

**Page 39**

ARM

A company named Acorn Computers developed a 32-bit RISC architecture named
the Acorn RISC Machine (later renamed to Advanced RISC Machine) in the late
1980s. This architecture proved to be useful beyond their limited product line,
so a company named ARM Holdings was formed to license the architecture for
use in a wide variety of products. It is commonly found in embedded devices
such as cell phones, automobile electronics, MP3 players, televisions, and so on.
The first version of the architecture was introduced in 1985, and at the time of
this writing it is at version 7 (ARMv7). ARM has developed a number of specific
cores (e.g., ARM7, ARM7TDMI, ARM926EJS, Cortex)—not to be confused with
the different architecture specifications, which are numbered ARMv1-ARMVv/7.
While there are several versions, most devices are either on ARMV4, 5, 6, or 7.
ARMvV4 and V5 are relatively “old,” but they are also the most dominant and
common versions of the processor (“more than 10 billion” cores in existence,
according to ARM marketing). Popular consumer electronic products typically
use more recent versions of the architecture. For example, the third-generation
Apple iPod Touch and iPhone run on an ARMVé6 chip, and later iPhone/iPad
and Windows Phone 7 devices are all on ARMv7.

Whereas companies such as Intel and AMD design and manufacture their
processors, ARM follows a slightly different model. ARM designs the architecture
and licenses it to other companies, which then manufacture and integrate the
processors into their devices. Companies such as Apple, NVIDIA, Qualcomm,
and Texas Instruments market their own processors (A, Tegra, Snapdragon,

39

---

**Page 40**

40

Chapter 2= ARM

and OMAP, respectively), but their core architecture is licensed from ARM.
They all implement the base instruction set and memory model defined in the
ARM architecture reference manual. Additional extensions can be added to
the processor; for example, the Jazelle extension enables Java bytecode to be
executed natively on the processor. The Thumb extension adds instructions
that can be 16 or 32 bits wide, thus allowing higher code density (native ARM
instructions are always 32 bits in width). The Debug extension allows engineers
to analyze the physical processor using special debugging hardware. Each
extension is typically represented by a letter (J, T, D, etc.). Depending on their
requirements, manufacturers can decide whether they need to license these
additional extensions. This is why ARMv6 and earlier processors have letters
after them (e.g., ARM1156T2 means ARMv6 with Thumb-2 extension). These
conventions are no longer used in ARMv/7, which instead uses three profiles
(Application, Real-time, and Microcontroller) and model name (Cortex) with
different features. For example, ARMv7 Cortex-A series are processors with
the application profile; and Cortex-M are meant for microcontrollers and only
support Thumb mode execution.

This chapter covers the ARMv7 architecture as defined in the ARM Architecture
Reference Manual: ARMv7-A and ARMv7-R Edition (ARM DDI 0406B).

Basic Features

Because ARM is a RISC architecture, there are a few basic differences between
ARM and CISC architectures (x86/x64). (From a practical perspective, new
versions of Intel processors have some RISC features as well—i.e., they are not
“purely” CISC.) First, the ARM instruction set is very small compared to x86,
but it offers more general-purpose registers. Second, the instruction length is
fixed width (16 bits or 32 bits, depending on the state). Third, ARM uses a load-
store model for memory access. This means data must be moved from memory
into registers before being operated on, and only load/store instructions can
access memory. On ARM, this translates to the LDR and str instructions. If you
want to increment a 32-bit value at a particular memory address, you must first
load the value at that address to a register, increment it, and store it back. In
contrast with x86, which allows most instructions to directly operate on data
in memory, such a simple operation on ARM would require three instructions
(one load, one increment, one store). This may imply that there is more code
to read for the reverse engineer, but in practice it does not really matter much
once you are used to it.

ARM also offers several different privilege levels to implement privilege
isolation. In x86, privileges are defined by four rings, with ring 0 having the

---

**Page 41**

Chapter 2= ARM

41

highest privilege and ring 3 having the lowest. In ARM, privileges are defined
by eight different modes:

m User (USR)

m Fast interrupt request (FIQ)
m Interrupt request (IRQ)

m Supervisor (SVC)

m Monitor (MON)

m Abort (ABT)

m Undefined (UND)

m System (SYS)

Code running in a given mode has access to certain privileges and registers
that others may not; for example, code running in USR mode is not allowed
to modify system registers (which are typically modified only in SVC mode).
USR is the least privileged mode. While there are many technical differences,
for the sake of simplicity you can make the analogy that USR is like ring 3 and
SVC is like ring 0. Most operating systems implement kernel mode in SVC and
user mode in USR. Both Windows and Linux do this.

If you recall from Chapter 1, x64 processors can execute in 32-bit, 64-bit, or
both interchangeably. ARM processors are similar in that they can also operate
in two states: ARM and Thumb. ARM/Thumb state determines only the instruc-
tion set, not the privilege level. For example, code running in SVC mode can be
either ARM or Thumb. In ARM state, instructions are always 32 bits wide; in
Thumb state, instructions can be either 16 bits or 32 bits wide. Which state the
processor executes in depends on two conditions:

m When branching with the Bx and BLx instruction, if the destination
register’s least significant bit is 1, then it will switch to Thumb state.
(Although instructions are either 2- or 4-byte aligned, the processor will
ignore the least significant bit so there won’t be alignment issues.)

m If the T bit in the current program status register (CPSR) is set, then it is in
Thumb mode. The semantic of cPsrR is explained in the following section,
but for now you can think of it as an extended EFLAGS register in x86.

When an ARM core boots up, most of the time it enters ARM state and remains
that way until there is an explicit or implicit change to Thumb. In practice, many
recent operating system code mainly uses Thumb code because higher code
density is wanted (a mixture of 16/32-bit wide instructions may be smaller in
size than all 32-bit ones); applications can operate in whatever mode they want.

---

**Page 42**

42

Chapter 2= ARM

While most Thumb and ARM instructions have the same mnemonic, 32-bit
Thumb instructions have a .w suffix.

It is a common misconception to think that Thumb is like real mode and ARM
is like protected mode on x86/x64. Do not think of it this way. Most operating systems
on the x86/x64 platform run in protected mode and rarely, if ever, switch back to real
mode. Operating systems and applications on the ARM platform can execute both in
ARM and Thumb state interchangeably. Note also that these states are completely dif-
ferent from the privilege modes explained in the previous paragraph (USR, SVC, etc.).

There are two versions of Thumb: Thumb-1 and Thumb-2. Thumb-1 was used in
ARMvV6 and earlier architectures, and its instructions are always 16 bits in width.
Thumb-2 extends that by adding more instructions and allowing them to be either 16
or 32 bits in width. ARMv7 requires Thumb-2, so whenever we talk about Thumb, we
are referring to Thumb-2.

There are several other differences between ARM and Thumb states but we cannot
cover them all here. For example, some instructions are available in ARM state but not
Thumb state, and vice versa. You can consult the official ARM documentation for more
details.

In addition to having different states of execution, ARM also supports con-
ditional execution. This means that an instruction encodes certain arithmetic
conditions that must be met in order for it to be executed. For example, an
instruction can specify that it will only be executed if the result of the previous
instruction is zero. Contrast this with x86, for which almost every single instruc-
tion is executed unconditionally. (Intel has a couple of instructions directly
supporting conditional execution: cmov and SETNE.) Conditional execution is
useful because it cuts down on branch instructions (which are very expensive)
and reduces the number of instructions to be executed (which leads to higher
code density). All instructions in ARM state support conditional execution, but
by default they execute unconditionally. In Thumb state, a special instruction
IT is required to enable conditional execution.

Another unique ARM feature is the barrel shifter. Certain instructions can
“contain” another arithmetic instruction that shifts or rotates a register. This
is useful because it can shrink multiple instructions into one; for example, you
want to multiply a register by 2 and then store the result in another register.
Normally, this would require two instructions (a multiply followed by a move),
but with the barrel shifter you can include the multiply (shift left by 1) inside
the MOV instruction. The instruction would be something like the following:

MOV R1, RO, LSL #1 ; Rl = RO * 2

---

**Page 43**

Chapter 2= ARM

43

Data Types and Registers

Similar to high-level languages, ARM supports operations on different data
types. The supported data types are: 8-bit (byte), 16-bit (half-word), 32-bit (word),
and 64-bit (double-word).

The ARM architecture defines sixteen 32-bit general-purpose registers, num-
bered RO, R1,R2,...,R15. While all of them are available to the application pro-
grammer, in practice the first 12 registers are for general-purpose usage (such as
EAX, EBX, etc., in x86) and the last three have special meaning in the architecture:

™ R13 is denoted as the stack pointer (SP). It is the equivalent of ESP/RSP in

BP WN BP

x86/x64. It points to the top of the program stack.

R14 is denoted as the link register (LR). It normally holds the return address
during a function call. Certain instructions implicitly use this register. For
example, BL always stores the return address in LR before branching to
the destination. x86/x64 does not have an equivalent register because it
always stores the return address on the stack. In code that does not use LR
to store the return address, it can be used as a general-purpose register.

R15 is denoted as the program counter (PC). When executing in ARM state,
PC is the address of the current instruction plus 8 (two ARM instructions
ahead); in Thumb state, it is the address of the current instruction plus 4
(two 16-bit Thumb instructions ahead). It is analogous to EIP/RIP in x86/
x64 except that they always point to the address of the next instruction to
be executed. Another major difference is that code can directly read from
and write to the PC register. Writing an address to PC will immediately
cause execution to start at that address. This can be elaborated upon a bit
further to avoid confusion. Consider the following snippet in Thumb state:

: 0x00008344 push {ir}

: 0x00008346 mov r0, pc

: 0x00008348 mov.w r2, rl, 1sl #31
: 0x0000834c pop {pc}

After line 2 is executed, Ro will hold the value 0x0000834a (=0x00008346+4):

(gdb) br main

Breakpoint 1 at 0x8348

Breakpoint 1, 0x00008348 in main ()
(gdb) disas main

---

**Page 44**

44

Chapter 2= ARM

Dump of assembler code for function main:

0x00008344 <+0>: push {lr}
0x00008346 <+2>5: mov r0, pc
=> 0x00008348 <+4>: mOov.w r2, rl, 1lsl #31
0x0000834c <+8>: pop {pc}
0x0000834e <+10>: lsls r0O, rO, #0

End of assembler dump.
(gdb) info register pc

pe 0x8348 0x8348 <main+4>
(gdb) info register ro
r0 0x834a 33610

Here we set a breakpoint at 0x00008348. When it hits, we show the PC and
RO register; as shown, PC points to the third instruction at 0x00008348 (about
to be executed) and Ro shows the previously read PC value. From this example,
you can see that when directly reading PC, it follows the definition; but when
debugging, PC points to the instruction that is to be executed.

The reason for this peculiarity is due to legacy pipelining from older ARM
processors, which always fetched two instructions ahead of the currently execut-
ing instruction. Nowadays, the pipelines are much more complicated so this does
not really matter much, but ARM retains this definition to ensure compatibility
with earlier processors.

Similar to other architectures, ARM stores information about the current
execution state in the current program status register (CPSR). From an applica-
tion programmer's perspective, CPSR is similar to the EFLAGS/RFLAG register
in x86/x64. Some documentation may discuss the application program status
register (APSR), which is an alias for certain fields in the cpsr. There are many
flags in the cpsr, some of which are illustrated in Figure 2-1 (others are covered
in later sections).

m £ (Endianness bit)—ARM can operate in either big or little endian mode.
This bit is set to 0 or 1 for little or big endian, respectively. Most of the
time, little endian is used, so this bit will be 0.

m T (Thumb bit)—This is set if you are in Thumb state; otherwise, it is ARM
state. One way to explicitly transition from Thumb to ARM (and vice
versa) is to modify this bit.

m (Mode bits)—These bits specify the current privilege mode (USR, SVC, etc.)

31 26 15 10 9 5 4 0
CPSR | cond. flags IT E T M |
Figure 2-1

---

**Page 45**

Chapter 2= ARM

45

System-Level Controls and Settings

ARM offers the concept of coprocessors to support additional instructions and
system-level settings. For example, if the system supports a memory management
unit (MMU), then its settings must be exposed to boot or kernel code. On x86/
x64, these settings are stored in cro and cr4; on ARM, they are stored in copro-
cessor 15. There are 16 coprocessors in the ARM architecture, each identified by
a number: CP0, CP1,..., CP15. (When used in code, these are referred to as Po,
...,P15,) The first 13 are either optional or reserved by ARM; the optional ones
can be used by manufacturers to implement manufacturer-specific instructions
or features. For example, cP10 and cp11 are usually used for floating-point and
NEON support. Each coprocessor contains additional “opcodes” and registers
that can be controlled through special ARM instructions. cP14 and cP15 are
used for debug and system settings; cP15, usually known as the system control
coprocessor, stores most of the system settings (caching, paging, exceptions, and
so forth).

Kee NEON provides the single-instruction multiple data (SIMD) instruction set
that is commonly used in multimedia applications. It is similar to SSE/MMX instructions
in x86-based architectures.

Each coprocessor has 16 registers and eight corresponding opcodes. The
semantic of these registers and opcodes is specific to the coprocessor. Accessing
coprocessors can only be done through the mrc (read) and mcr (write) instructions;
they take a coprocessor number, register number, and opcodes. For example, to
read the translation base register (similar to CR3 in x86/x64) and save it in Ro,
you use the following:

MRC p15, 0, r0O, c2, cO, 0 ; save TTBR in r0

This says, “read coprocessor 15’s C2/CO register using opcode 0/0 and store
the result in the general-purpose register Ro.” Because there are so many reg-
isters and opcodes within each coprocessor, you must read the documentation
to determine the precise meaning of each. Some registers (C13/C0) are reserved
for operating systems in order to store process- or thread-specific data.

While the mrc and mcr instructions do not require high privilege (i.e., they
can be executed in USR mode), some of the coprocessor registers and opcodes
are only accessible in SVC mode. Attempts to read certain registers without
sufficient privilege will result in an exception. In practice, you will infrequently
see these instructions in user-mode code; they are commonly found in very
low-level code such as ROM, boot loaders, firmware, or kernel-mode code.

---

**Page 46**

Chapter 2= ARM

Introduction to the Instruction Set

At this point, you are ready to look at the important ARM instructions. Besides
conditional execution and barrel shifters, there are several other peculiarities
about the instructions that are not found in x86. First, some instructions can
operate on a range of registers in sequence. For example, to store five registers,
R6-R10, at a particular memory location referenced by R1, you would write sT™™
R1, {R6-R10}. R6é would be stored at memory address R1, R7 at R1+4,R8 at R1+8,
and so on. Nonconsecutive registers can also be specified via comma separa-
tion (e.g., {R1,R5,R8}). In ARM assembly syntax, the register ranges are usually
specified inside curly brackets. Second, some instructions can optionally update
the base register after a read/write operation. This is usually done by affixing
an exclamation mark (!) after the register name. For example, if you were to
rewrite the previous instruction as STM R1!, {R6-R10} and execute it, then R1
will be updated with the address immediately after where R10 was stored. To
make it clearer, here is an example:

01: (gdb) disas main
02: Dump of assembler code for function main:

03: => 0x00008344 <+0>: mov r6, #10
04: 0x00008348 <+4>: mov v7, #11
05: O0x0000834c <+8>: mov r8, #12
06: 0x00008350 <+12>: mov v9, #13
07: 0x00008354 <+16>: mov r10, #14
08: 0x00008358 <+20>: stmia sp!, {r6, r7, r8, r9, r10}

09: 0x0000835c <+24>: bx lr
10: End of assembler dump.

11: (gdb) si

12: 0x00008348 in main ()

13: ...

14: 0x00008358 in main ()

15: (gdb) info reg sp

16: sp Oxbed£5848 Oxbed£5848

17: (gdb) si

18: 0x0000835c in main ()

19: (gdb) info reg sp

20: sp Oxbed£585c Oxbed£585c

21: (gdb) x/6x Oxbedf5848

22: Oxbedf£5848: 0x0000000a 0x0000000b 0x0000000c
0x0000000d

23: Oxbedf£5858: 0x0000000e 0x00000000

Line 15 displays the value of SP (oxbed£5848) before executing the stm instruc-
tion; lines 17 and 19 execute the st instruction and display the updated value
of SP. Line 21 dumps six words starting at the old value of SP. Note that Re was
stored at the old SP, R7 at SP+0x4, Rs at SP+0x8, R9 at SP+0xc, and R10 at SP+0x10.
The new SP (oxbed£585c) is immediately after where R10 was stored.

---

**Page 47**

Chapter 2= ARM

47

STMIA and STMEA are pseudo-instructions for STM—that is, they have the
same meaning. Disassemblers can pick either one to display. Some will show STMEA if
the base register is SP, and STMTA for other registers; some always use STM; and some
always use STMIA. There is no strict rule, so you have to get used to this if you are
using multiple disassemblers.

Loading and Storing Data

The preceding section mentions that ARM is a load-store architecture, which
means that data must be loaded into registers before it can be operated on. The
only instructions that can touch memory are load and store; all other instruc-
tions can operate only on registers. To load means to read data from memory
and save it in a register; to store means to write the content of a register to a
memory location. On ARM, the load/store instructions are LDR/STR, LDM/STM,
and PUSH/POP.

LDR and STR

These instructions can load and store 1, 2, or 4 bytes to and from memory. Their
full syntax is somewhat complicated because there are several different ways
to specify the offset and side effects for updating the base register. Consider
the simplest case:

O01: 03 68 LDR R3, [RO] ; R3 = *RO
02: 23 60 STR R3, [R4] ; *R4 = R3;

For the instruction in line 1, Ro is the base register and R3 is the destination;
it loads the word value at address Ro into R3. In line 2, R4 is the base register
and R3 is the destination; it takes the value in R3 and stores at the memory
address r4. This example is simple because the memory address is specified
by the base register.

At a fundamental level, the LDR/sTR instructions take a base register and an
offset; there are three offset forms and three addressing modes for each form.
We begin by discussing the offset forms: immediate, register, and scaled register.

The first offset form uses an immediate as the offset. An immediate is simply
an integer. It is added to or subtracted from the base register to access data at an
offset known at compile time. The most common usage is to access a particular
field in a structure or vtable. The general format is as follows:

™ STR Ra, [Rb, imm]
M@ LDR Ra, [Rc, imm]

---

**Page 48**

48

Chapter 2= ARM

Rb is the base register, and imm is the offset to be added to Rb.
For example, suppose that Ro holds a pointer to a KDPc structure and the

following code:

Structure Definition

0:000> dt ntkrnimp! KDPC
+0x000 Type
+0x001 Importance
+0x002 Number
+0x004 DpcListEntry
+0x00c DeferredRoutine
+0x010 DeferredContext
+0x014 SystemArgumentl
+0x018 SystemArgument2
+0x01lc DpcData
Code
O01: 13 23 MOVS
02: 03 70 STRB
03: O01 23 MOVS
04: 43 70 STRB
05: 00 23 MOVS
06: 43 80 STRH
07: C3 61 STR
08: Cl 60 STR
09: 02 61 STR

In this case,

R3,
R3,
R3,
R3,
R3,
R3,
R3,
Rl,
R2,

UChar
UChar
Uint2B

_LIST_ENTRY

Ptr32
Ptr32
Ptr32
Ptr32
Ptr32

void
Void
Void
Void
Void

#0X13

[RO]

#1

[RO, #1]

#0

RO, #2]
RO, #0x1C]
RO, #0xC]

[
[
[
[RO, #0x10]

RO is the base register and the immediates are 0x1, 0x2, 0xC, 0x10,

and oxic. The snippet can be translated into C as follows:

KDPC *obj
obj ->Type

obj->Importance =
obj ->Number =
obj->DpcData =
obj ->DeferredRoutine =
obj->DeferredContext =

This offset form is similar to the MOV Reg,

= 0x13;

Ox1;
0x0;
NULL;

R1;
R2;

/* RO is obj */

/* R1 is unknown to us */
/* R2 is unknown to us */

[Reg + Imm] on the x86/x64.

The second offset form uses a register as the offset. It is commonly used in
code that needs to access an array but the index is computed at runtime. The
general format is as follows:

m STR Ra,
™ LDR Ra,

[Rb, Rc]
[Rb, Rc]

---

**Page 49**

Chapter 2= ARM

49

Depending on the context, either Rb or Rc can be the base/offset. Consider

the following two examples:

03 FO F2 FA

R5 is the base and R8

Example 1
Ol:
02: 06 46
O03: ...
04: BB 57
; in this

Example 2
01: B3 EB
02: 2F 78
03: 18 F8
; here,
04: 9F 42

This is similar to the MoV Reg,

case,

05

05

08

30

BL strlen

MOV R6,
RO is strlen's return value

LDRSB R3,
R6 is the offset

RO

SUBS.W R8,
LDRB R7,
LDRB.W- R3,

CMP

R7,

[R7,R6]

R3, R5

[R5]

[R8,R5]

is the offset
R3

[Reg + Reg] form on x86/x64.

The third offset form uses a scaled register as the offset. It is commonly used
in a loop to iterate over an array. The barrel shifter is used to scale the offset.

The general format is as follows:

m LDR Ra,
™ STR Ra,

[Rb, Rc,
[Rb, Rc,

<shifter>]
<shifter>]

Rb is the base register; Rc is an immediate; and <shifter> is the operation
performed on the immediate—typically, a left/right shift to scale the immediate.

For example:

Ol:
02:
03:
04:
O05:
06:
O7:
08:
09:
10:
11:
12:
13:
14:
15:
16:
17:
18:

OE

00

19
09
00

50
00
A2
92
53
82
63
9C
23
8C
EF

4B

24
88
48
23

F8
23
F8
F8
FO
F8
1c
B2
46
42
DB

23

90
89
02
89

20

30
30
03
30

LDR

MOVS
LDRH
LDR

MOVS

loop start

LDR.W
MOVS
STRH.
LDRB.
ORRS.
STRB.
ADDS
UXTH
MOV
CMP
BLT

ZS saaa

R3,

R4,
Rl,
RO,
R3,

R2,
R3,
R3,
R3,
R3,
R3,
R3,
R4,
R3,
R4,

=KeNumberNodes

#0

[R3]
=KeNodeBlock
#0

[RO,R3,LSL#2]

#0
[R2,#0x90]
[R2,#0x89]
R3, #2
[R2,#0x89]
R4, #1

R3

R4

RL

loop start

---

**Page 50**

50

Chapter 2= ARM

KeNumberNodes and KeNodeBlock are a global integer and an array of KNODE
pointers, respectively.

Lines 1 and 5 simply load those globals into a register (we explain this syntax
later). Line 8 iterates over the KeNodeBlock array (R0 is the base), R3 is the index
multiplied by 2 (because it is an array of pointers; pointers are 4 bytes in size on
this platform). Lines 10-13 initialize some fields of the KNoDE element. Line 14
increments the index. Line 17 compares the index against the size of the array
(R1 is the size; see line 4) and if it is less than the size then continues the loop.

This snippet can be roughly translated to C as follows:

int KeNumberNodes = ...;
KNODE *KeNodeBlock [KeNumberNodes] = ...;
for (int i=0; i < KeNumberNodes; i++) {
KeNodeBlock[i] .x = ..;
KeNodeBlock [i] .y wef

}

This is similar to the Mov, Reg, [Reg + idx * scale] form on x86/x64.

Having covered the three offset forms, the rest of this section discusses address-
ing modes: offset, pre-indexed, and post-indexed. The only distinction among
them is whether the base register is modified and, if so, in what way. All the
preceding offset examples use offset addressing mode, which means that
the base register is never modified. This is the simplest and most common mode.
You can quickly recognize it because it does not contain an exclamation mark (!)
anywhere and the immediate is inside the square brackets. (Some publications
categorize these modes as pre-index, pre-index with writeback, and post-index.
The terminology used here reflects the official ARM documentation.) The general
syntax for the offset mode is LDR Rd, [Rn, offset].

Pre-indexed address mode means that the base register will be updated with
the final memory address used in the reference operation. The semantic is very
similar to the prefix form of the unary ++ and -- operator in C. The syntax for
this mode is LDR Rd, [Rn, offset] !. For example:

12 F9 01 3D LDRSB.W R3, [R2 ,#-1]! ; R3 = *(R2-1)
; R2 = R2-1

Post-indexed address mode means that the base register is used as the final
address, then updated with the offset calculated. This is very similar to the
postfix form of the unary ++ and -- operator in C. The syntax for this mode is
LDR Rd, [Rn], offset. For example:

10 F9 O01 6B LDRSB.W R6, [RO],#1 j; R6 = *RO
; RO = RO+1

---

**Page 51**

Chapter 2= ARM

51

The pre- and post-index forms are normally observed in code that accesses
an offset in the same buffer multiple times. For example, suppose the code
needs to loop and check whether a character in a string matches one of five
characters; the compiler may update the base pointer so that it can shave off an
increment instruction.

Kea Here’s atip to recognize and remember the different address modes in LDR/
STR: If there is a !, then it is prefix; if the base register is in brackets by itself, then it is
postfix; anything else is offset mode.

Other Usage for LDR

As explained earlier, LDR is used to load data from memory into a register;
however, sometimes you see it in these forms:

O01: DF F8 50 82 LDR.W R8, =0x2932E00 ; LDR R8, [PC, x]

02: 80 4A LDR R2, =a04d ; "S04d" ; LDR R2, [PC, y]
03: OF 4B LDR R3, = _imp_realloc ; LDR R3, [PC, 2]

Clearly, this is not valid syntax according to the previous section. Technically,
these are called pseudo-instructions and they are used by disassemblers to make
manual inspection easier. Internally, they use the immediate form of LDR with PC
as a base register; sometimes, this is called PC-relative addressing (or RIP-relative
addressing on x64). ARM binaries usually have a literal pool that is a memory
area in a section to store constants, strings, or offsets that others can reference
in a position-independent manner. (The literal pool is part of the code, so it will
be in the same section.) In the preceding snippet, the code is referencing a 32-bit
constant, a string, and an offset to an imported function stored in the literal pool.
This particular pseudo-instruction is useful because it allows a 32-bit constant
to be moved into a register in one instruction. To make it clearer, consider the
following snippet:

Ol: .text:0100B134 35 4B LDR R3, =0x68DB8BAD
; actually LDR R3, [PC, #0xD4]
; at this point, PC = 0x0100B138
02: ...
03: .text:0100B20C AD 8B DB 68 dword_100B20C DCD 0x68DB8BAD

How did the disassembler shorten the first instruction from LDR R3,
[Pc, #0xD4] to the alternate form? Because the code is in Thumb state, PC is
the current instruction plus 4, which is 0x0100B138; it is using the immediate
form of PC, so it is trying to read the word at 0x0100B20C (=0x100B138+0xD4),
which happens to be the constant we want to load.

---

**Page 52**

52

Chapter 2= ARM

Another related instruction is ADR, which gets the address for a label/function
and puts it in a register. For example:

01: 00009390 65 A5 ADR R5, dword_9528
02: 00009392 D5 EO 00 45 LDRD.W R4, R5, [R5]
03:

04: 00009528 00 CE 22 A9+dword_9528 DCD 0xA922CE00 , OxCOA4

This instruction is typically used to implement jump tables or callbacks where
you need to pass the address of a function to another. Internally, this instruction
just calculates an offset from PC and saves it in the destination register.

LDM and STM

LDM and st™ are similar to LDR/STR except that they load and store multiple
words at a given base register. They are useful when moving multiple data
blocks to and from memory. The general syntax is as follows:

m LDM<mode> Rn[!], {Rm}
m STM<mode> Rn[!], {Rm}

Rn is the base register and it holds the memory address to load/store from; the
optional exclamation mark (!) means that the base register should be updated
with the new address (writeback). Rmis the range of register to load/store. There
are four modes:

m 1a (Increment After)—Stores data starting at the memory location speci-
fied by the base address. If there is writeback, then the address 4 bytes
above the last location is written back. This is the default mode if nothing
is specified.

m 1B (Increment Before)—Stores data starting at the memory location 4 bytes
above the base address. If there is writeback, then the address of the last
location is written back.

m pa (Decrement After)—Stores data such that the last location is the base
address. If there is writeback, then the address 4 bytes below the lowest
location is written back.

m DB (Decrement Before)—Stores data such that the last location is 4 bytes
below the base address. If there is writeback, then the address of the first
location is written back.

This may sound a bit confusing at first, so let’s walk through an example
with the debugger:

01: (gdb) br main

02: Breakpoint 1 at 0x8344

03: (gdb) disas main

04: Dump of assembler code for function main:

---

**Page 53**

Chapter 2= ARM

53

O05:
06:
O7:
08:
O09:
10:
11:
12:
13:
14:
15:
16:
17:
18:
19:
20:
21:
22:
23:
24:
25:
26:
27:
28:
29:
30:

0x00008344
0x00008348
0x0000834c
0x00008350

0x00008

0x00008
(gdb) r
Breakpoint
(gdb) si

354
358

1,

<+0>: ldr
<+4>: mov
<+8>: mov
<+12>: mov
<+16>: idm
<+20>: stm

0x00008344 in main ()

0x00008348 in main ()

(gdb)

(gdb) si

x/3x S$r6é
0x1050c <mem>:

0x00000001

0x0000834c in main ()

(gdb)

0x00008358
(gdb) info
r3

r4

r5

(gdb) si
0x0000835c
(gdb) x/3x

in main ()

reg r3 r4 r5

Ox1 1
Ox2
0x3

in main ()

Sr6
0x1050c <mem>:

0x0000000a

r6, =mem ; edited a bit
r0O, #10

rl, #11

r2, #12

r6, {r3, r4, r5} ; IA mode
r6, {r0, rl, r2} ; IA mode
0x00000002 0x00000003
0x0000000b 0x0000000c

Line 5 stores a memory address in R¢6; the content of this memory address
(0x1050c) is three words (line 17). Lines 6-8 set Ro—R2 with some constants. Line
9 loads three words into R3-R5, starting at the memory location specified by Re.
As shown in lines 24-26, R3-R5 contain the expected value. Line 10 stores Ro-R2,
starting at the memory location specified by Rr6. Line 29 shows that the expected
values were written. Figure 2-2 illustrates the result of the preceding operations.

mem

0x1

0x2

0x3

Figure 2-2

ldr r6, =mem
mov rO, #10
mov rl, #11
mov r2, #12 stm r6, {r0, r1, r2}
ldm r6, {r3, r4, r5}
———>> ——>
r6 Ox1 6 0xA
r6+4 0x2 r6+4 0xB
r6+8 0x3 r6+8 OxC
r0=a r1=b r2=c r0=a r1=b r2=c
r3=1 r4=2 r5=3 r3=1 r4=2 r5=3

---

**Page 54**

54 Chapter 2= ARM

Here’s the same experiment with writeback:

!, {r3, v4, r5} ; IA mode w/ writeback
1, {r0, r1, r2} ; IA mode w/ writeback

01: (gdb) br main

02: Breakpoint 1 at 0x8344

03: (gdb) disas main

04: Dump of assembler code for function main:
O5: 0x00008344 <+0>: ldr r6, =mem ;
06: 0x00008348 <+4>: mov r0, #10
O7: O0x0000834c <+8>: mov rl, #11
08: 0x00008350 <+12>: mov r2, #12
O09: 0x00008354 <+16>: 1dm r6

10: 0x00008358 <+20>: stmia r6

11: ...

12: (gdb) r

13: Breakpoint 1, 0x00008344 in main ()

14: (gdb) si

15: 0x00008348 in main ()

16: ...

17: (gdb)

18: 0x00008354 in main ()

19: (gdb) x/3x $r6

20: Ox1050c <mem>: 0x00000001 0x00000002
21: (gdb) si

22: 0x00008358 in main ()

23: (gdb) info reg r6

24: r6 0x10518 66840

25: (gdb) si

26: 0x0000835c in main ()

27: (gdb) info reg $r6

28: r6é 0x10524 66852

29: (gdb) x/4x $r6-12

30: 0x10518 0x0000000a 0x0000000b
0x00000000

Line 9 uses IA mode with writeback, so the ré is updated with an address 4
bytes above the last location (line 23). The same can be observed in lines 10, 27,

edited a bit

0x00000003

0x0000000c

and 30. Figure 2-3 shows the result of the preceding snippet.

ldr r6, =mem

mov rO, #10

mov rl, #11

mov r2, #12

ldm r6!, {r3, r4,

————_
mem 0x1050c 0x1 0x1050c

0x1050c+4 0x2 0x1050c+4
0x1050c+8 0x3 0x1050c+8
0x1050c+c r6 0x1050c+c

Figure 2-3

stm r6, {r0, r1, r2}
r5}
——>
Ox1 0x1050c 0x1
0x2 0x1050c+4 0x2
0x3 0x1050c+8 0x3
0x1050c+c OxA
r0=a r2=b r3=c 0x1050c+10 0xB
r3=1 r4=2 15=3 0x1050c+14]} — OxC
r6 0x1050c+18

---

**Page 55**

Chapter 2= ARM

55

Because LDM and stm can move multiple words at a time, they are typically
used in block- copy or move operations. For example, they are sometimes used
to inline memcpy when the copy length is known at compile time. They are simi-
lar to the Movs instruction with the REP prefix on x86. Consider the following
blobs of code generated by two different compilers from the same source file:

Compiler A
Ol: A4 46 MOV R12, R4
02: 35 46 MOV R5, R6
03: BC E8 OF 00 LDMIA.W R12!, {RO-R3}
04: OF C5 STMIA R5!, {RO-R3}
05: BC E8 OF 00 LDMIA.W R12!, {RO-R3}
06: OF C5 STMIA R5!, {RO-R3}

07: 9C E8 OF 00 LDMIA.W R12, {RO-R3}
08: 85 E8 OF 00 STMIA.W R5, {RO-R3}

Compiler B
O1: 30 22 MOVS R2, #0x30
02: 21 46 MOV Rl, R4
03: 30 46 MOV RO, R6
04: 23 FO 17 FA BL memcpy

All this does is copy 48 bytes from one buffer to another; the first compiler
uses LDM/STM with writebacks to load/store 16 bytes at a time, while the second
simply calls into its implementation of memcpy. When reverse engineering code,
you can spot the inlined memcpy form by recognizing that the same source and
destination pointers are being used by LDM/STM with the same register set.
This is a good trick to keep in mind because you will see it often.

Another common place where LDM/STM can be seen is at the beginning and
end of functions in ARM state. In this context, they are used as the prologue
and epilogue. For example:

01: FO 4F 2D E9 STMFD- SP!, {R4-R11,LR} ; save regs + return address
O02: ...
03: FO 8F BD E8 LDMFD- SP!, {R4-R11,PC} ; restore regs and return

STMFD and LDMFD are pseudo-instructions for STMDB and LMDIA/LDM, respectively.

You will often see the suffixes FD, FA, ED, or EA after STM/LDM. They are
simply pseudo-instructions for the LDM/STM instructions in different modes (IA, IB,
etc.). The association is STMFD/STMDB, STMFA/STMIB, STMED/STMDA, STMEA/STMIA,
LDMFD/LDMIA, LDMFA/LDMDA, and LDMEA/LDMDB. It can be somewhat challenging
to memorize these associations—the most effective way is to draw pictures for each
instruction.

---

**Page 56**

56

Chapter 2= ARM

PUSH and POP

The final set of load/store instructions is PUSH and Pop. They are similar to LDM/
STM except for two characteristics:

m They implicitly use SP as the base address.
m SP is automatically updated.

The stack grows downward to lower addresses as it does in the x86/x64
architecture. The general syntax is PUSH/POP {Rn}, where Rn can be a range of
registers.

PUSH stores the registers on the stack such that the last location is 4 bytes below
the current stack pointer, and updates SP with the address of the first location.
PoP loads the registers starting from the current stack pointer and updates SP
with the address 4 bytes above the last location. PUSH/PoP are actually the same
aS STMDB/LDMIA with writeback and SP as the base pointer. Here is a short walk-
through demonstrating the instructions:

01: (gdb) disas main
02: Dump of assembler code for function main:

03: 0x00008344 <+0>: mov.w x0, #10

04: 0x00008348 <+4>: mov.w rl, #11

OS: 0x0000834c <+8>: mov.Ww r2, #12

06: 0x00008350 <+12>: push {r0O, r1, r2}
07: 0x00008352 <+14>: pop {r3, r4, x5}
08:

09: (gdb) br main

10: Breakpoint 1 at 0x8344

11: (gdb) r

12: Breakpoint 1, 0x00008344 in main ()
13: (gdb) si

14: 0x00008348 in main ()

15: ...

16: (gdb)

17: 0x00008350 in main ()

18: (gdb) info reg sp ; Current stack pointer
19: sp Oxbee56848 Oxbee56848

20: (gdb) si
21: 0x00008352 in main ()

22: (gdb) x/3x $sp ; sp is updated after the push

23: Oxbee5683c: 0x0000000a 0x0000000b 0x0000000c

24: (gdb) si ; pop into the registers

25: 0x00008354 in main ()

26: (gdb) info reg r3 r4 r5 ; new registers

27: ¥3 Oxa 10

28: r4 Oxb 11

29: r5 Oxc 12

30: (gdb) info reg sp ; new sp (4 bytes above the last location)
31: sp Oxbee56848 Oxbee56848

32: (gdb) x/3x $sp-12
33: Oxbee5683c: 0x0000000a 0x0000000b 0x0000000c

---

**Page 57**

Chapter 2= ARM

57

Figure 2-4 illustrates the preceding snippet.

mov.w r0, #10

mov.w rl, #11

mov.w r2, #12 pop {r3, r4, r5}
push {r0, rl, r2}

Oxbee56848—c sp Oxbee56848-—c 0xA Oxbee56848-c OxA
Oxbee56848-8 Oxbee56848-8 0xB Oxbee56848-8 0xB
Oxbee56848—-4 ——>  0xbee56848-4 OxC — > 0xbee56848-4 OxC
sp Oxbee56848 Oxbee56848 sp Oxbee56848
Oxbee56848+4 Oxbee56848+4 Oxbee56848+4
Oxbee56848+8 Oxbee56848+8 Oxbee56848+8
Oxbee56848+c Oxbee56848+c Oxbee56848+c
r0=a r1=b r2=c r0=a r1=b r2=c
r3=a r4=b r5=c
Figure 2-4

The most common place for PusH/PoP is at the beginning and end of func-
tions. In this context, they are used as the prologue and epilogue (like sTMFD/
LDMFD in ARM state). For example:

01: 2D E9 FO 4F  PUSH.W {R4-R11,LR} ; save registers + return address
02: ...
03: BD E8 FO 8F POP.W  ({R4-R11,PC} ; restore registers and return

Some disassemblers actually use this pattern as a heuristic to determine
function boundaries.

Functions and Function Invocation

Unlike x86/x64, which has only one instruction for function invocation (CALL)
and branching (gmp), ARM offers several depending on how the destination
is encoded. When you call a function, the processor needs to know where to
resume execution after the function returns; this location is typically referred
to as the return address. In x86, the CALL instruction implicitly pushes the return
address on the stack before jumping to the target function; when it is done execut-
ing, the target function resumes execution at the return address by popping it
off the stack into EIP.

The mechanism on ARM is essentially the same with a few minor differ-
ences. First, the return address can be stored on the stack or in the link register
(LR); to resume execution after the call, the return address is explicitly popped
off the stack into PC or there will be an unconditional branch to LR. Second, a

---

**Page 58**

58

Chapter 2= ARM

branch can switch between ARM and Thumb state, depending on the destina-
tion address’s LSB. Third, a standard calling convention is defined by ARM:
The first four 32-bit parameters are passed via registers (RO-R3) and the rest are
on the stack. Return value is stored in Ro.

The instructions used for function invocations are B, BX, BL, and BLX.

Although it is rare to see B used in the context of function invocation, it can be
used for transfer of control. It is simply an unconditional branch and is identical
to the ump instruction in x86. It is normally used inside of loops and conditionals to
go back to the beginning or break out; it can also be used to call a function
that never returns. B can only use label offsets as its destination; it cannot use
registers. In this context, the syntax of B is as follows: B_imm, where imm is an
offset relative from the current instruction. (This does not take into consider-
ation the conditional execution flags, which are discussed in the “Branching
and Conditional Execution” section.) One important fact to note is that because
ARM and Thumb instructions are 4- and 2-byte aligned, the target offset needs
to be an even number. Here is a snippet showing the usage of B:

O01: 0001C788 B loc_1C7A8
02: Q001C78A
03: 0001C78A loc_1C78A

04: O001C78A LDRB R7, [R6,R2]
O05: ...
06: O0001C7A4 STRB.W R7, [R3,#-1]

07: 0001C7A8
08: 0001C7A8 loc_1C7A8

09: 0001C7A8 MOV R7, R3
10: QOO1LC7AA ADDS R3, #2
11: 0Q001C7AC CMP R2, R4
12: 0001C7AE BLT loc_1C78A

In line 1, you see B being used as an unconditional jump to start off a loop.
You can ignore the other instructions for now.

Bx is Branch and Exchange. It is similar to B in that it transfers control to
a target, but it has the ability to switch between ARM/Thumb state, and the
target address is stored in a register. Branching instructions that end with X
indicate that they are capable of switching between states. If the LSB of the
target address is 1, then the processor automatically switches to Thumb state;
otherwise, it executes in ARM state. The instruction format is Bx <registers>,
where register holds the destination address. The two most common uses of
this instruction are returning from a function by branching to LR (i.e., BX LR)
and transferring of control to code in a different mode (i.e., going from ARM
to Thumb or vice versa). In compiled code, you will almost always see Bx LR at
the end of functions; it is basically the same as RET in x86.

BL is Branch with Link. It is similar to B except that it also stores the return
address in LR before transferring control to the target offset. This is probably the
closest equivalence to the CALL instruction in x86 and you will often see it used

---

**Page 59**

Chapter 2= ARM

59

to invoke functions. The instruction format is the same as B (that is, it takes only
offsets). Here is a short snippet demonstrating function invocation and returning:

01: 00014350 BL foo ; LR = 0x00014354
02: 00014354 MOVS R4, #0x15

O03: ...

04: 0001B224 foo

05: 0001B224 PUSH {R1-R3}

06: 0001B226 MOV R3, 0x61240

O7: ...

08: O001B24C BX LR ; return to 0x00014354

Line 1 calls the function foo using BL; before transferring control to the des-
tination, BL stores the return address (0x000014354) in LR. foo does some work
and returns to the caller (Bx LR).

BLX is Branch with Link and Exchange. It is like BL with the option to switch
state. The major difference is that BLx can take either a register or an offset as its
branch destination; in the case where BLX uses an offset, the processor always
swaps state (ARM to Thumb and vice versa). Because it shares the same charac-
teristics as BL, you can also think of it as the equivalent of the CALL instruction in
x86. In practice, both BL and BLX are used to call functions. BL is typically used if
the function is within a 32MB range, and BLx is used whenever the target range
is undetermined (like a function pointer). When operating in Thumb state, BLx is
usually used to call library routines; in ARM state, BL is used instead.

Having explored all instructions related to unconditional branching and
direct function invocation, and how to return from a function (BX LR), you can
consolidate your knowledge by looking at a full routine:

01: 0100C388 ; void *  cdecl mystery(int)
02: 0100C388 mystery

03: 0100C388 2D E9 30 48 PUSH.W {R4,R5,R11,LR}

04: 0100C38C OD F2 08 OB ADDW R11, SP, #8

05: 0100C390 OC 4B LDR R3, = imp malloc
06: 0100C392 C5 1D ADDS R5, RO, #7

07: 0100C394 6F F3 02 05 BFC.W R5, #0, #3

08: 0100C398 1B 68 LDR R3, [R3]

09: 0100C39A 15 Fl 08 00 ADDS.W RO, R5, #8

10: 0100C39E 98 47 BLX R3

11: 0100C3A0 04 46 MOV R4, RO

12: 0100C3A2 24 Bl CBZ R4, loc_100C3AE
13: 0100C3A4 EB 17 ASRS R3, R5, #0x1F

14: 0100C3A6 63 60 STR R3, [R4,#4]

15: 0100C3A8 25 60 STR R5, [R4]

16: O100C3AA 08 34 ADDS R4, #8

17: O100C3AC 04 EO B loc_100C3B8

18: O100C3AE loc_100C3AE

19: O100C3AE 04 49 LDR R1, =aFailed ; "failed..."
20: 0100C3BO 2A 46 MOV R2, R5

21: 0100C3B2 07 20 MOVS RO, #7

---

**Page 60**

60

Chapter 2= ARM

22: 0100C3B4 01 FO 14 FC. BL £o0o

23: 0100C3B8

24: 0100C3B8 loc_100C3B8

25: 0100C3B8 20 46 MOV RO, R4

26: 0100C3BA BD E8 30 88 POP.W  {R4,R5,R11,PC}
27: 0100C3BA ; End of function mystery

This function covers several of the ideas discussed earlier (ignore the other
instructions for now):

m Line 3 is the prologue, using the PUSH {..., LR} sequence; L26 is the
epilogue.
m Line 10 calls malloc via BLX.

m Line 22 calls £00 via BL.

m Line 26 returns, using the Pop {..., PC} sequence.

Arithmetic Operations

After loading a value from memory into a register, the code can move it around
and perform operations on it. The simplest operation is to move it to another
register with the mov instruction. The source can be a constant, a register, or
something processed by the barrel shifter. Here are examples of its usage:

O01: 4F FO OA OO MOV .W RO, #0xA ; rO = Oxa
02: 38 46 MOV RO, R7 ; vO = xr7
03: A4 4A AO El MOV R4, R4, LSR #21 ; r4 = (r4>>21)

Line 3 shows the source operand being processed by the barrel shifter before
being moved to the destination. The barrel shifter’s operations include left shift
(LSL), right shift (LSR, ASR), and rotate (ROR, RRX). The barrel shifter is useful
because it allows the instruction to work on constants that cannot normally be
encoded in immediate form. ARM and Thumb instructions can be either 16 or
32 bits wide, so they cannot directly have 32-bit constants as a parameter; with
the barrel shifter, an immediate can be transformed into a larger value and
moved to another register. Another way to move a 32-bit constant into a register
is to split the constant into two 16-bit halves and move them one a time; this is
normally done with the movw and movT instructions. MovT sets the top 16 bits of
a register, and movw sets the bottom 16 bits.

The basic arithmetic and logical operations are ADD, SUB, MUL, AND, ORR, and
EOR. Here are examples of their usage:

O01: 4B 44 ADD R3, R9 ; v3 = £3+r9
02: OD F2 08 OB ADDW R11, SP, #8 ; rll = sp+8
03: 04 EB 80 00 ADD .W RO, R4, RO,LSL#2 ; rO = r4 + (r0<<2)

04: EA BO SUB SP, SP, #0x1A8 ; sp = sp-0xla8s

---

**Page 61**

Chapter 2= ARM 61

05: 03 FB 05 F2  MUL.W R2, R3, RS5 ; r2 = r3*r5 (32bit result)
06: 14 FO 07 02 ANDS.W  R2, R4, #7 ; v2 = r4 & 7 (flag)

07: 83 EA Cl 03. EOR.W R3, R3, R1,LSL#3 ; r3 = r3 * (r1<<3)

08: 53 40 EORS R3, R2 ; r3 = r3 * r2 (flag)

09: 43 EA 02 23 ORR.W R3, R3, R2,LSL#8 ; r3 = r3 | (r2<<8)

10: 53 FO 02 03 ORRS.W  R3, R3, #2 ; v3 = r3 | 2 (flag)

11: 13 43 ORRS R3, R2 ; v3 = r3 | r2 (flag)

Note the “S” after some of these instructions. Unlike x86, ARM arithmetic
instructions do not set the conditional flag by default. The “S” suffix indicates
that the instruction should set arithmetic conditional flags (zero, negative, etc.)
depending on its result. Note that the mut instruction truncates the result such
that only the bottom 32 bits are stored in the destination register; for full 64-bit
multiplication, use the SMULL and UMULL instructions (see ARM TRM for the details).

Where is the divide instruction? ARM does not have a native divide instruc-
tion. (ARMv7-R and ARMv7-M cores have spIv and uDIv, but they are not
discussed here.) In practice, the runtime will have a software implementation
for division and code simply call into it when needed. Here is an example with
the Windows C runtime:

O1: 41 46 MOV R1, R8
02: 30 46 MOV RO, R6
03: 35 FO 9E FF BL __rt_udiv ; software implementation of udiv

Branching and Conditional Execution

Every example discussed so far has been executed in a linear manner. Most pro-
grams will have conditionals and loops. At the assembly level, these constructs
are implemented using conditional flags, which are stored in the application
program status register (APSR). The apsr is an alias of the cpsr and is similar to
the EFLAG in x86. Figure 2-5 illustrates the relevant flags, described as follows:

m n (Negative flag)—It is set when the result of an operation is negative (the
result’s most significant bit is 1).

m z (Zero flag)—It is set when the result of an operation is zero.

m c (Carry flag)—It is set when the result of an operation between two
unsigned values overflows.

m v (Overflow flag)—It is set when the result of an operation between two
signed values overflows.

m 17 (If-then bits)—These encode various conditions for the Thumb instruc-
tion 1T. They are discussed later.

The n, z, c, and v bits are identical to the sF, ZF, cF, and oF bits in the EFLAG
register on x86. They are used to implement conditionals and loops in higher-
level languages; they are also used to support conditional execution at the

---

**Page 62**

62

Chapter 2= ARM

instruction level. Equality is described in terms of these flags. Table 2-1 shows
common relationships and corresponding flags.

31 26 15 10 9 5 4 0
CPSR cond. flags IT E T M
APSR |N/Z/C|)VjQ Reserved
31 26 15 0
Figure 2-5
Table 2-1: Conditional code and meaning
SUFFIX/CODE MEANING ch
EQ Equal Z==1
NE Not equal Z==0
MI Minus, negative N==
PL Plus, positive, or zero N==
HI Unsigned higher/above C==1 and Z==
LS Unsigned lower/below C==0 or Z==
GE Signed greater than or equal N==
LT Signed less than N!=V
GT Signed greater than Z==0 and N==V
LE Signed less than or equal Z==1lorN!=v

Instructions can be conditionally executed by adding one of these suffixes at
the end. For example, BLT means to branch if the LT condition is true. (This is
the same as JL in x86.) By default, instructions do not update conditional flags
unless the “S” suffix is used; the comparison instructions (CBZ, CMP, TST, CMN,
and TEQ) update the flags automatically because they are usually used before
branch instructions.

The most common comparison instruction is probably cmp. Its syntax is CMP
Rn, X, where Rn is a register and x can be an immediate, a register, or a barrel
shift operation. Its semantic is identical to that in x86: It performs Rn - x, sets
the appropriate flags, and discards the result. It is usually followed by a condi-
tional branch. Here is an example of its usage and pseudo-code:

ARM

Ol:
02:
03:
04:
O05:

B3
05
O1
BD
02

EB E7 7F
DB
DC
42
D9

CMP .W
BLT
BGT
CMP
BLS

R3, R7, ASR #31
loc_less
loc_greater

R5, R7

loc_less

---

**Page 63**

Chapter 2= ARM

63

06: loc_greater

07: 07 3D SUBS R5, #7

08: 6E Fl 00 OF SBC.W LR, LR, #0
09: loc_less

10: A5 FB 08 12 UMULL.W R1, R2, R5, R8
11: 87 FB 08 04 SMULL.W RO, R4, R7, R8
12: OE FB 08 23 MLA.W R3, LR, R8, R2

Pseudo C

if (r3 < r7) { goto loc_less; }
else if ( r3 > r7) { goto loc greater; }
else if ( r5 < r7) { goto loc_less; }

The next most common comparison instruction is TST; its syntax is identical
to that of cmp. Its semantic is identical to TEST in x86: It performs Rn & x, sets
the appropriate flags, and discards the result. It is usually used to test whether
a value is equal to another or to test for flags. Like most compare instructions,
it is typically followed by a conditional branch. Here is an example:

O01: AB 8A LDRH R3, [R5,#0x14]
02: 13 FO 02 OF TST .W R3, #2

03: 09 DO BEQ loc_10179DA
O04: ...

05: loc_10179BE

06: AA 8A LDRH R2, [R5,#0x14]
07: 12 FO 04 OF TST .W R2, #4

08: 02 DO BEQ loc_10179E8

In Thumb-2 state, there are two popular comparison instructions: cBz and
cBnz. Their syntax is simple: cBZ/CBNZ Rn, label, where Rn is a register and
label is an offset to branch to if the condition is true. cBz then branches to label
if the register is zero. CBNZ is same except that it checks for a non-zero condition.
These instructions are usually used to determine whether a number is 0 or a
pointer is NULL. Here is a typical usage:

ARM

O01: 10 FO 48 FF BL £o0o

; foo returns a pointer in r0

02: 28 Bl CBZ RO, loc_100BC8E

03:

04: loc_100BC8E

05: O01 20 MOVS RO, #1

06: 28 EO B locret_100BCE4

O7: ...

08: locret_100BCE4

09: BD E8 F8 89  POP.W {R3-R8,R11,Pc}
Pseudo C

type *a;

a = foo(...);

if (a == NULL) { return 1; }

---

**Page 64**

64

Chapter 2= ARM

The other comparison instructions are cMN/TEQ, which performs addition/
exclusive-or on the operands. Because they are not commonly used they are
not covered here.

You have seen that the branch instruction (8) can be made to do conditional
branches by adding a suffix (BEQ, BLE, BLT, BLS, etc.). In fact, most ARM instruc-
tions can be conditionally executed in the same way. If the condition is not met,
the instruction can be seen as a no-op. Instruction-level conditional execution
can reduce branches, which may speed up execution time. Here is an example:

ARM

01: 00 00 50 E3 CMP RO, #0
02: 01 00 AO 03 MOVEQ RO, #1
03: 68 00 DO 15 LDRNEB RO, [RO,#0x68]

04: 1E FF 2F El BX LR
Pseudo C

unk_type *a = ...;

if (a == NULL) { return 1; }

else { return a->off 48; }

You immediately know that Ro is a pointer because of the LDR instruction
in line 3. Line 1 checks whether Ro is NULL. If true (EQ), then line 2 sets Ro to
1; otherwise, NEQ loads the value at Ro+0x68 into Ro (line 3) and then returns.
Because EQ and NEQ cannot be true at the same time, only one of the instructions
will be executed. Note that there are no branch instructions.

Thumb State

Unlike most ARM instructions, Thumb instructions cannot be conditionally
executed (with the exception of 8B) without the IT (if-then) instruction. This is
a Thumb-2-specific instruction that allows up to four instructions after it to be
conditionally executed. The general syntax is as follows: ITxyz cc, where cc
is the conditional code for the first instruction; x, y, and z describe the condi-
tion for the second, third, and fourth instruction, respectively. Conditions for
instructions after the first are described by one of two letters: T or E. T means
that the condition must match cc to be executed; E means to execute only if the
condition is the inverse of cc. Consider the following example:

ARM
O1: OO 2B CMP R3, #0
; check and set condition
02: 12 BF ITEE NE

; begin IT block
03: BC FA 8C FO CLZNE.W RO, R12
; first instruction

---

**Page 65**

Chapter 2= ARM

65

04: B6 FA 86 FO CLZEQ.W RO, R6
; second instruction

05: 20 30 ADDEQ RO, #0x20
; third instruction

Pseudo C

if (R3 != 0) {

RO = countleadzeros (R12) ;
} else {

RO = countleadzeros (R6) ;
RO += 0x20

}

Line 1 performs a comparison and sets a conditional flag. Line 2 specifies
the conditions and start the if-then block. NE is the execution condition for the
first instruction; the first E (after IT) indicates that the execution condition for
the second instruction is the inverse of the first. (EQ is the inverse of NE.) The
second E indicates the same for the third instruction. Lines 3-5 are instructions
inside the rT block.

Due to its flexibility, the IT instruction can be used to reduce the number of
instructions required to implement short conditionals in Thumb state.

Switch-Case

Switch-case statements can be understood as many if-else statements bundled
together. Because the test expression and target label are known at compile time,
compilers usually construct a jump table to store addresses (ARM) or offsets
(Thumb) for each case handler. After determining the index into the jump table,
the compiler indirectly branches to the destination by loading the destination
address into PC. In ARM state, this is normally done by LDR with PC as the
destination and base register. Consider the following example:

Ol: ; Rl is the case

02: OB 00 51 E3 CMP Rl, #0xB ; is it within range?

03: 01 Fl 9F 97  LDRLS PC, [PC,R1,LSL#2] ; yes, switch by
; indexing into the table

04: 14 00 00 EA B loc_DD10 ; no, break

05: 3C DD 00 00+ DCD loc_DD3C ; begin of jump table

06: 4C DD 00 00+ DCD loc _DD4C

07: 68 DD 00 00+ DCD loc _DD68

08: 8C DD 00 00+ DCD loc _DD8Cc

09: BC DD 00 00+ DCD loc _DDBC

10: FO DD 00 00+ DCD loc _DDFO

11: 38 DE 00 00+ DCD loc_DE38

12: 38 DE 00 00+ DCD loc_DE38

13: EC DC 00 00+ DCD loc _DCEC ; case/index 8

14: EC DC 00 00+ DCD loc_DCEC ; case/index 9

15: 3C DD 00 00+ DCD loc _DD3C

---

**Page 66**

66

Chapter 2= ARM

16: 3C DD 00 OO DCD loc _DD3C

17: loc_DCEC ; handler for case 8,9
18: 00 00 AO E3 MOV RO, #0

19: 08 10 41 E2 SUB R1, R1, #8

20: 04 30 AO E3 MOV R3, #4

21: 14 00 82 E5 STR RO, [R2,#0x14]

22: BC 31 C2 El STRH R3, [R2,#0x1C]

23: 10 10 82 E5 STR R1, [R2,#0x10]

Line 2 checks whether the case is within range; if not, then it executes the
default handler (line 4). Line 3 conditionally executes if R1 is within range; it
branches to the case-handler by indexing into the jump table and loads the des-
tination address in PC. Recall that PC is 8 bytes after the current instruction (in
ARM state), so the jump table is usually stored 8 bytes from the Lpr instruction.

In Thumb mode, the same concept applies except that the jump table con-
tains offsets instead of addresses. ARM added new instructions to support
table-branching with byte or half-word offsets: TBB and TBH. For TBB, the table
entries are byte values; for TBH, they are half-words. The table entries must be
multiplied by two and added to PC to get the final branch destination. Here is
the preceding example using TBB:

01: 0101E600 OB 29 CMP R1, #0xB ; is it within range?
02: 0101E602 76 D8 BHI loc_101E6F2 ; no, break

03: 0101E604 04 26 MOVS R6, #4

04: O0101E606 DF E8 O01 FO TBB.W [PC,R1] ; branch using table offset
05: O1O1E60A 06 jpt_101E606 DCB 6 ; begin of jump table
06: 0O101E60B 09 DCB 9

07: O1OLE60C OF DCB OXF

08: O101E60D 18 DCB 0x18

09: O1OLE60E 24 DCB 0x24

10: O1LOLE60F 32 DCB 0x32

11: 0101E610 45 DCB 0x45

12: O101E611 45 DCB 0x45

13: 0101E612 6D DCB Ox6D ; offset for 8

14: 0101E613 6D DCB O0x6éD ; offset for 9

15: 0101H614 06 DCB 6

16: O0101EF615 06 DCB 6

17: 2...

18: O101E6E4 loc_101E6E4 ; handler for case 8,9
19: O101E6E4 Bl F1 08 03 SUBS.W R3, R1, #8

20: O101E6E8 00 20 MOVS RO, #0

21: O1O1LE6EA 60 61 STR RO, [R4,#0x14]

Because it is in Thumb state, PC is 4 bytes after the current instruction; hence,
for case 8, the table entry would be at address 0x0101E612 (=0x0101E60A+8),
which is 0x6d, and the handler is at 0x101E6E4 (=PC+(0x6éd*2) ). Similar to the
previous example, the jump table is usually placed after the T8B/TBH instruction.
Note that the T8B/TBH are used only in Thumb state.

---

**Page 67**

Chapter 2= ARM

67

Miscellaneous

This section briefly discusses concepts that are not directly related to the pro-
cess of reverse engineering. However, in practice, they are important to know
because they may contribute to your overall knowledge. More knowledge is
always good. You can skip this section on a first read.

Just-in-Time and Self-Modifying Code

ARM supports the concept of just-in-time (JIT) and self-modifying code (GMC). JIT
code is native code that is dynamically generated by a JIT compiler; for example,
the Microsoft .NET languages compile to an intermediate language (MSIL) that
is converted into native machine code (x86, x64, ARM, etc.) for execution on the
CPU core. SMC is code that is generated or modified by the current instruction
stream. A common example of SMC is encoded shellcode that is decoded and
executed at run-time. Both JIT and SMC code require writing to memory new
data that is then later fetched by execution.

The ARM core has two separate cache lines for instruction (i-cache) and data
(d-cache); instructions are executed from the i-cache, and memory access is
through the d-cache. These cache lines are not guaranteed to be coherent, which
means that data written to one cache may not be immediately visible to the other.
For example, suppose the i-cache holds four instructions from the instruction
stream and the user generates new or modified instructions at the same spot
(which updates the d-cache). Because they are not coherent, the i-cache may not
know about the recent modification, so it executes stale instructions (which may
lead to mysterious crashes or incorrect results). If you are writing JIT systems
or shellcode, this is clearly not a desirable situation. The solution is to explicitly
force the i-cache to be refreshed (also known as flushing the cache). On ARM,
this is done by updating a register in the system control coprocessor (CP15):

O01: 4F FO 00 OO MOV .W RO, #0
02: O07 EE 15 OF MCR p15, 0, RO,c7,c5, 0

Most operating systems provide an interface for this operation, so you do
not have to write it yourself. On Linux, use __clear_cache; on Windows, use
FlushInstructionCache.

Synchronization Primitives

ARM does not have an instruction similar to cmpxchg (compare-and-exchange)
in x86; instead, two instructions are used: LDREX and STREX. These instructions
are just like LDR/sTR, except that they acquire exclusive access to the memory

---

**Page 68**

68

Chapter 2= ARM

address before loading/storing. Together, they are typically used to implement
compare-and-exchange intrinsics. For example:

ARM
Ol: O1 21 MOVS R1, #1
02: loc_100C4BO
03: 54 E8 00 2F LDREX .W R2, [R4]
04: 1A B9 CBNZ R2, loc_100C4BE
05: 44 E8 00 13 STREX .W R3, R1, [R4] ; r3 is the result
06: O00 2B CMP R3, #0
O07: F8 D1 BNE loc_100C4BO
Pseudo C
if (InterlockedCompareExchange(&r4, 1, 0) == 0) { do stuff; }

Line 3 performs an atomic load into R2 and compares it against 0; if it is zero,
then it is exchanged with zero and the result is returned in R3. This is actually
the implementation of InterlockedCompareExchange in Windows.

From time to time, you will run into code using the Dvs, DsB, and 1sB instruc-
tions. These are barrier instructions that ensure that memory access and
instruction fetches are synchronized before executing subsequent instructions. This
is necessary in some cases because memory access and instructions can be executed
out of order (i.e., the CPU might execute the instructions in a different order than
what appears in the assembly code), and other executing threads may not see the
updated result and consequently have an inconsistent view of the data. For this
reason, you will often see these instructions used in code that implements locks.

System Services and Mechanisms

When an ARM core boots up, it starts executing code in the ARM state at the
memory address 0x00000000 or 0xFFFF0000, depending on a setting in copro-
cessor 15. This is determined by the vector (V) bit in the system control register
(CP15, C1/CO0). If it is 0, then the exception vector is at 0x00000000; otherwise, it
is at OxFFFFO000. This address is usually in flash memory (RAM has not been
initialized yet so it cannot be used), and the content therein is commonly known
as the exception vectors. ARM has a list of predefined vectors starting at the base
address. The RESET exception handler is first in the table so it is executed after
a reset event. Because it is the first code to be executed, it usually begins by
performing basic hardware configuration and starts the boot process. Here is
an exception vector taken from a real device:

01: 00000000 1A 00 00 EA B- vect_RESET
02: 00000004 12 00 00 EA B  vect_UNDEFINED INSTRUCTION

---

**Page 69**

Chapter 2= ARM

69

03: 00000008 12 00 00 EA B vect_SUPERVISOR_CALL ; (for SWI/SVC)
04: QO000000C 12 00 00 EA B  vect_PREFETCHABORT

O5: ...

06: 00000054 vect_UNDEFINED INSTRUCTION

07: 00000054 FE FF FF EA B  vect_UNDEFINED INSTRUCTION
08: 00000058 vect_SUPERVISOR_CALL

09: 00000058 FE FF FF EA B  vect_SUPERVISOR_CALL

10: O0000005C vect_PREFETCHABORT

11: OO000005C FE FF FF EA B  vect_PREFETCHABORT

12: ...

13: 00000070 vect_RESET

14: 00000070 1C Fl 9F E5 LDR PC, =0x10000078

15: ; code has been mapped at 0x10000078
16: ; begin executing there

17:

18: 10000078 18 O01 9F E5 LDR RO, =0x2001

19: 1000007C 11 OF OF EE MCR p15, 0, RO,c15,cl, 0

20: ; initializes a vendor-specific register
21: 10000080 00 00 AO El NOP

22: 10000084 00 00 AO El NOP

23: 10000088 00 00 AO El NOP

24: 1000008C 78 00 AO E3 MOV RO, #0x78

25: 10000090 10 OF 01 EE MCR p15, 0, RO,c1,c0O, 0

26: ; initializes system control register

After initializing hardware, the reset exception code jumps to a bootloader
that is typically located in flash memory, removable media (MMC, SD card, etc.),
or some other form of storage. Some devices use U-Boot, a popular, open-source
bootloader. The bootloader performs more hardware initialization, reads an
OS image from storage and maps it into main memory, and transfers control
there. After that, the operating system boots up and the system is ready for use.

An operating system manages hardware resources and provides services
to users. Because user code (usually in USR mode) runs at a lower privilege
than kernel/OS code (usually SVC mode), it has to use an interface to request
service from the OS. In practice, the interface is provided through a software
interrupt or special trap instruction provided by the processor; the service is
commonly implemented as system calls. (For example, on Linux x86, you can
use interrupt 0x80 or the special instruction SYSENTER to issue a system call; on
x64, this is provided by the sySCALL instruction.) On ARM, there is no dedicated
system-call instruction, so software interrupt is used to implement syscalls.
When a software interrupt happens, the processor switches to supervisor mode
to handle the interrupt. Software interrupts can be triggered by the sw1/svc
instruction. (These instructions are identical except they are named differently.)

---

**Page 70**

70

Chapter 2= ARM

Both instructions take an immediate as the parameter—some operating systems
use this parameter as an index into a system call table; and some do not use the
parameter but require the system call number to be in a register (for example,
Windows uses R12 for this purpose). On some Linux systems, the syscall number
is put in R7 and arguments are passed via RO-R2. For example:

Linux (Ubuntu)
O01: 05 20 AO El MOV R2, R5 ; 3rd arg
02: 06 10 AO El MOV R1, R6 ; 2nd arg
03: 09 00 AO El MOV RO, RI ; ist arg
04: 92 70 AO E3 MOV R7, #0x92
; syscall number
05: 00 00 OO EF SVC Oo ; make the syscall

06: 04 00 70 E3 CMN RO, #4
; check return value
07: 00 30 AO 13 MOVNE R3, #0

; condition move based on return value

Windows RT
ZwCreateFile (in ntdll)
4F FO 53 0C MOV .W R12, #0x53
O01 DF SVC 1
70 47 BX LR

; End of function ZwCreateFile

svc transitions to supervisor mode, copies the relevant user registers into
their own space, performs whatever function is requested, and returns when
it is done. How does the svc know where to return? Normally, it returns to the
instruction after svc. Before processing the exception, SVC mode copies
the return address to R14_ svc, which is a banked register in SVC mode. Banked
registers are those that have meaning only in the context of a particular proces-
sor mode. For example, R13_svc and R14_ svc are banked registers in SVC mode
so they will have different values than R13-14 in USR mode.

While there is a dedicated instruction for software breakpoint BKPT, there are
a few ways that it can be implemented. The first is through the BKPT instruction,
which triggers the prefetch abort exception handler; the handler can then pass
control to a debugger. Another common method is to trigger the undefined
instruction exception handler via an undefined instruction. The ARM instruc-
tion encoding has a reserved range that is guaranteed to be undefined.

Instructions

Every instruction in ARM state encodes an arithmetic condition to support
conditional execution. By default, the condition is AL (always execute). This

---

**Page 71**

Chapter 2= ARM

71

condition is encoded in the four most significant bits in the opcode (bits 28-31);
AL is defined as 0b1110, which is oxe. If you pay close attention to the assembly
snippets (in ARM state), you will notice that the byte code usually has an oxE*
pattern at the end. In fact, if you look at the instructions in a hex editor, you will
notice that 0xE* commonly occurs every four bytes. For example:

FE FF FF EA FE FF FF EA FE FF FF EA FE FF FF EA
FE FF FF EA 1C Fl 9F E5 00 00 AO El 18 O01 9F E5
11 OF OF EE 00 00 AO El 00 00 AO El OO OO AO El
78 00 AO E3 10 OF 01 EE 00 00 AO El OO OO AO El
00 00 AO E1 00 00 AO E3 17 OF O08 EE 17 OF O7 EE

Why is it important to know this pattern? Because ARM code is sometimes
embedded in ROM or flash memory and may not follow a specific file for-
mat. In your reverse engineering journey, sometimes you will just be given
a raw memory dump without much context, so it can be useful to guess the
architecture by looking at the opcodes. The other reason is related to exploits.
Shellcode can be embedded inside an exploit delivered over the network or in
a document; to analyze it, you must extract the shellcode from the rest of the
network traffic. Sometimes it is straightforward and the shellcode boundary
is obvious, other times it is not. However, if you can recognize the pattern, you
can quickly guess the start/end of code. The ability to recognize instruction
boundaries in a seemingly random blob of data is important. Maybe you will
appreciate it later.

Walk-Through

Having learned all the fundamentals, you can apply them in this section by fully
decompiling an unknown function. This function encompasses many concepts
and techniques covered in this chapter, so it is an excellent way to put your
knowledge to the test. Along the way, you will also learn new skills that were
only hinted at in the early sections. Because the function is somewhat long, we
put it in graph form to save space and improve readability. The function body
is shown in Figure 2-6, and all the code line numbers discussed in this section
refer to this figure.
Following is the context in which it is called:

O01: 17 9B LDR R3, [SP,#0x5c]
02: 16 9A LDR R2, [SP,#0x58]
03: 51 46 MOV R1, R10

04: 20 46 MOV RO, R4

05: FF F7 98 FF BL unk_function

---

**Page 72**

72 Chapter 2 = ARM
07: unk_function
08: 2D E9 78 48 PUSH.W {R3-R6,R11,LR}
09: OD F2 10 0B ADDW R11, SP, #0x10
10: 85 68 LDR R5, [RO,#8]
11: 8C 69 LDR R4, [R1,#0x18]
12: 1E 46 MOV R6, R3
13: A5 42 CMP R5, R4
14: 01 DO BEQ loc_103C4BE
Vv
18: loc_103C4BE
19: 03 BA LDRH R3, [RO,#0x10]
20: 02 2B CMP R3, #2
21: FA D1 BNE loc_103C4BA
Vv
22: 83 69 LDR R3, [RO,#0x18]
23: 1A 40 ANDS R2, R3
24: C3 69 LDR R3, [RO,#0x1C]
25: 33 40 ANDS R3, R6
26: 13 43 ORRS R3, R2
27: F4 Dl BNE loc_103C4BA
28: C3 68 LDR R3, [RO,#0xC]
29: 00 68 LDR RO, [RO]
30: 03 EB 43 02. ADD.W R2, R3, R3,LSLH#1
31: CB 68 LDR R3, [R1,#0xC]
32: DB 68 LDR R3, [R3,#0xC]
33: 03 EB C2 03. ADD.W R3, R3, R2,LSLH#3
34: 93 F9 16 40 LDRSB.W R4, [R3,#0x16]
35: EQ F7 E6 F9 BL foo ; assume this takes 1 arg
36: 61 28 CMP RO, #0x61
37: 04 DO BEQ loc_103C4F6
38: 62 28 CMP RO, #0x62
39: 04 DO BEQ loc_103C4FA
Vv |
43: loc_103C4F6 3 00 -
44: 61 2C CMP R4, #0x61 40: e 2 sce ne een
45: DF Dl BNE loc_103C4BA 41: DA BGE Oc_103C4FA
! — —_
46: loc_103C4FA | 42: El E7 1oc_103C4Ba |
47: 01 20 MOVS RO,
7 2 Y v \
15: loc_103C4BA
16: 00 20 MOVS RO, #0
17: 1E EO B locret_103C4FC
Vv v
48: locret_103C4FC
49: BD E8 78 88 POP.W {R3-R6,R11, Pc}
50: ; End of function unk_function
Figure 2-6

When approaching an unknown function (or any block of code), the first step
is to determine what you know for certain about it. The following list enumer-

ates these facts and how you know them:

m The code is Thumb state and the instruction set is Thumb-2. You know
this because: 1) prologue and epilogue (lines 1 and 49) use the PUSH/ POP
pattern; 2) instruction size is either 16 or 32 bits in width; 3) the disas-
sembler shows the .w prefix for some instructions, indicating that they are

using the 32-bit encoding.

---

**Page 73**

Chapter 2= ARM

73

m The function preserves R3-Ré6 and R11. You know this because they are saved
and restored in the prologue (line 1) and epilogue (line 49), respectively.

m The function takes at most four arguments (RO-R3) and returns a Boolean
(RO). You know this because according to the ARM ABI (Application
Binary Interface), the first four parameters are passed in RO-R3 (the rest are
pushed on the stack) and the return value is in Ro. It is “at most four” in
this case because you saw that before calling the function in line 5, Ro-R3
are initialized with some values and you do not see any other instructions
writing to the stack (for additional arguments). At this point, the function
prototype is as follows:

BOOL unk _function(int, int, int, int)

m The first two arguments’ type is “pointer to an object.” You know this
because Ro and R1 are the base address in a load instruction (lines 10-11).
The types are most likely structures because there is access to offset 0x10,
0x18, Oxlc, and so on (line 10, 11, 19, 22, 24, 28, etc.). You can be nearly
certain that they are not arrays because the access/load pattern is not
sequential. It is uncertain whether Ro and R1 are pointers to one or two
different structure types without further context. For now, you can assume
that they are two different types. You update the prototype as follows:

BOOL unk function(structl *, struct2 *, int, int)

m loc_103C4Ba is the exit path to return 0; loc_103C4FA is the exit path to
return 1; and locret_103Cc4Fc returns from the function. Hence, branches
to these locations indicate that you are done with the function.

m The third and fourth arguments are of type integer. You know this because
R2 and R3 are being used in AND/orR operations (lines 23, 25, and 26). While
there is indeed a possibility that they can be pointers, it is unlikely to be
the case unless they were encoding /decoding pointers; and even if they
were pointers, you should see them being used in load/store operations
but you don’t.

m Even though R11 is adjusted to be 0x10 bytes above the stack pointer, it
is never used after that instruction. Hence, it can be ignored.

m The function foo (line 35) takes one argument. Its entire body is not included
here due to space constraints. Just assume this is a given for the sake of
simplicity.

Having enumerated known facts, you now need to use them to logically derive
other useful facts. The next important task is to delve into the two unknown
structures identified. Obviously you cannot recover its entire layout because
only some of its elements are referenced in the function; however, you can still
infer the field type information.

RO is of type struct *. Inline 10, it loads a field member at offset oxs and then
compares it with R4 (line 13). R4 is a field member at offset 0x18 in the structure
struct2 (R1). Because they are being compared to each other, you know that they

---

**Page 74**

74

Chapter 2= ARM

are of the same type. Line 13 compares these two fields. If they are equal, then
execution proceeds to loc_103C4BE; otherwise, 0 is returned (line 15). Because
of the equality compare, you can infer that these two fields are integers.

Line 19 loads another field member from struct1 and compares it against 2;
if it is not equal, then 0 is returned (line 21). You can infer that the field type is
a short because of the LDRH instruction (loads a half-word).

Lines 22-23 load another field member from struct1 and ANDs it against the
third argument (which is assumed to be an integer). Lines 25-27 do something
similar with the fourth argument. Because of these operations, you can infer
that field members at offset 0x18 and oxic are integers.

The structure definitions so far are as follows:

structl
+0x008 fieldO8’ i ; same type as struct2.field18_ i
+0x010 field10_s ; short

+0x018 field18 i; int
+0x0lc fieldilc_i ; int

struct2

+0x018 field18 i ; same type as structl1.field08_i

For struct field names, you might follow the habit of indicating the offset and
the “type.” For example, an “I” suffix means integer (or some generic 32-bit type),
means short (16-bit), “c” means char (1 byte), and “p” means pointer of some type. This
enables you to quickly remember what their types are. When you determine their true
purpose, you can then rename them to something more meaningful.

Mel
s

Given these types, you can already recover the pseudo-code of everything
from line 1 to 27. It is as follows:

structl *argl weet
structl *arg2 weet

int arg3 = ...;
int arg4 = ...;

BOOL result = unk _function(argl, arg2, arg3, arg4);

if (argl->fieldos i == arg2->fieldis i) {
if (argl->field10_s != 2) return 0;
if ( ((argl->field18 i & arg3) |

(argl->fieldic_i & arg4)
) t= 0
) return 0;

\ else {

---

**Page 75**

Chapter 2= ARM

75

return 0;

It is a bit suspicious that the AND operation is being used on two adjacent
integer fields. This usually means that they are actually 64-bit integers split into two
registers/memory locations. This is a common pattern used to access 64-bit constants
on 32-bit architectures.

Astute readers will notice that lines 25-27 may seem a bit redundant. anps sets
the condition flags, orRs immediately overwrites it, and BNE takes the flag from
ORRS; hence, the conditions set by ANDs are really not necessary. The compiler
generates this redundancy because it is optimizing for code density: AND will
be 4 bytes long, but anps is only 2 bytes. mov and movs are also subjected to the
same optimization. You will often see this pattern in code optimized for Thumb.

Line 28 loads another field from struct1 into R3; line 29 loads from offset
zero of the same structure into Ro; and line 30 sets R2 to R3*3 (=R3+(R3<<1)).
Line 31 loads a field from struct2 into R3 and then accesses another field using
that as a base pointer. This implies that you have a pointer to another structure
inside struct2 at offset oxc. Line 32 loads a field from that new structure into
R3; line 33 updates it to be R3+R2*8; and line 34 uses that as a base address and
loads a signed short value at offset 0x16 of another structure into R4.

Let’s update the structure definition before continuing:

structl
+0x000 fieldoO i ; int

+0x008 fielddO8’ i ; same type as struct2.field18 i
+0x00c fieldOc_i ; integer

+0x010 field1l0_s ; short

+0x018 field18 i ; int

+0x01c fieldilc_i ; int
struct2

+0x00c fieldOc_p ; struct3 *

+0x018 field18 i ; same type as struct1l.field08 i

struct3

+0x00c fieldOc_p ; struct4 *

struct4 (size=0x18=24) // why?

---

**Page 76**

76

Chapter 2= ARM

+0x016 field1l6é_c; char
+0x017 end

You could deduce that there was an array involved because of the multiplica-
tion/scaling factor (lines 30 and 33); there were not two arrays because R2-R3
in line 30 is not a base address but an index. Also, it does not make sense for a
base address to be multiplied by 3. The base address of the array is R3 in line
33 because it is being indexed with R2. You inferred that each array element
must be 0x18 (24) because after simplification, it was R2*3*8, where R2 is the
index and 24 is the scale.

Figure 2-7 illustrates the relationships between the four structures.

struct struct2 struct3 (0 struct4
+00 field00_i . . . ‘
we +0c fieldOc_p +0c fieldOc_p +16 field16_c 0x18 bytes
+08 field08_i a a i +17 field17_c
+0c fieldOc_i KY +18 field18_i
=j struct4
+10 field10_a +10 field10_a [2]
+18 field18_i struct4
XY
+1c field1c_a
= [3]
[i-1]
Figure 2-7

Here is the pseudo-code for lines 28-35:

r3
r2

r3
r3
r3

r4
r0

argl->field0dc_i;

r3 + Y3<<l

argl->field0c_i*3;

arg2->field0oc_p;

arg2->field0c_p->field0dc_ p;

arg2->field0Oc_p->field0c_p + r2*8
arg2->fieldOc_p->field0c_p + argl->field0c_1i*24;
arg2->field0Oc_p->fieldd0c_ plargl->fieldoc_ i];
arg2->field0c_p->field0dc plargl->field0c_i].fieldlé _c;
foo (argl->fieldodo i);

The rest of the function is simply comparing the return value from foo and
r4. The full pseudo-code now looks like this:

structl *argl = ...;

struct2 *arg2 wei

---

**Page 77**

Chapter 2= ARM

77

int arg3 = ...;
int arg4

BOOL result = unk_function(argl, arg2, arg3, arg4)j;

BOOL unk _function(structl *argl, struct2 *arg2, int arg3, int arg4)
{
char a;
int b;
if (argl->field08’ i == arg2->fieldis i) {
if (argl->field10_s != 2) return 0;
if ( ((argl->field18 i & arg3) |
(argl->fieldic_i & arg4)
) t= 0
) return 0;
b = foo(argl->field0o i);
a = arg2->field0c_p->field0dc plargl->field0dc_i].fieldl6é_c;
if (b == 0x61 && a != 0x61) {
return 0;
} else { return 1;}
if (b == 0x62 && a >= 0x63) {
return 1;
} else { return 0;}
} else {
return 0;
}
}

While this function used multiple, interconnected data structures whose full
layout is unclear, you can see how you were still able to recover some of the field
types and their relationship with others. You also learned how to recognize a
type’s width and signedness by considering the instruction and conditional
code associated with them.

Next Steps

This chapter provided the fundamental skills required to statically reverse engi-
neer ARM code. We intentionally avoided writing an instruction manual and
left out many details; to improve your skills, you will need to do the exercises,
practice, and read the ARM manuals (these activities go together). The technical
reference manual can be somewhat dense, but the knowledge acquired from
this chapter will make it much easier to understand.

Your next step should be to buy an ARM device and experiment with it. There
are many ARM devices to choose from, but perhaps the two most conducive
to learning are the BeagleBoard and the PandaBoard. These are development
boards intended to introduce people to embedded development on the ARM

---

**Page 78**

78

Chapter 2= ARM

platform; they are relatively powerful, cheap ($150-$170), well-documented,
and have a large user community. (You may not run into many people who
understand ARM assembly, but that’s okay because you already read this chap-
ter. The areas for which you may need help are usually related to the onboard
peripherals and how they are programmed/controlled.) You can install Linux
with a full development environment on these boards, so it is very simple to
test your knowledge of ARM.

Exercises

The exercises are included to ensure that you have a good understanding of the
concepts and to raise your motivation. Some of the exercises were intentionally
selected to include instructions that were not covered in the chapter so that
you get used to reading the manual (a very important habit); calling context is
also omitted to make you think more. Every function is self-contained to facili-
tate complete decompilation; some are selected such that you can verify your
answer if you have done enough of them. It is recommended that you write
comments and notes, and draw connections between branches/labels, on the
exercise themselves.

For the code in each exercise, do the following in order (whenever possible):

m Determine whether it is in Thumb or ARM state.

m Explain each instruction’s semantic. If the instruction is LDR/STR, explain
the addressing mode as well.

m Identify the types (width and signedness) for every possible object. For
structures, recover field size, type, and friendly name whenever possible.
Not all structure fields will be recoverable because the function may only
access a few fields. For each type recovered, explain to yourself (or some-
one else) how you inferred it.

m Recover the function prototype.
m Identify the function prologue and epilogue.
m Explain what the function does and then write pseudo-code for it.

m Decompile the function back to C and give it a meaningful name.

1. Figure 2-8 shows a function that takes two arguments. It may seem some-
what challenging at first, but its functionality is very common. Have
patience.

2. Figure 2-9 shows a function that was found in the export table.

---

**Page 79**

Debugging and Automation

Debuggers are programs that leverage support from the processor and operat-
ing system to enable tracing of other programs so that one can discover bugs
or simply understand the logic of the debugged program. Debuggers are an
essential tool for reverse engineers because, unlike disassemblers, they allow
runtime inspection of the program’s state.

The purpose of this chapter is to familiarize you with the free debugging
tools from Microsoft. It is not intended to teach you debugging techniques or
how to troubleshoot memory leaks, deadlocks, and so forth. Instead, it focuses
on the most important commands and automation/scripting facilities, and
how to write debugger extensions for the sole purpose of aiding you in reverse
engineering tasks.

The chapter covers the following topics:

m The debugging tools and basic commands—This section covers the basics
of debugging, various commands, expression evaluations and operators,
process and thread-related commands, and memory manipulation.

187

---

**Page 80**

188

Chapter 4 = Debugging and Automation

m Scripting—tThe scripting language of the debugger engine is not very
user friendly. This section explains the language in a structured and easy
to follow manner, with various examples and a set of scripts to illustrate
each topic. After reading this section, you will start leveraging the power
of scripting in the debugger.

m Using the SDK—When scripts are not enough, you can always write
extensions in C or C++. This section outlines the basics of extension writ-
ing in C/C++.

The Debugging Tools and Basic Commands

The Debugging Tools for Windows package is a set of debugging utilities that
you can download for free from Microsoft's website. The toolset ships with four
debuggers that are all based on the same debugger engine (DbgEng).

The DbgEng is a COM object that enables other programs to use advanced
debugging APIs rather than just the plain Windows Debugging APIs. In fact,
the Debugging Tools package comes with an SDK that illustrates how to write
extensions for the DbgEng or host it in your own programs.

The Debugging Tools for Windows package includes the following debuggers:

= NTSD/CDB—Microsoft NT Symbolic Debugger (NTSD) and Microsoft
Console Debugger (CDB) are both identical except that the former cre-
ates a new console window when started, whereas the latter inherits the
console window that was used to launch it.

m= WinDbg—This a graphical interface for the DbgEng. It supports source-
level debugging and saving workspaces.

m KD—Kernel Debugger (KD) is used to debug the kernel.

The debuggers have a rich set of command-line switches. One particularly
useful switch is -z, which is used to analyze crash dumps (* . dmp), cab files
(* .cab) containing a crash dump file. Another use of the -z switch is to analyze
PE files (executables or DLLs) by having the DbgEng map them as though they
were in a crash dump.

The following example runs the cdb debugger with the -z switch in order to
map calc.exe in the debugger:

C:\>edb -z c:\windows\syswow64\calc.exe

Microsoft (R) Windows Debugger Version 6.13.0009.1140 X86
Copyright (c) Microsoft Corporation. All rights reserved.

Loading Dump File [c:\windows\syswow64\calc.exe]
Symbol search path is: SRV*C:\cache*http://msdl.microsoft.com/download/
symbols

---

**Page 81**

Chapter 4= Debugging and Automation 189

Executable search path is:
ModLoad: 00400000 004c7000 c:\windows\syswow64\calc.exe
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=00000000

eip=0041a592 esp=00000000 ebp=00000000 iopl=0 nv up di pl nz na pone
cs=0000 ss=0000 ds=0000 es=0000 f£fs=0000 gs=0000 ef£1=00000000
calc!WinMainCRTStartup:

0041a592 e84bfOffftt call calc! security_init cookie (004195e2)
0:000>

Please note two things:

™ Calc.exe was mapped into the debugger, and EIP points to its entry point
(unlike live targets, which point inside ntdl1.d11).

m Many debugger commands won't be present, especially the process control
commands (because the program is mapped for analysis/inspection, not
for dynamic tracing/debugging).

Using the -z switch, you can write powerful scripts to analyze programs and
extract information.

Key You can configure WinDbg to act as the just-in-time (JIT) debugger (for the
purposes of postmortem debugging) by running Windbg.exe -I onceasa privi-
leged user.

The following sections explain various debugger commands, providing
examples along the way.

Setting the Symbol Path

Before launching any of the debuggers (WinDbg, CDB, NTSD, or KD), let’s set
up the _NT_SYMBOL_PATH environment variable:

_NT_SYMBOL PATH=SRV*c:\ cache*http://msdl.microsoft.com/download/symbols

You can also set that up from inside the debugger using the . sympath command:

Keg Setting the symbol path is important so that you can inspect some basic OS
structures as you debug the programs in question. For instance, the ! peb extension
command will not function without symbols loaded for NTDLL.

Debugger Windows

The following windows, including their hotkeys when applicable, are exposed
in WinDbg:

= Command/output window (Alt+1)—This window enables you to type
commands and see the output of operations. While it is possible to debug

---

**Page 82**

190

Chapter 4 = Debugging and Automation

using other windows and menu items, the command window enables
you to make use of the full power of DbgEng’s built-in commands and
the available extensions.

m Registers window (Alt+4)—Displays the configured registers. It is possible
to customize this view to control which registers are displayed or hidden.

m Memory (Alt+5)—Memory dump window. This window enables you
to see the contents of memory, and to scroll, copy, and even edit the
memory contents.

m Calls (Alt+6)—Displays the call stack information.

m Disassembly (Alt+7)—Whereas the command window will display the
current instruction disassembly listing, the disassembly window displays
a page worth of disassembled code. In this window it is also possible to
carry out actions with hotkeys:

m Add or delete breakpoints on the selected line (F9)
m Process control (stepping /F11, resuming /F5, etc.)

m Navigation (Page up/Page down to explore disassembled code)

kee WinDbg supports workspaces to enable the window configuration to be
saved or restored.

Evaluating Expressions

The debugger understands two syntaxes for expression evaluation: Microsoft
Macro Assembler (MASM) and C++.
To determine the default expression evaluator, use .expr without any arguments:

0:000> .expr

Current expression evaluator: MASM - Microsoft Assembler expressions
To change the current expression evaluation syntax, use

0:000> .expr /s c++

Current expression evaluator: C++ - C++ source expressions

or

0:000> .expr /s masm

Current expression evaluator: MASM - Microsoft Assembler expressions

Use the ? command to evaluate expressions (using the default syntax).
The ?? command is used to evaluate a C++ expression (disregarding the
default selected syntax).

---

**Page 83**

Chapter 4= Debugging and Automation 191

eee The C++ syntax is preferable when type/symbol information is present and
you need to access structure members or simply leverage the C++ operators.

Numbers, if not prefixed with a base specifier, are interpreted using the
default radix setting. Use the n command to display the current number base,
orn base value to set the new default base.

When using MASM syntax, you can express a number in a base of your choice,
use the following prefixes:

m™ 0n123 for decimal
m 0x123 for hex

m™ 0t123 for octal

m Oy10101 for binary

Unlike evaluating with the MASM syntax, when using ?? to evaluate com-
mands, it is not possible to override the radix:

? Oyl0Ol -> works
?? OylOl -> does not work.

When the default radix is 16 and you try to evaluate an expression such as
abc, it can be confused between a symbol named abc or the hexadecimal number
abc (2748 decimal). To resolve the symbol instead, prepend ! before the variable
name: ? !abc.

As in the C++ language, the C++ evaluator syntax only permits the 0x prefix for
hex and the 0 prefix for octal numbers. If no prefix is specified, base 10 is used.

To mix and match various types of expression, use the @ec++ (expression)
Or @@masm (expression):

0:000> .expr

Current expression evaluator: MASM - Microsoft Assembler expressions

0:000> ? @@c++(@Speb->ImageSubsystemMajorVersion) + @@masm(0y1)
Evaluate expression: 7 = 00000007

The @@ prefix is a shorthand prefix that can be used to denote the alternative
expression evaluation syntax (not the currently set syntax):

0:000> .expr

Current expression evaluator: MASM - Microsoft Assembler expressions

0:000> ? @@(@$Speb->ImageSubsystemMajorVersion) + @@masm(Oy1)
Evaluate expression: 7 = 00000007

You do not have to specify @@c++ (...) because when MASM is the default,
@@ (...) will use the C++ syntax and vice versa.

---

**Page 84**

192

Chapter 4 = Debugging and Automation

Useful Operators

This section illustrates various useful operators that can be used in expressions.
For the sake of demonstration, we use the predefined pseudo-registers $ip and
$peb, which denote the current instruction pointer and the _PEB * of the current
process, respectively. Other pseudo-registers are mentioned later in the chapter.

The notation used is “operator (expression syntax)”, where the expression
syntax will be either C++ or MASM. Note that in the following examples the
MASM expression evaluator is set by default.

m Pointer->Field (C++)—As in the preceding example, you use the arrow

operator to access the field value pointed at by $peb and the offset of the
ImageSubsystemMajorVersion field.

sizeof (type) (C++)—This operator returns the size of the structure. This
can come in handy when you are trying to parse data structures or write
powerful conditional breakpoints:

0:000> ? @@c++ (sizeof (_PEB) )
Evaluate expression: 592 = 00000250

#FIELD_OFFSET (Type, Field) (C++)—This macro returns the byte offset
of the field in the type:

0:000> ? #FIELD OFFSET(_PEB, ImageSubsystemMajorVersion)
Evaluate expression: 184 = 000000b8

The ternary operator (C++)—This operator behaves like it does in the
C++ language:

0:000> ? @@c++(@Speb->ImageSubsystemMajorVersion >= 6 ? 1: 0)
Evaluate expression: 1 = 00000001

(type) Value (C++)—Type casting enables you to cast from one type to
another:

0:000> ? #FIELD OFFSET(_ PEB, BeingDebugged)

Evaluate expression: 2 = 00000002

0:000> ? @Speb

Evaluate expression: 2118967296 = 7e4ce000

0:000> ? #FIELD OFFSET(_PEB, BeingDebugged) + (char *)@$peb
Evaluate expression: 2118967298 = 7e4ce002

Note that you cast @$peb to (char*) before adding to it the offset of
BeingDebugged.

* (pointer) (C++)—Dereferencing operator:

0:000> dd @Sip L 4

012a9615 2ec048a3 8b5e5f01 90c35de5 90909090
0:000> ? *( (unsigned long *)0x12a9615 )
Evaluate expression: 784353443 = 2ec048a3

---

**Page 85**

Chapter 4= Debugging and Automation 193

Note that before dereferencing the pointer you have to give it a proper
type (by casting it).
™ poi(address) (MASM)—Pointer dereferencing:

0:000> ? @@masm(poi (0x12a9615) )
Evaluate expression: 784353443 = 2ec048a3

m™ hi|low (number) (MASM)—Returns the high or low 16-bit value of a number:

0:000> ? hi(0x11223344)

Evaluate expression: 4386 = 00001122
0:000> ? low(0x11223344)

Evaluate expression: 13124 = 00003344

™ by/wo/dwo (address) (MASM)—Returns the byte/word/dword value
when the address is dereferenced:

0:000> db @Sip L 4

012a9615 a3 48 00 00

0:000> ? by(@Sip)

Evaluate expression: 163 = 000000a3
0:000> ? wo(@Sip)

Evaluate expression: 18595 = 000048a3
0:000> ? dwo(@Sip)

Evaluate expression: 18595 = 000048a3

m™ pointer [index] (C++)—The array subscript operator enables you to
dereference memory using indices:

0:000> db @Sip L 10

012a9615 a3 48 cO 2e 01 5f Se 8b e5 5d
0:000> ? @@c++(((unsigned char *)@Sip) [3] )
Evaluate expression: 46 = 0000002e

The same thing can be achieved using MASM syntax and poi () or by ():

0:000> ? poi(@Sip+3) & Oxff

Evaluate expression: 46 = 0000002e
0:000> ? by(@Sip+3)
Evaluate expression: 46 = 0000002e

kee When the pointer [index] is used, the base type size will be taken
into consideration (unlike poi (), for which one has to take the type size into
consideration).

™ Sscmp("stringl", "string2") /S$sicmp("Stringl", "String2") (MASM)—
String comparison (case sensitive /case insensitive). Returns -1, 0, or 1, as
in C’s stremp() / stricmp():

0:000> ? S$scmp("practical", "practica")
Evaluate expression: 1 = 00000001

---

**Page 86**

194 Chapter 4= Debugging and Automation

0:000> ? S$scmp("practical", "practical")
Evaluate expression: 0 = 00000000

0:000> ? S$scmp("practica", "practical")
Evaluate expression: -1 = ffffffff
0:000> ? S$scmp("Practical", "practical")
Evaluate expression: -1 = ffffffff
0:000> ? Ssicmp("Practical", "practical")
Evaluate expression: 0 = 00000000

m Siment (address) (MASM)—Returns the image entry point for the image
existing in that address. The PE header is parsed and used:

0:000> 1lmvm ole32
start end module name
74b70000 74c79000 ole32

0:000> ? $iment (74b70000)
Evaluate expression: 1958154432 = 74b710c0
0:000> u Siment (74670000)
ole32! D11MainCRTStartup:

74b710c0O 8bff mov edi,edi
74b6710c2 55 push ebp
74b710c3 8bec mov ebp,esp

m Svvalid(address, length) (MASM)—Checks if the memory pointed at
by the address until address + length is accessible (returns 1) or inac-
cessible (returns 0):

0:000> ? @@masm(Svvalid(@Sip, 100) )
Evaluate expression: 1 = 00000001
0:000> ? @@masm(Svvalid(0x0, 100))
Evaluate expression: 0 = 00000000

m Sspat ("string", "pattern") (MASM)—Uses pattern matching to deter-
mine if the pattern exists in the string, and returns true or false.

Process Control and Debut Events

This section introduces the basic process control commands (such as single
stepping, stepping over, etc.) and the commands that can be used to change
how the debugger reacts to certain debug events.

Process and Thread Control

These are some commands that allow you control the flow of the debugger:
m t (F11)—Step into.

m gu (Shift+F11)—Go up. Steps out of the current function and back to the
caller.

---

**Page 87**

Chapter 4 = Debugging and Automation

195

m p (F10)—Step over.
m g (F5)—Go. Resumes program execution.
m Ctrl+Break—When the debuggee is running, use this hotkey to suspend it.

Note that the preceding commands work only with live targets.

I Mh

There are useful variations to the “resume,
instructions, including the following:

step into,” and “step over”

m [t|p]a Address—Step into. Steps over until the specified address is reached.

m gc—This is used to resume execution when a conditional breakpoint
suspends execution.

™ g[h|n]—This is used to resume execution as handled or unhandled when
an exception occurs.

Another set of tracing/stepping commands are useful to discover basic blocks:
m™ [p|t]c—Step over/into until a CALL instruction is encountered.

™ [p|t]h—Step over/into until a branching instruction is encountered (all
kinds of jump, return, or call instructions).

m™ [p|t]t—Step over/into until a RET instruction is encountered.

m™ [p|t]ct—Step over/into until a CALL or RET instruction is encountered.

Most of the preceding commands (tracing and stepping over) are implicitly
operating within the context of the current thread.
To list all threads, use the ~ command:

0:004> ~

O Id: 1224.13d8 Suspend: Teb: f£4ab000 Unfrozen
1 Id: 1224.1758 Suspend: Teb: ££4a5000 Unfrozen
2 Id: 1224.2920 Suspend: Teb: ££37£000 Unfrozen
3 Id: 1224.1514 Suspend: 1 Teb: ££37c000 Unfrozen

. 4 Id: 1224.b0 Suspend: 1 Teb: ££2£7000 Unfrozen

HPP

The first column is the thread number (decided by DbgEng), followed by a
pair of SystemProcessId.SystemThreadId in hexadecimal format.

The DbgEng commands work with DbgEng IDs, rather than the operating
system’s process/thread IDs.

To switch to another thread, use the ~Ns command, where N is the thread
number you want to switch to:

0:004> ~1s
eax=00000000 ebx=00bblab0 ecx=00000000 edx=00000000 esi=02faf9ec edi=00b2ec00
eip=7712c46c esp=02faf8a4 ebp=02fafa44 iopl=0 nv up ei pl nz na po ne

cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b ef1=00000202

---

**Page 88**

196

Chapter 4 = Debugging and Automation

ntdll!NtWaitForWorkViaWorkerFactory+0xc:
7712c46c c21400 ret 14h
0:001>

The debugger prompt also shows the selected thread ID in the prompt
ProcessID:ThreadId>.

You don’t have to switch to threads before issuing a command; for instance,
to display registers of thread ID 3, use the ~3 prefix followed by the desired
debugger command (in this case the r) command:

0:001> ~3r

eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=00000001 edi=00000001
eip=7712af2c esp=03lafb38 ebp=031lafcb8 iopl=0 nv up ei pl nz na pone
cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b ef1=00000202
ntdll!NtWaitForMultipleObjects+0xc:

7712af2c c21400 ret 14h

0:001> ~3t

eax=00000000 ebx=00000000 ecx=77072772 edx=00000000 esi=00000001 edi=00000001
eip=758c11b5 esp=03lafb50 ebp=031lafcb8 iopl=0 nv up ei pl nz na po ne
cs=0023 ss=002b ds=002b es=002b fs=0053 gs=002b ef1=00000202
KERNELBASE! WaitForMultipleObjectsEx+0xdc:

758c11b5 8bf8 mov edi,eax

To display the register values of all the threads, simply pass * as the thread
number.

kee Not all debugger commands can be prefixed with ~N cmd so that they yield
information about thread N. Instead, use the thread-specific command ~eN cmd.

If you are debugging various user mode processes (i.e., when the debugger is
launched with the -o switch), it is possible to switch from one process to another
using the | command. The following example uses Internet Explorer because
it normally spawns various child processes (with different integrity levels and
for various purposes):

C:\ dbg64>windbg -o "c:\Program Files (x86)\Internet Explorer\iexplore.exe"

Let it run, open a few tabs, and then let the debugger resume with g and then
suspend it and type |:

0:030>
0 id: 1818 child name: iexplore.exe
1 id: 1384 child name: iexplore.exe

To switch from one process to another, type |Ns, where Nis the process number:

0:030> |1s
1:083> |
# O id: 1818 child name: iexplore.exe

1 id: 1384 child name: iexplore.exe

---

**Page 89**

Chapter 4= Debugging and Automation 197

Once you switch to a new process, future commands will apply to this pro-
cess. Breakpoints you set for a process will not be present in the other process.

Kee Aliases and pseudo-registers will be common to all the processes being
debugged.

Monitoring Debugging Events and Exceptions

It is possible to capture certain debugging events and exceptions as they occur
and let the debugger suspend, display, handle, leave unhandled, or just ignore
the event altogether.

The DbgEng may suspend the target and give the user a chance to decide
what action to take in the follow two circumstances:

m Exceptions—These events happen when an exception triggers in the
context of the application (Access Violation, Divide By Zero, Single Step
Exception, etc.).

m Events—These events are not errors, they are triggered by the operat-
ing system to notify the debugger about certain activities taking place (a
new thread has been created or terminated, a module has been loaded or
unloaded, a new process has been created or terminated, etc.).

To list all the events, use the sx command. Equally, if you are using WinDbg,
you can navigate to the Debug/Event Filters menu to graphically configure the
events, as shown in Figure 4-1.

Command
0:000> sx
ct - Create thread - ignore
et -— Exit thread - ignore
cpr - Create process - ignore
epr - Exit process - break
ld - Load module - output
ud — Unload module - ignore x
ser -— System error - ignore
ibp - Initial breakpoint - break
iml - Initial module load - ignore iCreate thread — ignore — not handled ia Close
out - Debuggee output - output Exit thread - ignore —- not handled
Create process - ignore - not handled
av - Access violation - break - not handled Exit process - enabled - not handled Help
asrt - Assertion failure - break - not handled Load module - output - not handled
aph — Application hang - break — not handled Unload module - ignore - not handled
bpe - Break instruction exception - break System error - ignore — not handled
bpec - Break instruction exception continue — handled Initial breakpoint - enabled - handled
eh — C++ EH exception - second-chance break - not handled Initial module load - ignore — handled ‘Add
clr - CLR exception - second-chance break - not handled Debuggee output —- output — handled rae
clrn - CLR notification exception - second-chance break - handled Unknown exception — disabled - not handled
cce - Control-Break exception — break Access violation — enabled - not handled
cc — Control-Break exception continue — handled Assertion failure - enabled - not handled
cce - Control-C exception — break Application hang - enabled - not handled
ec - Control-C exception continue — handled Break instruction exception — enabled — handled
dn - Data misaligned - break - not handled C++ EH exception - disabled - not handled —
dbce - Debugger command exception - ignore — handled CLR exception - disabled - not handled Commands
gp - Guard page violation — break — not handled CLR notification exception - disabled - handled
ii - Illegal instruction - second-chance break - not handled Control-Break exception -— enabled - handled
ip — In-page 1/0 error — break - not handled Control-C exception — enabled — handled Execution
dz - Integer divide-by-zero - break - not handled Data misaligned - enabled - not handled © Enabled
iov - Integer overflow - break - not handled Debugger command exception — ignore — handled CO Disabled
ch - Invalid handle - break Guard page violation - enabled - not handled 2s
he - Invalid handle continue - not handled Illegal instruction - disabled - not handled © Output
isq - Invalid lock sequence - break - not handled In-page 1/0 error - enabled - not handled —
isc — Invalid system call — break — not handled Integer divide -by-zero — enabled — not handled O Ignore
3c - Port disconnected - second-chance break - not handled Integer overflow - enabled - not handled
svh - Service hang - break - not handled Invalid handle - enabled - not handled :
sse - Single step exception — break Invalid lock sequence - enabled - not handled Continue
ssec - Single step exception continue — handled Invalid system call - enabled —- not handled (©) Handled
sbo - Stack buffer overflow — break - not handled Port disconnected - disabled - not handled bai ||| ee
sov - Stack overflow - break - not handled < > © Not Handled
vs — Verifier stop - break - not handled ~ ~
vepp — Visual C++ exception - ignore — handled
wid — Wale debuanar — break — not handled
]0:000> |sx

Figure 4-1

---

**Page 90**

198

Chapter 4 = Debugging and Automation

The screenshot shows two sets of configuration to control events:

m Execution—Dictates what to do when that event takes place.
m Continue—Decides how to resume from the event or exception.

m Handled—Marks the exception as being handled (the application’s
exception handler will not trigger). This is useful when the debugger
breaks and you manually fix the situation and then resume the appli-
cation with the gh command.

m Not Handled—Lets the application’s exception handler take care of
the exception. Use the gn command to resume.

Use the following commands to control how events/exceptions are handled:

m sxe event—Enables breaking for an event

m sxd event—Disables breaking for an event

m sxr event—Enables output only for an event

m™ sxi event—lIgnores the event (do not event output anything)

The event parameter can be an exception code number, event short code
name, or * for any event.

A rather useful application of the sxe or the sxd commands is to catch module
loading or unloading. For example, when kernel debugging, to stop the debug-
ger when a certain driver is loaded, use the following command:

sxe ld:driver_name.sys

To associate a command with an event, use the sx- -c command event com-
mand. For example, to display the call stack each time a module is loaded, use
the following command:

sx- -c "k" ld

Registers, Memory, and Symbols

This section covers some of the useful commands that deal with registers man-
agement, memory contents inspection and modification, symbols, structures,
and other handy commands.

Registers

The r command is used to display register values or to change them.

Kee ~The x command can also be used to alter fixed-name aliases and pseudo-
registers values. This usage is covered in subsequent sections.

---

**Page 91**

Chapter 4 = Debugging and Automation

199

The general syntax of the r command is as follows:

r[M Mask|F|X] [RegisterName_Or FlagName[: [Num]Type] [=[Expression_Or Value]]]

Here is the simplest syntax of the r command:

r RegisterName|FlagName [= Expression _Or Value ]

If the expression or value is omitted, then r will display the current value of
the register:

0:001> r eax
eax=7f£fda000
0:001> r eax = 2
0:001> r eax
eax=00000002

To display the registers involved in the current instruction, use the r. command:

0:000> u rip Ll

O0007££6~£54d6470 48895c2420 mov qword ptr [rsp+20h] ,rbx
0:000> r.

rsp=000000c9~e256fbb8 rbx=00000000~00000000

0:000> u eip L1

user32 !MessageBoxA+0x3:

773922c5 8bec mov ebp, esp

0:000> r.

ebp=0018ff98 esp=0018ff78

Register Masks

The r command can be suffixed with the m character followed by a 32-bit mask
value. The mask designates which registers to display when r is typed without
parameters. Table 4-1 shows a short list of the mask values:

Table 4-1: Register Mask Values

REGISTER MASK VALUE DESCRIPTION

2 General registers

4 Floating-point registers

8 Segment registers

0x10 MMX

0x20 Debug registers

0x40 SSE XMM

0x80 Kernel mode: Control registers

0x100 Kernel mode: TSS

---

**Page 92**

200

Chapter 4 = Debugging and Automation

Kee Use the OR operator (|) to combine various masks.

To see the current mask, type rm:

0:000> rm

Register output mask is a:
2 - Integer state (64-bit)
8 - Segment registers

Now if you execute r, you should see only general-purpose registers and the

segment registers:

eax=025ad9d4 ebx=00000000 ecx=7c91056d edx=00ba0000 esi=7c810976 edi=10000080
eip=7c810978 esp=025ad780 ebp=025adbec iopl=0 nv up ei pl nz na po ne
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 ef1=00000202

To display all possible registers, set all the bits to one in the mask parameter

(mask Ox1ff):
kd> rM1ff
eax=025ad9d4 ebx=00000000 ecx=7c91056d edx=00ba0000 esi=7c810976 edi=10000080
eip=7c810978 esp=025ad780 ebp=025adbec iopl=0 nv up ei pl nz na pone
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 ef1=00000202
fpcw=027F: rn 53 puozdi fpsw=0000: top=0 cc=0000 -------- fptw=FFFF

fopcode=0000 fpip=0000:00000000 £fpdp=0000:00000000

st0= 0.000000000000000000000e+0000 stl= 0.303405511757512497160e-4933
St2=-3.685298464319287816590e-4320 st3= 0.000000015933281407050e-4357
st4=-0.008610620845784322250e-4310 st5= 0.000000125598791309870e-4184
st6=-0.008011795206688037930e+0474 st7=-1.#QNAN0000000000000000e+0000
mm0=0000000000000000 mm1=0127b52000584c8e

mm2=2390ccb400318a24 mm3=000000057c910732

mm4=003187cc00000000 mm5=000000117c910732

mm6=003187ec00000000 mm7=7c9107387c90ee18

xmm0=1.79366e-043 0 6.02419e+036 6.02657e+036

xmm1l=0 3.08237e-038 3.08148e-038 0

xmm2=3 .30832e-029 5.69433e-039 0 3.08147e-038

xmm3=5.6938e-039 0 9.62692e-043 5.69433e-039

xmm4=3 .04894e-038 2.12997e-042 3.07319e-038 5.69433e-039
xmm5=5.69528e-039 6.02651e+036 4.54966e-039 1.16728e-042

xmm6=5 .69567e-039 0 5.69509e-039 6.02419e+036

xmm7=4.54901e-039 5.69575e-039 0 5.69559e-039

cr0=8001003b cr2=7c99a3d8 cr3=07£40280

dr0=00000000 dr1=00000000 dr2=00000000

dr3=00000000 dré=ffff4f£0 dr7=00000400 cr4=000006£9

gdtr=8003£000 gdtl=03ff idtr=8003f400 idtl=07f£ tr=0028 Ildtr=0000

tee Some processor registers (GDT, IDT, control registers, etc.) can be displayed

in kernel mode debugging only.

---

**Page 93**

Chapter 4 = Debugging and Automation 201

To set the default mask, use the rm command followed by the desired mask
value:

0:000> rm 2|4|8

0:000> rm

Register output mask is f:
2 - Integer state (64-bit)
4 - Floating-point state
8 - Segment registers

The DbgEng provides shorthand flags for certain masks—namely, the floating-
point and the MMX registers.
To display floating-point registers, use rF; and to display XMM registers, use rx:

0:000> rF

fpcw=027F: rn 53 puozdi fpsw=4020: top=0 cc=1000 --p----- fptw=FFFF
fopcode=0000 fpip=0023:74b785bc fpdp=002b:00020a84

st0= 0.000000000000000000000e+0000 stl= 0.000000000000000000000e+0000

0:000> rX

xmm0=0 0 0 0
xmm1l=0 0 0 0
xmm2=0 0 0 0

Register Display Format

It is possible to specify how the registers should be displayed. This is very use-
ful in many cases, as illustrated in the following examples.

Displaying Registers in Floating-Point Formats

Suppose you're debugging and notice that register eax holds a floating-point value:

0:000> r eax
eax=3f8ccccd

To display it properly, use the following:

0:000> r eax:£f
eax=1.1

To display the contents of rax in double-precision, floating-point value, use this:

0:000> r rax
rax=4014666666666666
0:000> r rax:d
rax=5.1

---

**Page 94**

202

Chapter 4 = Debugging and Automation

Displaying Registers in Bytes/Word/Dword/Qword Formats

When registers are involved in data transfer, it is useful to see the register’s
individual bytes:

msvcrt !memcpy+0x220:

OOO0O7EE9 5f671a5d £30£7£40£0 movdqu xmmword ptr [rax-10h] ,xmm0
0:000> r xmm0
xmm0= 0 1.05612e-038 1.01939e-038 1.00102e-038

0:000> r xmm0:ub

xmm0=00 00 00 00 00 73 00 6c 00 6£ 00 62 00 6d 00 79
0:000> rX xmm0:uw

xmm0=0000 0000 0073 006c O06£ 0062 006d 0079

0:000> rX xmm0:ud

xmm0=00000000 0073006c O006£0062 006d0079

0:000> rX xmm0:uq

xmm0=000000000073006c 006£0062006d0079

In the preceding example, memcpy () uses the XMM registers to transfer 16
bytes at a time. You use the ub format to display the contents of xmmo in unsigned
bytes format, uw for word format, ud for double-word format, and ug for quad-
word format. To display in signed format, use the i prefix instead of u.

Display Selector Command

The display selector command has the following syntax:

dg FirstSelector [LastSelector]

It displays information about a given selector (or range of selectors). In this
case, you are interested in selector values that are currently set in one of the
x86/x64 registers—namely, the cs, ds, ss, gs, and fs registers.

Selectors are used in the segment part of an address in protected mode.

The following example executes the dg command for cs, ds, ss, gs, and fs,
respectively:

0:001> .foreach /s (sel "es ds ss gs fs") { dg sel; }
(cs Selector)

P Si Gr Pr Lo
Sel Base Limit Type 1 ze an es ng Flags

0023 00000000 f£fffffff Code RE Ac 3 Bg Pg P N1 O0000cf£b
(ds Selector)

P Si Gr Pr Lo
Sel Base Limit Type 1 ze an es ng Flags

002B 00000000 f£fffLLLL Data RW Ac 3 Bg Pg P NI 00000c£3

(ss Selector)

---

**Page 95**

Chapter 4= Debugging and Automation 203

P Si Gr Pr Lo
Sel Base Limit Type 1 ze an es ng Flags
002B 00000000 f£fffffLLL Data RW Ac 3 Bg Pg P N1 00000cf£3
(gs Selector)

P Si Gr Pr Lo
Sel Base Limit Type 1 ze an es ng Flags
002B 00000000 f£ffffffL Data RW Ac 3 Bg Pg P NI 00000cf3
(fs Selector)

P Si Gr Pr Lo
Sel Base Limit Type 1 ze an es ng Flags
0053 7£fda000 OO000fFF Data RW Ac 3 Bg By P NI1 000004f3

In MS Windows/user-mode applications, the cs, ds, es, ss, and gs selectors have
a base value of zero, thus the linear address is the same as the virtual address.
Conversely, the fs register is variable, changing its value from thread to
thread. The fs segment in user-mode processes points to the TEB (Thread

Environment Block) structure:

0:003> dg fs
Sel Base Limit Type

1 ze an

0053 ££306000 OO000fFE Data RW Ac 3 Bg By

(Switch to another thread)
0:003> ~2s

0:002> dg fs

Sel Base Limit Type

1 ze an

0053 ££4a5000 OO000ffL Data RW Ac 3 Bg By

Memory

es

ng

N1

ng

Nl

Flags

000004£f3

Flags

000004£3

Before describing memory-related commands, it is important to explain the
address and range notations because they are passed as arguments to most
commands that require a memory address and count.

The Address parameter can be any value, expression, or symbol that resolves
to a numeric value that can be interpreted as an address. The number 0x401000
can be treated as an address if the address is mapped in memory. The name
kerne132 will resolve to the image base of the module:

0:000> Imm kernel32

start end module name
75830000 75970000 KERNEL32
0:000> ? kernel32

Evaluate expression: 1971519488

= 75830000

---

**Page 96**

204

Chapter 4 = Debugging and Automation

A symbol such as module_name! SymbolName can be used as an address as
long as it resolves:

0:000> ? kernel32!GetProcAddress

Couldn't resolve error at 'kernel32!GetProcAddress'
0:000> ? kernelbase!GetProcAddress

Evaluate expression: 1979722334 = 76002a5e

It is possible to use any expression as an address (notwithstanding whether
the value resolves to a valid address or not):

0:000> ? (kernelbase!GetProcAddress - kernel32) / 0n4096
Evaluate expression: 2002 = 000007d2

The Range parameter can be specified in two ways. The first method is with
a pair of starting and ending addresses:

0:000> db 02c0000 02c0005
002c0000 23 01 00 00 00 00 #...

The second method is by using an address followed by the L character and
an expression (address L Expression_Or Value) that designs a count.

If the count is a positive value, then the starting address will be the specified
address, and the ending address is implied and equal to address + count:

0:000> db 02c0000 L5
002c0000 23 01 00 00 00 #....

If the count is a negative value, then the ending address becomes the specified
address, and the starting address becomes address - count:

0:000> db 02c0005 L-5
002c0000 23 01 00 00 00 #....

By default, the expression or the value passed after L cannot exceed 256MB.
This is to prevent accidentally passing very large values. To overwrite this
limitation, use L? instead of just L. For example, notice how the DbgEng will
complain about this big size:

0:000> db @Sip LOxfff£fLLEE
“ Range error in 'db @$ip lOxfffffffFt

When L? is used, the DbgEng will be happy to comply:

0:000> db @Sip L?0xfffffffFt
760039c2 83 e4 £8 83 ec 18 8b 4d-1c 8b cl 25 b7 7£ 00 00. ....... M...%....

---

**Page 97**

Chapter 4= Debugging and Automation 205

Dumping Memory Contents

The d command is used to dump memory contents. The general syntax is as
follows:

d[a|b|c|da|D|£|p|q|u|w|W] [Options] [Range]

Various formats can be used to display memory contents. The most common
formats are as follows:

m™ b,w,d, qg—For byte, word, double-word, and quad-word format, respectively
m £,D—For single and double-precision floating-point values, respectively
m a, u—To display ASCII or Unicode memory contents, respectively

m »—For pointer values (the size varies according to the current pointer
size of the target)

When the dp, dd, or dg are suffixed with s, the symbols corresponding to the
addresses will be displayed. This can be handy to discover function pointers
that are defined in an array or a virtual table:

(1)

0:011> bp combase!CoCreateInstance

(2)

0:024> g

Breakpoint 0 hit

combase!CoCreateInstance:

7526aeb0O 8bff mov edi,edi

0:011> ? poi(esp+4*5)

Evaluate expression: 112323728 = 06blec90

0:011> ? poi(poi(esp+4*5) )

Evaluate expression: 0 = 00000000

(3)

0:011> g poi(esp)

combase!CustomUnmarshaliInterface+0x15d:

752743e7 fe8ef0000000 dec byte ptr [esi+0F0h]

ds :002b:08664160=01

0:011> ? poi(06blec90)

Evaluate expression: 141774136 = 08734d38

(4)

0:011> dps 08734d38 L1

08734d38 752c9688 combase!CErrorObject:: vftable'

0:011> dps 752c9688 L3

752c9688 752f6bdf combase! [thunk] :CErrorObject: :QueryInterfaceadjustor{8}'
752c968c 752£6bd0 combase! [thunk] :CErrorObject: :AddRef~adjustor{8}'
752c9690 752a9b91 combase! [thunk] :CErrorObject: :Release adjustor{8}!'

Marker 1 adds a breakpoint on the following function:

HRESULT CoCreateInstance (
REFCLSID rclsid,

---

**Page 98**

206

Chapter 4 = Debugging and Automation

LPUNKNOWN pUnkOuter,
DWORD dwClsContext,
REFIID riid,
LPVOID *ppv)

We are interested in determining the pointer value (parameter 5) of the newly
created interface after the function returns. On marker 2, we resume execu-
tion. The program later breaks on the breakpoint and gets suspended. We then
inspect the fifth pointer location and dereference it. Its dereferenced value should
be NULL and initialized properly only if the function returns successfully. On
marker 3, we let the debugger run the CoCreateInstance function and return
to the caller. We then dereference the output pointer again. Finally, on marker
4, we use the dps command to display the address of the vftable, and then use
dps once more to display three pointers at the vftable.

Keegy dps is equivalent to dds on 32-bits targets, and to dqs on 64-bits targets.

Editing Memory Contents
To edit the memory contents, use the e command. The general syntax is as follows:

e[b|d|D|£|p|q|w] Address [Values]

kee If no suffix is specified after the e command, the last suffix that was previ-
ously used with e will be used. For instance, if ed were used the first time, then the
next time e alone is used, it will act as if it were ed.

Use the b, w, d, or gq format specifiers to set byte, word, dword, or qword values,
respectively, at the specified memory address:

0:000> eb 0x1b0000 11 22 33 44; db Ox1b0000 L 4

001b0000 11 22 33 44

0:000> ed 0x1b0000 Oxdeadbeef OxdeadcOde; dd 0x1b0000 L 2
001b0000 deadbeef deadcOde

It is possible to use single quotes to enter character values when using either
of the w/d or q formats. The DbgEng will respect the “endianness” of the target:

0:000> ed 1b0000 'TAGI'
0:000> db 1b0000 'TAGI1' L 4
001b0000 31 47 41 54 1GAT

Apart from editing the memory with integer values, the e command has other
format specifiers that allow you to enter other types:

---

**Page 99**

Chapter 4= Debugging and Automation 207

m e[£|D] (address values)—Sets a single or double-precision floating-pointer

number:

0:000> eD @$to 1999.99

0:000> dD @$to Ll

000000c9~e2450000 1999.99

m ep (address values)—Sets pointer-sized values. This command knows
how big a pointer is based on the currently debugged target.

m e[a|u] (address string)—Enters an ASCII or Unicode string at the given
address. The entered string will not be zero terminated:

0:000> £ Ox1b0000 LOx40 0x21 0x22 0x23; db 0x1b0000 LOx20;
Filled 0x40 bytes
001b0000 21 22 23 21 22 23 21 22-23 21 22 23 21 22 23 21
ec ce
001b0010 22 23 21 22 23 21 22 23-21 22 23 21 22 23 21 22
"HI "HI "HY "HY "HY "
0:000> ea 0x1b0000 "Hello world"; db 0x1b0000 L0x20
001b0000 48 65 6c 6c 6f 20 77 6f£-72 6c 64 23 21 22 23 21 Hello
world#!"#!
001b0010 22 23 21 22 23 21 22 23-21 22 23 21 22 23 21 22
"HI "HY "HI "HY "HY W
m e[za|zu] (address string)—As opposed to e[a|u], this command will

enter the zero character termination at the end of the string.
To fill a memory area with a given pattern, use the £ command:

f Address L Count Values

For example:

0:000> £ @eax LOx40 0x21 0x22 0x23; db @eax L0x20

Filled 0x40 bytes

001b0000 21 22 23 21 22 23 21 22-23 21 22 23 21 22 23 21 OE ee ce ce ee a
001b0010 22 23 21 22 23 21 22 23-21 22 23 21 22 23 21 22 "#!I"#HI"HINHINHIM

Miscellaneous Memory Commands
Following is another set of memory-related commands that come in handy:
ms [-[flags]type] Range Pattern—Searches the memory for a given
pattern
Moc Range For Addressl Address2—Compares two memory regions

m .dvalloc [Options] Size—Allocates memory in the process space of
the debugger:

0:000> .dvalloc 0x2000
Allocated 2000 bytes starting at 001c0000

m .dvfree [Options] BaseAddress Size—Frees the memory previously
allocated by .dvalloc

---

**Page 100**

208 Chapter 4= Debugging and Automation

m .readmem FileName Range—Reads a file from disk to the debuggee’s
memory:

kd> .readmem file.bin @eax L3
Reading 3 bytes.

m .writemem FileName Range—Writes the debuggee’s memory to a file on disk

Symbols

The following commands enable you to inspect symbols and structured data:

m dt [type] [address]—A very handy command to display the type of
an item at the given address:

S$ Display the type of the structure UNICODE STRING
0:000> dt UNICODE STRING
ole32!UNICODE STRING

+0x000 Length : Uint2B
+0x002 MaximumLength : Uint2B
+0x004 Buffer : Ptr32 Wchar

$$ Display type information and values in a type at a given address
0:000> dt UNICODE STRING 0x18fef4
ntdll! UNICODE STRING

"KERNEL32.DLL"

+0x000 Length : Ox18
+0x002 MaximumLength : Oxla
+0x004 Buffer : 0x00590168 "KERNEL32.DLL"

m dv [flags] [pattern]—Displays information about local variables

m x [options] [module_pattern] ! [symbol_pattern]—Displays symbol(s)
in a given module or modules

m !dh [options] Address—Dumps PE image headers

m !drvobj DriverObjectPtr [Flags]—Displays information about a
DRIVER_OBJECT object.

m !heap—Displays heap information

m™ !pool—Displays kernel pool information

Breakpoints
On the x86/x64 architecture, the DbgEng supports two types of breakpoints:

m Software breakpoints—These breakpoints are created by saving the
byte at the breakpoint address then replacing it with a OxCC byte (on

---

**Page 101**

Chapter 4 = Debugging and Automation

209

x64/x64). The debugger implements the underlying logic to handle the
breakpoint magic.

m Hardware breakpoints—Also known as processor or data breakpoints,
these breakpoints may or may not be present depending on the hardware
running the target. They are limited in count and can be set up to trigger
on read, write, or execute.

The simple syntax to create a software breakpoint is as follows:

bp Address ["CommandString"]
bu Address "CommandString"
bm SymbolPattern ["CommandString"]

Kee Please refer to the debugger documentation for the full syntax of the b*
commands.

To list breakpoints, simply use the b1 command:

0:001> bl

0 e 771175c9 0001 (0001) O:**** ntd1ll!RtlInitString+0x9

1 e 77117668 0001 (0001) O:**** ntdll!RtlInitUnicodeString+0x38
2 e 771176be 0001 (0001) O:**** ntdll! sin default+0x26

3 e 7711777e 0001 (0001) O:**** ntdll!sqrt+0x2a

4 e 771177c0 0001 (0001) O:**** ntdll!sqrt+0x6a

To disable breakpoints, use the bd command. Similarly, use the be command
to enable breakpoints, and the bc command to clear (delete) breakpoints.
You can specify a series of breakpoint IDs to enable, disable, or clear them:

be 0 2 4

Or a range:
be 1-3

Or simply all breakpoints:

be *

Unresolved Breakpoints

The bu command creates a breakpoint whose address is still unknown/unre-
solved or whose address may change if it belongs to a module (that is ASLR
aware) that is loaded and unloaded many times at different base addresses.

The debugger will try to reevaluate the breakpoint address when a new
module is loaded and if the symbol is matched the breakpoint becomes active.
When the module is unloaded, the breakpoint becomes inactive until the symbol
can be resolved again.

---

**Page 102**

210

Chapter 4 = Debugging and Automation

In short, the address of the breakpoint is not fixed and will automatically be
adjusted by the debugger.

Software Breakpoints

Software breakpoints can be created using the bp command. If the address can
be resolved when the breakpoint is created, then the breakpoint becomes active.
If the breakpoint cannot be resolved, the breakpoint will act like an unresolved
breakpoint and become active once the address can be resolved. If the module
at the breakpoint address is unloaded and then loaded again, the previously
resolved breakpoint address will remain fixed (as opposed to the unresolved
breakpoints).

Hardware Breakpoints

Hardware breakpoints can be created using the ba command. These breakpoints
are assisted by the hardware. To create a hardware breakpoint you need to
specify the address, access type, and size. The access type designates whether
to break on read (read/write), write (write only), or execute. The size designates
how big the item you are breaking on access for is. For instance, to break on
“word access,” specify the size 2.

kee «There is an architectural limit on the number of hardware breakpoints you
can have.

Conditional Breakpoints

Conditional breakpoints can be any type of breakpoint just described. In fact,
each breakpoint can be associated with a command. When a conditional com-
mand is associated with a breakpoint, the breakpoint can be considered a con-
ditional breakpoint.

The following example creates a conditional breakpoint such that when eax
has the value of 5, the breakpoint will suspend execution; otherwise, the break-
point will continue resuming execution:

0:000> uf kernelbase!GetLastError
KERNELBASE!GetLastError:

7661d0d6 64a118000000 mov eax,dword ptr fs: [00000018h]
7661d0dc 8b4034 mov eax,dword ptr [eax+34h]
7661d0dE c3 ret

0:000> bp 7661d0df ".if @eax!=5 { gc; }"
0:000> bl
0 e 7661d0d£ 0001 (0001) 0:*** KERNELBASE!GetLastError+0x9 ".if @eax!=5

{gc;}"

---

**Page 103**

Chapter 4= Debugging and Automation 211

It is possible to associate a more elaborate condition with a breakpoint. This is
covered in the section “Scripting with the Debugging Tools,” later in this chapter.

Inspecting Processes and Modules

The DbgEng enables you to inspect running processes, loaded/unloaded mod-
ules, or loaded kernel mode drivers.
To get the list of loaded and unloaded modules, use 1m:

0:001> Ilmn

start end module name
00400000 00405000 image00400000
5ca40000 5cb44000 MFC42
733a0000 733b9000 dwmapi
73890000 73928000 apphelp

Similarly, in kernel mode debugging, the 1m command will display the list
of loaded device drivers:

kd> lm n

start end module name

804d7000 806cd280 nt ntkrnilpa.exe
806ce000 806ee380 hal halaacpi.d1ll
b205e000 62081000 Fastfat Fastfat.SYS
b2121000 b2161380 HTTP HTTP.sys
b2d2b000 b2d4cd00 afd afd.sys
b2d4d000 b2d74c00 netbt netbt.sys
b2da75000 b2dccas0 tcpip tcpip.sys
b£800000 b£9c0380 win32k win32k.sys
£83e6000 £8472480 Ntfs Ntfs.sys

£86ca000 £86d6c80 VolSnap VolSnap.sys
£f8aaa000 f8aad000 BOOTVID BOOTVID.dll

Kee ~The n option was passed to minimize the default output of the 1m command.

To view module information (version, size, base, etc.), use the v switch for
verbose mode and m to specify a module name to match:

kd> lm v m *volsnap*
start end module name
£86ca000 £86d6c80 VolSnap
Loaded symbol image file: VolSnap.sys
Image path: VolSnap.sys
Image name: VolSnap.sys
Timestamp: Tue Aug 03 23:00:14 2004 (41107B6E)

---

**Page 104**

212. Chapter 4= Debugging and Automation

CheckSum: 00017B61
ImageSize: 0000CC80
Translations: 0000.04b0 0000.04e4 0409.04b0 0409.04e4

When in kernel mode, you have a full view of all running processes. Use the
!process extension command with the 0 0 flags to list all running processes:

kd> !process 0 0
*xx** NT ACTIVE PROCESS DUMP ****
PROCESS 823c8830 SessionId: none Cid: 0004 Peb: 00000000 ParentCid:
0000
DirBase: 00334000 ObjectTable: e1000c90 HandleCount: 246.
Image: System
PROCESS 820ed020 SessionId: none Cid: 017¢c Peb: 7£f£dd000 ParentCid:
0004
DirBase: 07£40020 ObjectTable: e14f£9c60 HandleCount: 21.
Image: smss.exe
PROCESS 81e98740 SessionId: 0 Cid: 0278 Peb: 7£fde000 ParentCid: 017c
DirBase: 07£40060 ObjectTable: e1010ac8 HandleCount: 517.
Image: winlogon.exe
PROCESS 81e865c0O SessionId: 0 Cid: 02a4 Peb: 7£fde000 ParentCid: 0278
DirBase: 07£40080 ObjectTable: e1a7a450 HandleCount: 265.
Image: services.exe
PROCESS 821139f0 SessionId: 0 Cid: 0354 Peb: 7££d9000 ParentCid: 02a4
DirBase: 07£400e0 ObjectTable: ela78ce0 HandleCount: 201.
Image: svchost.exe
PROCESS 81e68558 SessionId: 0 Cid: 0678 Peb: 7£f£dd000 ParentCid: 0658
DirBase: 07£401e0 ObjectTable: e177aa70 HandleCount: 336.
Image: explorer.exe

eee This is equivalent to using the ! for each process extension command
without any parameters.

It is possible to set breakpoints in user-mode processes using the kernel
debugger. First you need to switch to the correct process context, and for that
you need the EPROCESS value:

kd> !process 0 0 explorer.exe

PROCESS 81e68558 SessionId: 0 Cid: 0678 Peb: 7££dd000 ParentCid: 0658

DirBase: 07£401e0 ObjectTable: e177aa70 HandleCount: 336.
Image: explorer.exe

Then use the .process /r /p EPROCESS command to switch to the context
of the desired process:

kd> .process /r /p 81e68558
Implicit process is now 81e68558
.cache forcedecodeuser done
Loading User Symbols.........

---

**Page 105**

Chapter 4 = Debugging and Automation

213

At this point, after the context switch, use 1m to not only list the loaded kernel
drivers but also the user-mode modules.
The next example sets a breakpoint at kerne132!CreateFilew for that EPROCESS:

(1)

kd> bp /p 81e68558 kernel32!CreateFilew

(2)

kd> bl

0 e 7¢c810976 0001 (0001) kernel32!CreateFilew
Match process data 81¢68558

(3)

kd>g

Breakpoint 0 hit

kernel32!CreateFilew:

001b:7¢c810976 8bff mov edi,edi

(4)

kd> .printf "%Smu\n", poi(@esp+4) ;

c:\Temp\desktop. ini

In marker 1, we set an EPROCESS filter with the bp /p EPROCESS command so
that only the explore.exe process triggers the breakpoint. Marker 2 lists the
breakpoints. Note that it will only match for a certain EPRocEsS. At marker 3
we resume execution and wait until the breakpoint triggers. At marker 4, we
display the filename that was accessed. Marker 4 will become much clearer after
you read the “Language” section later in this chapter.

Now suppose you want to display all processes that called the createFilew
API and display which filename was referenced:

kd> bp kernel32!CreateFileW "!process @$proc 0;.printf "Smu\n",poi(@esp+4) ;gc;"

This will break whenever any user-mode process hits the breakpoint, and
then the breakpoint command will invoke ! process with the current EPROCESS
(set in the pre-defined pseudo-register $proc) to display the current process
context information, display the filename, and finally resume execution with gc.

ROM !process @S$proc 0 is equivalentto !process -1 0.

When execution is resumed, you see this redacted output:

kd> g

PROCESS 82067020 SessionId: 0 Cid: 0138 Peb: 7£fdf£000 ParentCid: 02a4
DirBase: 07£40260 ObjectTable: elb6é6ef8 HandleCount: 251.

Image: vmtoolsd.exe

C: \WINDOWS\SoftwareDistribution\DataStore\DataStore.edb
PROCESS 81dcOda0 SessionId: 0 Cid: 0204 Peb: 7££d5000 ParentCid: 03fc

---

**Page 106**

214 = Chapter 4= Debugging and Automation

DirBase: 07f£40280 ObjectTable: elba8ea8 HandleCount: 177.
Image: wuauclt.exe

PROCESS 81e68558 SessionId: 0 Cid: 0678 Peb: 7£f£dd000 ParentCid: 0658
DirBase: 07f£401e0 ObjectTable: e177aa70 HandleCount: 362.
Image: explorer.exe

C:\WINDOWS\media\Windows XP Start.wav

PROCESS 81e68558 SessionId: 0 Cid: 0678 Peb: 7£f£fdd000 ParentCid: 0658
DirBase: O07f£401le0 ObjectTable: e177aa70 HandleCount: 351.
Image: explorer.exe

C:\WINDOWS\WinSxS\Policies\x86_ Policy.6.0.Microsoft .Windows.Common-Controls
_6595b64144ccfldf x-ww_5ddad775\6.0.2600.2180.Policy
PROCESS 820f0020 SessionId: 0 Cid: 0260 Peb: 7£fd£000 ParentCid: 017c
DirBase: 07£40040 ObjectTable: e1503128 HandleCount: 343.
Image: csrss.exe

Miscellaneous Commands

This section introduces several miscellaneous debugger commands, the .printf£
command, along with the format specifiers it supports, and describes how to
use the Debugger Markup Language (DML) with .print£ or other commands
that support DML.

The .printf Command

The .print£ command is one of the most useful commands to help display
information from scripts or commands. As in the C language, this command
takes format specifiers. Following are a few important ones:

™ %p (pointer value)—Displays a pointer value.

ol?

d, x, su (number value)—Displays integer values. The syntax is very
similar to C’s format specifiers.

m zma / smu (pointer value)—Displays the ASCII/Unicode string at the
specified pointer.

m %msa / smsu (pointer value)—Displays the ANSI_STRING / UNICODE_STRING
value at the specified pointer.

m %y (pointer value)—Displays the symbol name (and displacement if any)
at the specified pointer.

---

**Page 107**

Chapter 4= Debugging and Automation 215

Here is a simple example:

0:000> .printf "t0=%d t1l=%d eax=%x ebx=%d\n", @St0, @$t1, @eax, @ebx
t0=0 t1=0 eax=5 ebx=8323228

There is no %s specifier to expand string arguments. The following example
expands the value of the user-defined alias by embedding it in the format
parameter:

0:000> aS STR "TheValue"

0:000> al
Alias Value
STR TheValue

0:000> .printf "This value of string is ${STR}\n"

The .printf command can make use of the Debugger Markup Language
(DML). To use DML with .print£, specify the /D switch.

Kee = DML works only in WinDbg.

To display with strings with colors, use the col markup:

0:000> .printf /D "<col fg=\"emphfg\">Hello</col> world\n"
Hello world

It is also possible to use the u, i, and b tags for underline, italic, and bold,
respectively:

0:000> .printf /D "<u>underline</u> <b>bold</b> <i>italics</i>\n";
underline bold italics

A very useful markup is the 1ink because it makes the output clickable and
associated with a command:

0:000> .printf /D "Click <link cmd=\"u 0x401000\">here</link>\n"
Click here

Some debugger commands also take the /D switch. For example, 1m /p will
list the modules, and each module is clickable. When a module is clicked, the
command 1mvm modulename will be issued.

kee Usethe .prefer dml 1commandto toggle a global setting that tells com-
mands that support DML to prefer DML when applicable.

---

**Page 108**

216

Chapter 4 = Debugging and Automation

For more information, check dm1.doc in the debugging tools distribution.

Other Commands

Before ending our discussion about debugger commands, we list a few more
useful commands:

m #—Searches for a disassembly pattern.
m™ !gle—Returns the last error code.

™ .logopen/.logfile/.logappend/.logclose—Commands to manage log-
ging of output from the command window to text files.

m .load—Loads a debugger extension.

m .cls—Clears the debugger’s output window. (This command does not
work in scripts because it is not part of the DbgEng scripting language.)

m .effmach—Changes or displays the processor mode that the debugger
uses. It is useful when debugging WOW64 processes. This command is
also similar to the extension command !wow64exts.sw.

Scripting with the Debugging Tools

This section illustrates important scripting features in the DbgEng that are use-
ful for automating reverse engineering and debugging tasks.

Pseudo-Registers

The DbgEng supports pseudo-registers to hold certain values. All of the pseudo-
registers start with the $ sign. Prefixing a pseudo-register or a register with the
@ sign tells the interpreter that the identifier is not a symbol, thus no exhaustive,
sometimes slow, symbol lookup will take place.

Predefined Pseudo-Registers

In this section we introduce some useful predefined pseudo-registers. They
can be used in expressions or as parameters to debugger commands or scripts.
Please note that some pseudo-registers may or may not be defined, depending
on the debugged target.

m $csp—tThe current call stack pointer. This is useful because you don’t
have to guess if you should use esp or rsp.

m $ip—tThe current instruction pointer. Similarly, a dot (.) can be used to
denote the current instruction pointer.

---

**Page 109**

Chapter 4= Debugging and Automation 217

m Sretreg/Sretreg64—The return registers (typically eax, edx: eax, Or rax).

m sp—The first value that the last d? command displayed:

0:000> dd @Sip L 1

O012aa5e5 012ec188

0:000> ? @Sp

Evaluate expression: 19841416 = 012ec188
0:000> dw @Sip+2 L 1

O1l2aa5e5 c188

0:000> ? @Sp

Evaluate expression: 49544 = 0000c188
0:000> db @$Sip+2 L 1

Ol2aa5e5 88

0:000> ? @Sp

Evaluate expression: 136 = 00000088

m sra—The current return address. This is equivalent to poi (@$csp).

m Sexentry—The entry point address of the first executable of the current
process. This is very useful when debugging a program from the begin-
ning because DbgEng does not break on the entry point but in the kernel.

m™ speb—Process Environment Block. This pseudo-register has the following
type: ntd1ll! PEB *.

m Sproc—The EpRocEss* address of the current process in kernel mode. In
user-mode it equates to $peb.

steb—Thread Environment Block of the current thread. It has the follow-
ing type: ntdll!_TEB*.

$thread—ETHREAD* in kernel mode. In user-mode it is same as Steb.
$tpid—tThe current process id.

$tia—tThe current thread id.

$ptrsize—The pointer size from the point of view of the debuggee. If
your host OS is 64-bit and you are debugging a 32-bit process, then $ptr-
size=4. In kernel mode it returns the pointer size of the target machine.

m sSpagesize—The number of bytes per memory page (usually 4,096).
m $dbgtime—The current time (based on the computer running the debugger).

m sbpNuM—The address associated with the breakpoint number:

0:000> bl
0 e 012aa597 0001 (0001) O:**** calc!WinMainCRTStartup+0xf
1 e 012aa5ab 0001 (0001) O:**** calc!WinMainCRTStartup+0x23
0:000> ? @S$bpo
Evaluate expression: 19572119 = 012aa597
0:000> ? @$bp1
Evaluate expression: 19572139 = 012aa5ab

---

**Page 110**

218 Chapter 4= Debugging and Automation

m sexp—The value of the last expression evaluated:

0:000> r StO = 1+ 4
0:000> ? @$exp
Evaluate expression: 5 = 00000005

or
0:000> ? Esp
Evaluate expression: 1637096 = 0018fae8
0:000> ? @$exp
Evaluate expression: 1637096

0018fae8

The first example assigns a value into a pseudo-register after it was evaluated.
You can see how sexp returns the last value. The same is true for the second
example, which evaluates the value of the esp register.

User-Defined Pseudo-Registers

In addition to the pre-defined pseudo-registers, DogEng enables users to define

their own set of pseudo-registers. DbgEng provides 20 user-defined pseudo-

registers (UDPRs) for use and to store integer values. They are $to to $t19.
The r command is used to assign values to those registers:

0:000> r $tO = 1234
0:000> ? @StO
Evaluate expression: 4660 = 00001234

Because numbers can be pointers, it is possible to store typed pointers into
those pseudo-registers using the r? command:

(1)
0:000> ? poi(@$ip)
Evaluate expression: 409491562 = 1868586a

(2)

0:000> r? $tO = @@c++((unsigned long *)@S$ip)
(3)

0:000> ? @@c++(*@St0)

Evaluate expression: 409491562 = 1868586a

On marker 1, we dereference and evaluate the value pointed to by sip. On
marker 2, we use r? to assign a C++ expression to $t0; the cast operator is used
to return a typed pointer (of type unsigned long *) into sto. Finally, on marker
3 we use the C++ dereferencing operator to dereference sto. (This would have
not been possible without having a previously typed sto or without preceding
the expression by a cast.)

Here’s another example:

0:000> r? $StO = @@c++ (@$Speb->ProcessParameters->ImagePathName)
0:000> ? StO

---

**Page 111**

Chapter 4 = Debugging and Automation

219

Evaluate expression: 0 = 00000000

0:000> ?? @StoO

struct _UNICODE STRING
"c:\windows\syswow64\calc.exe"

+0x000 Length : 0x38
+0x002 MaximumLength : Ox3a
+0x004 Buffer : 0x0098189e "c:\windows\syswow64\calc.exe"

Note that when you evaluate sto with ?, you get zero. When you use the C++
evaluation syntax ??, however, you get the actual typed value.
Symbols, all kinds of pseudo-registers, or aliases can also be used in expressions.

Aliases

An alias is a mechanism that enables you to create equivalence between a
value and a symbolic name. By evaluating the alias you get the value that was
assigned to the alias.

The DbgEng supports three kinds of aliases:

m User-named aliases—As the name implies, these aliases are chosen by
the user.
m Fixed-name aliases—There are ten of them, named suo .. $u9.

m Automatic aliases—These are pre-defined aliases that expand to certain
values.

User-Named Aliases

This section describes how to create and manage user-defined aliases and
explains how they are interpreted.

Creating and Managing User-Named Aliases

The following commands are used to create user-named aliases:

mas AliasName Alias_Equivalence—Creates a line equivalence for the
given alias:

as MyAlias lm;vertarget

This will create an alias for two commands: 1m and then vertarget. You
can execute both commands by invoking MyAlias.

m aS AliasName Alias_Equivalence—Creates a phrase equivalence for the
given alias. That means a semicolon will terminate the alias equivalence
(unless the equivalence was enclosed in quotes) and start anew command.

aS MyAlias 1lm;vertarget
aS MyAlias "lm;vertarget"

---

**Page 112**

220 Chapter 4= Debugging and Automation

The first line will execute two things: create an alias with value 1mand then
execute the vertarget command. The second line (because the equivalence
is enclosed in quotes) defines the alias with value 1m; vertarget.

kee User-defined alias names cannot contain the space character.

Other alias commands include the following:
m al—Lists already defined aliases.

mad [/q] AliasName|*—Deletes an alias by name or all aliases. The /q
switch will not show error messages if the alias name was not found.

The as command can used to create aliases that equate to environment vari-
ables values, expressions, file contents, command output, or even string contents
from the debuggee’s memory:

m aS /f AliasName FileName—Assigns the contents of a file to the alias:

0:000> aS /f AliasName c:\temp\lines.txt
0:000> al
Alias Value
AliasName linel
line2
line3
line4
line5

m aS /x AliasName Expression64—Assigns the 64-bit value of an expres-
sion to the alias. This is useful in many ways, especially when assigning
the value of an automatic alias to a user-named alias:

0:000> r StO = 0x123
0:000> as /x AliasName @StoO

0:000> al

Alias Value
AliasName 0x123
0:000> as IncorrectAlias @St0O
0:000> al

Alias Value
AliasName 0x123

IncorrectAlias @sto

---

**Page 113**

Chapter 4= Debugging and Automation 221

Note that the first as /x usage correctly assigned the value 0x123 to the
alias, whereas the second as assignment took the literal value of esto
(because of the missing /x switch).

as /e AliasName EnvVarName—Sets the AliasName alias to the value of
the environment variable called EnvVarName:

0:000> as /e CmdPath COMSPEC

0:000> al
Alias Value
CmdPath C:\Windows\system32\cmd.exe

as /ma AliasName Address—Sets the content of the null-terminated
ASCII string pointed to by the address in the alias:

0:000> db 0x40600C

0040600c 54 6f 6£ 6c 62 61 72 57-69 6e 64 6£ 77 33 32 00 ToolbarWin-
dow32.

0:000> as /ma Strl 0x40600C

0:000> al
Alias Value
Str1 ToolbarWindow32

as /mu AliasName Address—Sets the content of the null-terminated
Unicode string pointed to by the address in the alias

as /ms[a|u] AliasName Address—Sets the contents of an ASCII_STRING
(structure defined in the DDK) or uNICODE_STRING in the alias:
(1)

0:000> dt UNICODE STRING
ntdl1! UNICODuE_STRING

+0x000 Length : Uint2B
+0x002 MaximumLength : Uint2B
+0x004 Buffer : Ptr32 Uint2B

(2)
0:000> ?? sizeof (_ UNICODE STRING)
unsigned int 8

(3)
0:000> ?? @@c++ (@Speb->ProcessParameters->D11Path)
struct _UNICODE_STRING
"C:\Windows\system32\NV"
+0x000 Length : Ox2c
+0x002 MaximumLength : Ox2e
+0x004 Buffer : 0x001f1880 "C:\Windows\system32\NVv"

---

**Page 114**

222 Chapter 4= Debugging and Automation

(4)
0:000> dd @@c++(&(@$peb->ProcessParameters->D11Path)) L2
001f1408 002e002c 001£1880

(5)

0:000> db 001f1880 L2e

001£f1880 43 00 3a 00 5c 00 57 00-69 00 6e 00 64 00 6£ 00
C.:.\.W.i.n.d.o.

001£1890 77 00 73 00 5c 00 73 00-79 00 73 00 74 00 65 00
w.s.\.s.y.s.t.e.

001f18a0 6d 00 33 00 32 00 5c 00-4e 00 56 00 00 00 m.3.2.\.N.V...

(6)
0:000> as /msu D1llPath @@c++(&(@$peb->ProcessParameters->D11Path) )

0:000> al
Alias Value
D11lPath Cc: \Windows\system32\NV

At marker 1, we display the fields of the _UNICODE_STRING structure, and
at marker 2 we display the structure’s size using the C++ evaluator. Similarly,
marker 3 uses the C++ typed evaluation to dump the value of D11Path field.
Marker 4 uses the & operator to dump the _UNICODE_STRING field contents, and
marker 5 dumps the Buffer address. Finally, marker 6 uses the as command to
create an alias with its contents read from a _UNICODE_STRING pointer.

Interpreting User-Named Aliases

User-named aliases can be interpreted using the basic syntax ${AliasName} or
by simply typing the alias name. The former should be used when the alias is
embedded in a string and not surrounded by space characters:

0:000> aS AliasName "Alias value"
0:000> .printf "The value is >${AliasName}<\n"
The value is >Alias value<

When an alias is not defined, alias evaluation syntax remains unevaluated:

0:000> .printf "The value is >${UnkAliasName}<\n"
The value is >${UnkAliasName}<

The following switches control how the aliases are interpreted:

m s{/d:AliasName }—Evaluates to 1 if the alias is defined, and 0 if the alias
is not defined. This switch comes in handy when used ina script to deter-
mine whether an alias is defined or not:

0:000> .printf ">${/d:AliasName}<\n"

>1l<

---

**Page 115**

Chapter 4= Debugging and Automation 223

0:000> .printf ">${/d:UnkAliasName}<\n"

>0<

m ${/f£:AliasName }—When this switch is used, an undefined alias will
evaluate to an empty string or to the actual value if the alias was defined:

0:000> .printf ">${/£:DefinedAliasName}<\n"
>Alias value<
0:000> .printf ">${/£:UndefinedAliasName}<\n"

><

m s{/n:AliasName}—Evaluates to the alias name or remains unevaluated
if the alias is not defined:

0:000> .printf ">${/n:AliasName}<\n"
>AliasName<

0:000> .printf ">${/n:AliasName2}<\n"
>${/n:AliasName2}<

0:000> .printf ">${/n:UnkAliasName}<\n"
>${/n:UnkAliasName}<

m ${/v:AliasName}—This switch prevents any alias evaluation:

0:000> .printf ">${/v:AliasName}<\n"
>${/v:AliasName}<

0:000> .printf ">${/v:UnkAliasName}<\n"
>${/v:UnkAliasName}<

After an alias is defined, it can be used in any subsequent command (as a
command or a parameter to a command):

0:000> aS my_ printf .printf

0:000> al
Alias Value
my_ printf -printft

When used as a command:

0:000> ${my printf} "Hello world\n"
Hello world

0:000> my printf "Hello world\n"
Hello world

When used as a parameter to a command:

0:000> .printf "The command to display strings is >${my_printf£}<\n"
The command to display strings is >.printf

---

**Page 116**

224 Chapter 4= Debugging and Automation

0:000> .printf "The command to display strings is my printf \n"
The command to display strings is printf

When reassigning values to user-defined aliases, note the following:
m Using the as command as follows produces an error:
0:000> aS MyVar 0n123;.printf "v=%d", ${MyVar}
v=Couldn't resolve error at '${MyVar}'
The reason for this error is because aliases are expanded in new blocks
only. This can be remedied with the following:
0:000> aS MyVar 0n123;.block { .printf "v=%d", ${Myvar}; }
v=123
m The /v: switch behaves like the /n: switch when used with as, as, and

ad. The reason we mention this is illustrated in the following example:

0:000> aS MyVar 0n123;.block { aS /x MyVar ${Myvar}+1 }

0:000> al

Alias Value
0n123 Ox7c
MyVar 0n123

The first command creates the Myvar alias and increments its value by
one; however, a new alias named 0n123 is created. That’s because the
MyVar alias has been replaced by its equivalent instead of being used as
an alias name.

What you instead need to do is let the as command know that Myvar is
the alias name, and its value should not be expanded or evaluated. This is
where the /v: switch, when used with the as or the aS command, should
be used:

0:000> aS MyVar 123;.block { aS /x ${/v:MyVar} ${Myvar}+1 };al
Alias Value

Notice that now, when ${/v:MyVar} is used in conjunction with as, it
evaluates to the alias name (like the ${/n:AliasName} would).

---

**Page 117**

Chapter 4= Debugging and Automation 225

Fixed-Name Aliases

As mentioned earlier, there are 10 fixed-name aliases named suo through sug.
While the fixed-name aliases look like registers or pseudo-registers, they are
not. To assign values to them, use the r command followed by $. and the alias

name, like this:

(1)

0:000> r $.u0
(2)

0:000> r $.ul = 0x123
(3)

0:000> r $.u2
(4)

0:000> Sud "Su2\n"

Hello world

(5)

0:000> Sud "Su2, ul=%x", Sul
Hello world, ul=123

-printf

Hello world

Marker 1 aliases suo to the .printf command. Note the $. prefix and that
the .printf command is purposely not enclosed with quotes in the equivalence.
Marker 2 defines $ui with a numeric value, and marker 3 defines $u2 with a
string value. Marker 4 uses suo as an equivalent to the .print£ command and
prints $u2, which is enclosed in quotes and resolves to “Hello world.” Finally,
marker 5 prints the value $u1 in a similar fashion to marker 4.

Kew Always use $. when defining the alias; however, when using the alias you do
not need to use $ . or even the @ sign as you do for pseudo-registers or aliases.

Fixed-name alias replacement has a higher precedence than user-named aliases.

Automatic Aliases

The DbgEng defines a few aliases when the debugging session starts. The auto-
matic aliases are similar to the pre-defined pseudo-registers except that they
can also be used with the ${} syntax (like user-named aliases).
The following registers are defined:

m@ Sntnsym
m@ Sntwsym
m sntsym
||

$CurrentDumpFile

---

**Page 118**

226 Chapter 4= Debugging and Automation

m sCurrentDumpPath
@™ sCurrentDumpArchiveFile

@™ sCurrentDumpArchivePath

To illustrate this, the following invokes the cdb command-line debugger with
the -z switch to open a crash dump file, and uses -cf£ script .wds to execute a
series of commands from a text file:

c:\Tools\dbg>cedb -cf av.wds -z m:\xp_kmem.dmp
The contents of the script file is as follows:

-printf "Script started\n"

.logopen @"${$CurrentDumpFile}.log"

!analyze -v

. Logclose

-printf "Script finished, quitting\n"

q

When the debugger starts, it will interpret each line in av.wds:
1. Print a startup message.

2. Open a log file that has the name of the current crash dump file with . 10g
appended to it. Note how you expand to automatic alias with the ${}
syntax.

3. Issue the !analyze -v command.

4. Close the log file, print a quit message, and exit the debugger with the q
command.

kee The @ sign is used to define a literal (or raw) string. See the upcoming
“Characters and Strings” section.

Language

In this section, we discuss the scripting language, tokens, and commands.

Comments

Use the $s command to specify comments. For instance:

$s This is a comment
$s This is another comment

---

**Page 119**

Chapter 4 = Debugging and Automation

227

To use more than one comment on a line with multiple statements, use the
semicolon character to terminate the comment:

r eax = 0; $S clear EAX ; r ebx = ebx + 1; $S increment EBX;

The asterisk (*) can also be used to create comments; however, the entire line
after the asterisk will be ignored even if a semicolon delimiter is used:

r eax = 0; * clear EAX ; r ebx = ebx + 1;

The preceding command will just clear EAX; it won’t increment EBX by one.
There is a slight difference between the $$ comment specifier and the .echo
command. The .echo command displays the line instead of just ignoring it.

Characters and Strings
Characters are specified when enclosed in single quotes:

0:000> @dvalloc 1

0:000> eb @StO 'a' 'b' 'c! 'd!' '£' 'g!
0:000> db @StO L 6

02250000 61 62 63 64 66 67

Strings are specified with double quotes:

0:000> ea @StO "Practical reverse engineering";

0:000> db @StO L20

02250000 50 72 61 63 74 69 63 61-6c 20 72 65 76 65 72 73 Practical revers
02250010 65 20 65 6e 67 69 6e 65-65 72 69 6e 67 00 00 00 e engineering...

As in C, the string may contain escape sequences; therefore, you need to
escape the sequence in order to get the correct result:

(1)

0:000> .printf "c:\\tools\\dbg\\windbg.exe\n"
c:\tools\dbg\windbg.exe

(2)

0:000> .printf "a\tb\tce\n1\t2\t3\n"

a b

1 2 3

The first command escaped the backslash with the escape character. The
second example uses the horizontal tab escape sequence (\t).

The DbgEng allows the use of raw strings; such strings will be interpreted
literally without taking into consideration the escape sequence. To specify a
literal string, precede the string with the at sign (@):

---

**Page 120**

228

Chapter 4 = Debugging and Automation

(1)

0:000> .printf @"c:\tools\dbg\windbg.exe\n";.printf "\n";
c:\tools\dbg\windbg.exe\n

(2)

0:000> .printf @"a\tb\tc\n1\t2\t3\n"

a\tb\tce\n1\t2\t3\n

Notice how the escape sequences remained as specified without being inter-
preted. Similarly, if you have a user-named alias that was created from memory
contents and you want to evaluate it literally, also prefix the ${} with e:

(1)
0:000> aS /mu STR 0x3cba030

0:000> al
Alias Value
STR c:\Temp\file.txt

(2)

0:000> .printf "S${STR}\n";
C:Tempfile.txt

(3)

0:000> .printf @"S{STR}";.printf "\n";
C:\Temp\file.txt

Marker 1 creates a user-named alias from the zero-terminated Unicode string
at the specified memory address and displays the list of aliases. Marker 2 prints
the alias value. (Notice that the output is not as intended.) At marker 3, after
prefixing the string with @, the output is correct.

Blocks

A block can be created via the .block command followed by opening and clos-
ing curly braces ({_ }):

- block

{

$$ Inside a block ...
- block

{

$S Nested block ...

}
}

When a user-named alias is created in a script, its value won't be evaluated/
interpreted as intended unless a new block is created:

aS MyAlias (@eax + @edx)
- block

{

$$ Inside a block ...

---

**Page 121**

Chapter 4 = Debugging and Automation

229

printf "The value of my alias is %X\n", ${MyAlias}

Conditional Statements

The .if, .elsif, and .else command tokens are used to write conditional
statements.

The usage of .if and .elsif is similar to other languages where they take a
condition. The condition can be any expression that evaluates to zero (treated
as false) or a non-zero value (treated as true):

r StO = 3;
-if (@St0==1)

{

-printf "one\n";

}

-elsif @St0==

{

-printf "two\n";

}

-elsif (@$t0==3)

{

-printf "three\n";

-printf "unknown\n";

kee The use of parentheses around the condition is optional.

All the built-in repetition structures and conditional statements require the
use of the curly braces ({ and }) and thus create a block, which results in the
proper evaluation of aliases:

aS MyAlias (@eax + @edx)
-if (1)

{

SS Inside a block ...
-printf "The value of my alias is %X\n", ${MyAlias}

}

You can also compare strings with .if using a few different methods:

$$ By enclosing the strings to be compared in single quotes:
if '${my_alias}'=='value'
{

-printf "equal\n";

}

---

**Page 122**

230

Chapter 4 = Debugging and Automation

.else

-printf "not equal!\n";

$$ By using the MASM operator scmp (or sicmp):
.if $scmp("${my_alias}", "value")

{

-printf "equal\n";

$$ By using the MASM operator spat:
.if $spat("${my_alias}", "value")

{

-printf "equal\n";

-printf "not equal!\n";

The DbgEng also provides the j command, which can be compared to C’s

ternary operator ( cond ? true-expr: false-expr), except that it runs com-
mands instead of returning expressions:

j Expression [']Command-True['] ; [']Command-False[']

The following is a very simple example with one command being executed

in both cases (true or false):

0:000> r $tO = -1

0:000> j (@$StO < 0) x $tO = @§t0-1 ; r $tO = @§t0+1
0:000> ? StoO

Evaluate expression: -2 = fffffffe

The single quotes are optional in most cases; specify them if more than one

command is to be executed:

0:000> r $tO = 2
0:000> j (@StO < 0) 'r Sto
'r Sto

@$t0-1;.echo Negative value' ;
@St0+1;.echo Positive value'

Positive value
0:000> ? Sto

Evaluate expression: 3 = 00000003

It is common to use the } command as part of breakpoint commands to form

conditional breakpoints.

The following example suspends the debugger (note the empty single quotes

that specify that no command should be executed when the expression evaluates
to True) only when the return address matches a certain value:

---

**Page 123**

Chapter 4 = Debugging and Automation

231

0:000> bp user32!MessageBoxA "j (@$ra=0x401058) '';'gc;'"
0:000> g

user32 !MessageBoxA:

756e22c2 8bff mov edi,edi

0:000> ? Sra
Evaluate expression: 4198488 = 00401058

The next example suspends the debugger whenever the GetLastError func-
tion is called and it returns ACCESS DENIED (value 5):

0:014> bp kernelbase!GetLastError "g @$ra;j @eax==5 '';'gc'"

0:014> g

uxtheme ! ThemePreWndProc+0xd8:

OO0O07EE8 ~484915e8 33c9 xor ecx, €Cx
0:000> !gle

LastErrorValue: (Win32) Ox5 (5) - Access is denied.

LastStatusValue: (NTSTATUS) 0xc0000034 - Object Name not found.

This is not the optimal way to achieve that. The public symbols of NTDLL, when
loaded, expose a symbol called g_dwLastErrorToBreakon. Editing this value in
memory and passing the desired error value to break on is the better approach:

0:000> ep ntdll!g dwLastErrorToBreakOn 5

0:000> g

(2a0.2228): Break instruction exception - code 80000003 (first chance)
ntdll!RtlSetLastWin32Error+0x21:

OOOO07EE8'4c444df1 cc int 3
0:000> !gle
LastErrorValue: (Win32) 0 (0) - The operation completed successfully.

LastStatusValue: (NTSTATUS) 0xc0000034 - Object Name not found.

Script Errors

If an error is encountered when a debugger script is executing, then the entire
script will be aborted after the error message is displayed. Consider a script file
with the following contents:

-printf "Script started\n";
invalid command;
-printf "Script ending\n";

When this script is executed, it will produce an error:

Script started
Script started

“ Syntax error in '.printf "Script started

0:000>

---

**Page 124**

232 Chapter 4= Debugging and Automation

To prevent the script from aborting, you can use the . catch command token:

-printf "Script started\n";
.catch

{

invalid command;
-printf "!! will not be reached !!\n";

}

-printf "After catch\n";

The error will cause the script to break out of the . catch block and display
the error, but continue executing the script after that block:

Script started

A

Syntax error in '; invalid command; '
After catch

When inside a . catch block, one can explicitly exit it with the . leave com-
mand token.
Interestingly, . leave can be used to emulate a “break,” like in a loop:

r $t0=0;
.catch
{
.if (by(@Sip) == Oxb9)
{
-printf "found MOV ECX, ...\n";
r $t0O = dwo(@Sip+l1) ;
. Leave;
}
-elsif (by(@$ip) == 0xb8)
{
-printf "found MOV EAX, ...\n";
xr $t0O = dwo(@$ip+1) ;
- leave;

}

$$ do some other analysis
-printf "Could not find the right opcode\n";
$$ do more stuff...

}

$$ Reached after the catch block is over, an error has

$$ occurred or a .leave is used

Repetition Structures

The DbgEng supports four repetition structures, which are described in the
following sections.

---

**Page 125**

Chapter 4 = Debugging and Automation

233

The .break command can be used to break out of a loop. Similarly, the . con-
tinue command can be used to go to the next iteration within the encapsulating
repetition structure.

keeway In the case of an erroneous repetition condition (the script or command exe-
cutes endlessly), you can interrupt it by pressing Ctrl+C in any of the console debug-
gers (kd, cdb, ntsd) or Ctrl+PauseBreak in WinDbg.

The for Loop
The . for command token has the following syntax:

.for (InitialCommand ; Condition ; IncrementCommands) { Commands }

The following example script dumps the interrupt descriptor table (IDT) han-
dlers using a for loop. First, we run the dt command to inspect the structure
of an IDTENTRY on a 32-bit system in a kernel-mode debug session:

kd> dt _KIDTENTRY
ntdll! KIDTENTRY

+0x000 Offset : Uint2B
+0x002 Selector : Uint2B
+0x004 Access : Uint2B
+0x006 ExtendedOffset : Uint2B

The script is as follows:

.for (r $t0=0; 1;r $t0=@$t0+1)

{
$$ Take a typed pointer to the next IDT entry
vr? Stl = @@c++(((_KIDTENTRY *)@idtr) + @St0);

$$ Last entry?
-if (@@c++(@St1->Selector) == 0)
{

$s Break out

. break;

$$ Resolve the full address
r $t2 = @@c++((long) (((unsigned long) @$t1->ExtendedOffset << 0x10) +
(unsigned long) @$t1->0ffset) );

-printf "IDT[%02x] @ %p\n", @St0, @$t2
$$ .printf "IDT[%02x] @ Sp\n", @st2

---

**Page 126**

234

Chapter 4 = Debugging and Automation

Some important aspects of the script to note:

m The for loop’s condition is set to 1 so it loops indefinitely. We will break
out conditionally from inside the loop’s body with the .break command.

m The r? is used to assign a typed value to $t1.

m The pseudo-register $t1 is a pointer to _KIDTENTRY. When sto is added
to it, this will advance to the appropriate memory location (taking into
consideration the size of _KIDTENTRY).

m You determine the end of the IDT entries by examining the Selector field
and breaking out of the loop accordingly.

m The full base address of the IDT handler is computed by combining the
Extendedoffset and Offset fields.

m You cast $t2 to long so that it is properly sign extended (as pseudo-registers
are always 64-bit values).

m Display the result.

If you find using pseudo-registers like $t0 as a for loop counter a bit unusual
and instead want to use a name like i, j, or k, for example, then create a user-
named alias called i that is equivalent to esto:

aS i @Sto;

- block

{
.for (vr ${i} = 1; ${i} <= 5; vr ${i} = ${i}+1)
{

sprintf "i=%d\n", ${i}

}

The while Loop
The while loop is a simplified form of a for loop that has neither an initial
command nor an increment command:

-while (Condition) { Commands }

Depending on the condition expression, the while loop’s body may not execute
at all. Here’s a sample script that traces 200 instructions in a newly started process:

S$ Go to entry point (skip NT process initialization)
-printf "Going to entry point\n";

---

**Page 127**

Chapter 4= Debugging and Automation 235

g @Sexentry;
-printf "Started tracing...\n";

SS Reset the counter
r StO = 0;

-while (@St0O <= 0n200)

{

-printf "ip -> %p; ntrace=%d\n", @Sip, @S$t0;
r StO = @StO +1;
tr;

}

-printf "Condition satisfied\n";
u @Sip Ll;

Note that this is not the ideal way to do conditional tracing. The t and j com-
mands used together are a better approach.

The do-while Loop
The do-while loop has the following syntax:

.do { Commands } (Condition)

Unlike the while loop, the do loop’s body will execute at least once before the
condition is evaluated:

.do
{
.if (by(@$ip) == Oxbs)
{
-printf "Found MOV EAX, ...\n";
. break;
}
$$ do other things
$$ ....
SS ....
} (0);

-printf "Continue doing something else...\n";

The DbgEng also provides the z command to execute commands while a
certain condition holds true:

Command [ Command ; [Command ...;] ]; z( Expression )

---

**Page 128**

236

Chapter 4 = Debugging and Automation

In the following example, $t0 is used as a counter to trace five (5) branching
instructions:

0:000> r St0=1

0:000> th;r $t0=@StO + 1; z (@StO <= 5);

redo [1] th;r S$t0=@St0O + 1; z asta <= 5);
redo [1] th;r St0O=@StO + 1; z (@St0O <= 5);
redo [1] th;r S$t0O=@StO +1; z (@St0O <= 5);
redo [1] th;r S$t0O=@StO +1; z (@StO <= 5);

0:000> ? @StO
Evaluate expression: 6 = 00000006

As in the preceding example, one or more commands can be specified to the
left of the z command.

The foreach Loop

The foreach loop is very useful and can be used to enumerate tokens read from
a file, from the output of a command or from a user-provided string.

Two common options can be passed (separately or together) as first parameters
to the . foreach command token:

m /pS ExpressionValue—Initial number of tokens to skip when the loop
starts. This is equivalent to initializing the counter to a non-zero value
in a for loop.

m /ps ExpressionValue—The number of tokens to skip after each iteration.
This is equivalent to the for loop increment part where the programmer
can specify the counter increment value.

Tokenizing from a String

The general syntax is as follows:
.foreach [Options] /s (TokenVariableName "InString" ) { OutCommands }

For example, assume you are looking for *createFile*-related symbols in the
following three modules: ntdll, kernelbase, and kernel32. This is one way to do it:

.foreach /s (token "ntdll kernel32 kernelbase") { x ${token}!*CreateFile*; }

In the next example, suppose you want to tokenize the contents of a given
ASCII string in memory:

aS /mu STR 0x8905e8
r $tO = 0;
- block

{

.foreach /s (token "S{STR}")

{

---

**Page 129**

Chapter 4 = Debugging and Automation

237

-printf "token_i=%d, token_val=${token}\n", @$t0;
r $StO = @StO +1;

}

The ${} is used to evaluate the token variable’s value. This is only necessary
only if the token is not surrounded by the space character at the time of evalu-
ation. The .block was used in order to cause the alias STR to be evaluated.

Tokenizing from the Output of aCommand

The general syntax is as follows:
.foreach [Options] ( Variable { InCommands } ) { OutCommands }

This use of . foreach is the most common because it enables extracting infor-
mation from a command’s output and using it in your script.

For the sake of demonstration, imagine a script that needs to allocate memory
in the process space of the debuggee and then uses that memory to read a file’s
contents to it.

First, examine the output of the memory allocation command .dvalloc:

0:000> .dvalloc 0n4096
Allocated 1000 bytes starting at 00620000

The output can be tokenized into six tokens; thus, the foreach loop should
use the /ps flag to skip the first five tokens and directly start with the last token
(which is the newly allocated memory address):

0:000> .foreach /pS 5 (token {.dvalloc 0x1000 }) { r $t0O = ${token}; .break; }
0:000> ? @s$t0
Evaluate expression: 8323072 = 007£0000

The full script becomes the following:

$$ Set the image file name

aS fileName @"c:\temp\shellcode.bin"

.catch

{
$$ Set the allocation size to be equal to the file we want to read
r S$tO = 0n8s8so0;

.foreach /pS 5 (token {.dvalloc @$to; })

{
r $tl = token;
. break;

}

$S Read the file
.readmem "${fileName}" @$t1 L@sto;

---

**Page 130**

238 Chapter 4= Debugging and Automation

-printf "Loaded ${fileName} @ %p\n", @$t1

Kee] Remember to free the memory with the .dvfree command.

The next example parses the output of 1m1m (which, by design, returns simpli-
fied output for use with . foreach):

0:000> lmilm
image00400000
SHCORE
KERNEL32
comct132
user32

Ntdll

The foreach loop should look like this:

0:000> .foreach (modulename { lmlm; }) { .printf "Module name: modulename \n"; }

Tokenizing from a File

The general syntax is as follows:
.foreach [Options] /f ( Variable "InFile" ) { OutCommands }

Assume a file called lines. txt with the following contents:

This is line 1
This is line 2
This is line 3

It will be tokenized as follows:

0:000> .foreach /f (line "c:\\temp\\lines.txt") { .printf ">${line}<\n" }
>This<
>is<
>line<
>l<
>This<
>is<
>line<
>2<
>This<
>is<
>line<

>3<

---

**Page 131**

Chapter 4= Debugging and Automation 239

Extension-Provided foreach Loops

There are a few other foreach commands provided by extensions that are not
part of the scripting language. These foreach commands are implemented

inside various DbgEng extensions:

m™ !for_each_frame—Executes a command for each frame in the stack of

the current thread

m !for_each_function—Executes a command for each function in a given
module that matches the search pattern

m™ !for _each_local—Executes a command for each local variable in the

current frame

m !for_each_module—Executes a command for each loaded module

m !for_each_process—Executes a command for each process (this exten-
sion works in kernel debugging only)

m !for_each_thread—Executes a command for each thread (kernel debug-

ging only)

kee Usethe .extmatch *for_each* command to enumerate all the foreach

extension commands.

Each of those extension commands exposes special variables to the command
they execute. Please refer to the debugger manual to learn what variables are
exposed for each specific extension command.

The following example lists all modules and displays some information

about them:

!for_each_module .printf /D "%16p %16p: ${@#ModuleName}
@<link cmd=\"u %p\">%p</link>\n", ${@#Base},${@#End},
$iment (0x${@#Base}), Siment (0x${@#Base})

400000
74670000
75130000
755d0000
75670000
75960000
76c00000
76£a0000

408000:
74c78000:
75270000:
75656000:
757b£000:
76628000:
76cbe000:
77017000:

image00400000 @00406800
gdi32 @74b7afc5
KERNEL32 @7514a5cf
comct132 @755dle15
user32 @75685422
shell32 @759b108d
msvert @76c0a9ed
ADVAPI32 @76£a1005

The entry point was computed with the $iment () operator. Also, the Debugger
Markup Language (DML) was used to make the entry point clickable. When
clicked it will unassemble the instructions at the entry point.

---

**Page 132**

240

Chapter 4 = Debugging and Automation

The next example scans for all functions in ntd11 that contain the File substring
in their name:

!for_each_ function -m:ntdll -p:*File* -c:.echo @#SymbolName

kee Torun more commands, enclose them in quotes or just use one of the com-
mands that run script files.

Script Files

Various commands can be used to instruct the DbgEng to run scripts. These
commands are split into two main categories:

= Commands that open the script file, replace all new lines with a semico-
lon (the command separator), and concatenate the whole contents into a
single command block. These commands have the following form: $><.

m= Commands that open the script file and interpret each line separately.
These commands have the following form: $<.

The former is very handy when using a debugger command that accepts other
commands as its arguments. For example, the bp command takes a breakpoint
action, which can be a simple command or a command that runs a script file
(that contains various commands inside of it).

The latter interprets the contents of the script file line by line; each line could
contain various commands separated by a semicolon. Each command executed
will also be echoed in the debugger output.

Some debugger commands interpret the whole line, disregarding whether
there is a semicolon (;) or not. This means that using the $><-related commands
will not work for such scripts. Consider the following example script:

r eax;r ebx

r $.u0 = This is just a line
-printf "suo"

r ecx;r edx

Running this script with $>< does not work as intended:

0:000> $><test.wds
eax=00000000
ebx=00000000
0:000> ? Sud

Couldn't resolve error at 'This is just a line;.printf "";r ecx;r edx'

---

**Page 133**

Chapter 4= Debugging and Automation 241

Conversely, running this particular script with $< works just fine:

0:000> $<test.wds

0:000> r eax;r ebx

eax=00000000

ebx=00000000

0:000> r $.u0 = This is just a line
0:000> .printf "Suo"

This is just a lineO:000> r ecx;r edx
ecx=£7£c0000

edx=00000000

The reason for this behavior is that when assigning a value to a fixed-name
alias, semicolons will also be part of the assignment. This explains why in the
first output, the script seems to have been suddenly stopped; it’s because $><
will concatenate all lines and separate them with a semicolon.

For the same reason, if you use a command that creates blocks and the curly
braces ({ and }) are used on separate lines in the script file, $< will not work

properly:
if (1 == 2)

{

-printf "No way!\n";

-printf "That's what I thought";

}
When executed, the preceding returns the following error:

(1)
0:000> $<blocktest.wds
0:000> .if (1 == 2)
“ Syntax error in '.if (1 == 2)!
0:000> {

“ Syntax error in '{'
0:000> -printf "No way!";
No way!0:000> }

“ Syntax error in '}!
0:000> .else

“ Syntax error in '.else'

0:000> {
“ Syntax error in '{'
0:000> -printf "That's what I thought";
That's what I thought0:000> }
“* Syntax error in '}!
(2)
0:000> $><p:\book\scripts\t_blocktest.wds

That's what I thought

---

**Page 134**

242

Chapter 4 = Debugging and Automation

kee When the run script commands are prefixed with an extra $, the script file
name/path can no longer contain semicolons. When a semicolon is found after $$><
or $$<, then whatever comes after it is interpreted as another set of commands.

To run a script file with its contents concatenated into a single command
block, use $>< or $$><:

$$><path_to\the script.wds; r eax; al; bl;

Because $$>< is used, the semicolon allows the subsequent commands to be
executed.

Passing Arguments to Script Files
It is possible to pass arguments to scripts using the $$>a< command:

$$>a<path_to\the script.wds argl arg2 ...

The arguments can then be accessed in the script via the sargn aliases. The
alias $argo contains the script name (as in C’s argv [0]).

If you pass UDPRs as arguments, then they will not be expanded or evalu-
ated before being passed to the script. This is a tricky situation and can lead to
various unexpected behaviors. For example, suppose you call a script like this:

$$>a<script.wds @S$t1 @$t2

The preceding script will be passed the values @$t1 and e@st2 as ${$arg1}
and ${$arg2}, respectively. To solve this problem, assign the pseudo-registers to
a user-named alias and then call the script from a .block. This will guarantee
expansion of the alias values before they are passed to the script:

aS /x vall @Ssto
aS /x val2 @$t1
- block

{

$S>acscript.wds ${val1} ${val2}

}

ad /q vall
ad /q val2

To check whether an argument is present, use the .if" with "${/d:...}:

-catch
{
.if ${/d:$argl} == 0 or ${/d:$arg2} == 0
{
-printf "Usage: ${$SargO} memory-address len\n";
.- leave;
}

r $tO = ${$argl1};

---

**Page 135**

Chapter 4= Debugging and Automation 243

.1£ $vvalid(sSt0O, 1) == 0

-printf "Invalid memory address specified\n";
.- leave;

r $tl = @$to + ${$arg2} - 1;
-printf "Summing memory bytes from %x to %x\n", @$t0, @$t1;
-for (r St3 = 0;@St0O <= @Stl;r $tO = @St1 +1)

r $t3 = @$t3 + by(@St1);

-printf "The result is %x\n", @St3;

}

We used a few tricks worthy of a brief explanation:

™ .catch and .leave were used to simulate a function start and “return”
like behavior.

m .if and ${/d:$arg1} were used to check if the first argument was defined.
Because we did not explicitly switch the evaluator syntax, the scripting
engine will evaluate using MASM; thus the operators used should all be
valid in MASM syntax. Enclosing an expression with @@c++ (expression)
will evaluate the expression using C++ syntax.

m The $vvalid() operator is used to check if the passed memory address
is valid.

m The .for command token is used to loop through the memory contents,
and each byte at that location is dereferenced using MASM's by () operator.

In the following output, the script is passed various arguments:

(1)

0:000> $$>a<script.wds

Usage: script.wds memory-address len

(2)

0:000> $$>a<script.wds Oxbadf00d

Invalid memory address specified

(3)

0:000> $$>a<script.wds @eip 2

Summing memory bytes from 76£83bc5 to 76f£83bc6
The result is eb

At marker 1, the script is executed without any arguments and it successfully
showed its arguments. At marker 2, the script is passed an invalid memory
address. Finally, at marker 3, the script is called correctly and the sum of the
bytes is returned.

---

**Page 136**

244

Chapter 4 = Debugging and Automation

kee The . wds file extension is not necessary. It is just a convention used by vari-
ous script writers and stands for WinDbg Script file.

Using Scripts Like Functions

There is no way to define functions in the DbgEng’s scripting language. However,
it is possible to use various script files as if they were functions. A script can
call itself recursively or call another script with another set of arguments, and
those arguments will be different in the context of each script.

UDPRs are very handy when writing a script. When a script calls another script,
those UDPRs will be common to all scripts and thus cannot be used exclusively
inside each script without disrupting the state of the other caller scripts, unless
of course they are saved and restored by the script in its entry and exit points.

You can think of the need to preserve UDPRs in terms of registers in X86
or AMD64 programs, where the compiler ensures that it emits code that preserves
certain general-purpose registers upon the entry and the exit of each function while
(depending on the calling convention) dedicating certain registers for input/output of
the function.

With that in mind, it is important to devise a mechanism that allows us to
easily and seamlessly, and with as little repetition as possible, save/restore
certain UDPRs anytime a script is going to call another.

The @call Script File Alias

In the previous section we outlined the necessity of having a way to save/restore
UDRPs. For that reason, we devised two simple scripts that do just that. This
section illustrates both the init .wds and call.wds scripts and explains how
they work.

The init .wds script is used to set up the scripting environment and create
the short aliases to act like function names:

(1)

ad /q *;

(2)

aS ${/v:SCRIPT_PATH} @"p:\book\scripts";
- block

{

S$ Callable scripts (using @call) (3)

---

**Page 137**

Chapter 4 = Debugging and Automation

245

aS ${/v:#sigma} @"${SCRIPT_PATH}\sigma";
aS ${/v:#pi} @"${SCRIPT_PATH}\pi";
$$ Script call aliases (4)
aS ${/v:@dvalloc} @"$$>a<${SCRIPT_PATH}\dvalloc.wds";
aS ${/v:@call} @"$$>a<${SCRIPT_ PATH}\call.wds";
}
r $t19 = 0; (5)
r $t18 = 1; (6)

The init .wds script devises two user-named alias naming conventions:

m Names prefixed with @ denote aliases to the $$>a< command (run a script
with arguments). Normally those are scripts that are self-sufficient. (They
do not need to preserve UDPRs and do not necessarily call themselves
or other scripts.)

m Names prefixed with # designate an alias that can be called with the
@call alias. Those scripts can be recursive and can safely assume that all
the UDPRs other than those designated as return values will be saved/
restored before/after a script is called/returns.

Marker 1 deletes all previously defined aliases. At marker 2, the script’s base
path is defined. (Note the use of @ to specify a literal string.) At marker 3, we
define two user-named aliases prefixed with # defined. These are callable via
the @cali alias and evaluate to the full script path without the .wds extension.
(The call script will append the extension.) For the sake of demonstration, two
callable scripts are defined: sigma and pi. At marker 4, we define two user-
named aliases prefixed with @. These aliases simply resolve to $$>a< followed by
the full script path. The @call alias is what makes calling scripts as a function
possible. The @dvalloc is a wrapper around the .dvalloc command. Marker 5
defines the $t19 UDPR, which is used internally by call .wds script to remem-
ber the script calls nesting level. The nesting level is used to form an alias that
will save all UDPRs per nest level. At marker 6, we define UDPR $t18, which is
used internally by call .wds to determine how many UDPRs starting from $to
should be skipped while restoring the saved UDPRs after a script call (more on
that in the following explanation).

Here is the call.wds script:

ad /q ${/v:_tn_} (1)
.catch
{
if ${/d:S$arg1} == 0 (2)
{
-printf "No script to call specified";
. leave;

---

**Page 138**

246 Chapter 4= Debugging and Automation

}

$$ Compute the saved registers alias name of the previous call
aS /x ${/v:_tn_} @$t19; (3)
-block

{

$$ Delete the saved registers alias name of the previous run
ad /q _sr ${_tn };

}

r $t19 = @$St19 + 1; $$ Increment the nesting level (4)

$$ Compute the saved registers alias name for the current run
aS /x ${/v:_tn_} @$t19; (5)

S$ Save all pseudo-registers
- block
{ (6)
aS /c _sr_ ${_tn_} "r $t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8,$t9,
$t10,$t11,$t12,$t13,$t14,$t15,$t16,$t17";

}

$$ Call the script

.catch

{ (7)

$$>a<"S{Sargl}.wds" ${/f:$arg2} ${/f:$arg3} ${/f£:Sarg4}

${/£:Sarg5} ${/£:Sarg6} ${/f:Sarg7} ${/f:Sargs8} ${/f:Sarg9} ${/f:S$arg10}
${/£:$arg11} ${/f:$arg12} ${/f:$arg13} ${/f:$arg14} ${/f:$arg15}
${/£:$arg16} ${/f£:$arg17} ${/f:S$arg18} ${/f:$arg19} ${/f:$arg20};

}

$$ Restore the registers after calling
-block
{
(8)
$$ Compute the saved registers alias name
aS /x ${/v:_tn_} @$t19;
- block

{

$$ Restore all registers except the first ones that
$S are due to return a value
.foreach /pS @$t18 /s (X "sr ${ tn_}" ) (9)

{
x ${xX}; (10)

$$ Delete the saved registers alias name
ad /q _sr ${_tn_}; (11)

$$ Decrease the nesting level
r $t19 = @$t19 - 1; (12)

}

ad /q ${/v:_tn_}; (13)

---

**Page 139**

Chapter 4 = Debugging and Automation

247

This script needs two UDPRs for special purposes. The first is $t19, which
is used to store the call nesting level. It is incremented each time @cal1 is used
to run a script, and decremented when the script finishes execution. Because
$t19 is incremented and decremented, you can create an alias with a unique
name per nesting level to store the UDPR values.

The second UDPR is $t18, which is used to designate the count of UDPRs
used to return values (starting from $to). By default, the value 1 indicates that
$to is the only register to be used as a return value. If the script returns more
than one value (for example, in $t 0 and $t1), then the caller has to set $t18 to 2
before calling the script. This guarantees that neither sto nor $t1 will be reverted
back to their original values (the values before the script was called). The call
script takes the script name to be called as the first argument, followed by the
rest of the arguments (Sarg2 through sargn).

Now we briefly explain how the rest of this script works before putting it into
action. At marker 1, we delete the user-named alias _tn_ (used to compute a
per-nesting-level alias name) before redefining it. Marker 2 checks if a param-
eter was passed to the script. At marker 3 and 4, we assign to the _tn_alias the
numeric value of the nesting level (note the use of as /x), and then we increment
the nesting level UDPR $t19. At marker 5, we create a temporary alias that has
the value of the current nesting level.

At marker 6, we save UDPRs sto through $t17 into an aliasnamed _sr_{_tn_}
by using as /c followed by the r command and the list of UDPRs to return
their values. For instance, if the nesting level is 2, the saved register’s alias name
will be _sr_2 and will contain the values of all UDPRs in question. _sr_0x2
will equate to $t0=00000003 $t1=00000000 $t2=00000000 ... $t17=00000000.

At markers 7 and 8, the script that was passed into $arg1 is called with the
rest of the arguments that were passed. After the script returns, re-compute
the _tn_alias. (The alias could have been overwritten by the called script.)

At markers 9 and 10, we iterate in the current sr NESTING LEVEL alias but
skip $t18 tokens (note the /ps switch), and then restore each UDPR with the r
command.

At markers 11-13, we clean up the saved registers alias (_sr_NESTING_LEVEL),
decrement the nesting level, and delete the temporary name alias.

The next step is to run the init .wds script that will create the appropriate
aliases:

0:000> ad /q *; $$><p:\book\scripts\init.wds; al;

Alias Value

#pi "o:\book\scripts\pi"

#Sigma "p:\book\scripts\sigma"

#test "o:\book\scripts\test"

@call $$>a<"p:\book\scripts\call.wds"
@dvalloc $$>a<"p:\book\scripts\dvalloc.wds"

SCRIPT_PATH p:\book\scripts

---

**Page 140**

248 Chapter 4= Debugging and Automation

Another way to do that is to run WinDbg (or cdb) with the -c command-line
switch:

c:\dbg\windbg.exe -c "ad /q *;$$><p:\book\scripts\init.wds;al;" p:\test.exe

You can now tell that you have two aliases for @call and @dvalloc that are
scripts that do not require automatic save/restore of UDPRs, and three other
scripts that rely on @call to automatically save/restore UDPRs, and they act
like “functions.”

The sigma.wds script takes two numeric parameters and returns the sum
of terms between the first and second argument, returning the result in $to:

-for (r $t0=0, $t1=${$argl}, $t2=${$arg2}; @$t1 <= @$t2; r $t1 = @$t1 + 1)

{

vr $tO = @StO + @$tl1;

}

To execute sigma.wds, use @call #sigma start num end_nun, as follows:

0:000> @call #sigma 1 4;.printf "The result is %d\n", @$t0
The result is 10

Similarly, the script pi.wds returns the multiplication result of the terms
between the first and second argument:

.for (ry $t0=1, $t1=${S$arg1}, $t2=S{Sarg2}; @$t1 <= @$t2; r $t1 = @$t1 + 1)

{

r $tO = @S$tO * @Stl;

}

The dvalloc.wds script is a wrapper around the .dvalloc command. When
@dvalloc is called, the result is returned in $to0 so it can be used in scripts:

.catch

{

r StO = -1; SS Set invalid result

if ${/d:S$arg1} == 0

{
-printf "Usage: dvalloc.wds memory-size\n";
-printf "The allocated memory is returned in t0\n";
. Leave;

$$ Allocate memory and set result into $t0
.foreach /pS 5 (t {.dvalloc ${$arg1}})
{
if $vvalid(${t}, 1) == 1
{
r $to = ${t};

. leave;

---

**Page 141**

Chapter 4 = Debugging and Automation

249

}

After allocating memory with .dvalloc, we tokenize the result and parse
out the memory address into $to.

Both sigma.wds and pi.wds are sample functions that use the $t1 and $t2
UDPRs. That means if a script calls sigma or pi, then $t1 and $t2 should not be
modified in any way upon returning from both the functions back to the caller.

You can verify this behavior with the following simple test .wds script:

r Stl
r $t2

0x123;
Ox456;

-printf "Before calling sigma: tl=%x, t2=%x\n", @$t1, @$t2

@call #sigma 1 3

-printf "After calling sigma: the result is t0=%x, tl=%x, t2=%x\n",
@$t0, @$t1, @$t2

The preceding script assigns values to UDPRs $t1 and $t2 and then calls
#sigma 1 3, which will modify $t1 and $t2. If e@call works as expected, then
those UDPRs are restored just after the call:

0:000> @call #test
Before calling sigma: t1=123, t2=456
After calling sigma: the result is t0=6, t1=123, t2=456

Example Debug Scripts

In this section you will make use of various helpful scripts, putting into practice
all that you have learned so far.

Getting the Image Base of a Specified Module

One quick way to get the image base of a module is to use the 1m (list modules)
command with the m switch to list modules matching the specified pattern:

0:000> lm m kernel32
start end module name
749e0000 74620000 KERNEL32 (deferred)

From the output, you can tell that at the fifth token you have the image base.
Thus, the image base can be easily parsed with . foreach by skipping the first
tokens, extracting the value of the fifth token, and breaking out of the loop:

r $tO = -1;
.foreach /pS 4 ( imgbase { lmm ${$argl1}; } )

{

---

**Page 142**

250

Chapter 4 = Debugging and Automation

r @$tO = ${imgbase};
. break;

}
Writing a Basic UPX Unpacker

Writing a UPX unpacker is pretty simple, and there are many ways to do it.
The method used here is elaborate in order to exercise various debugger com-
mands. It is assumed that you have basic PE file format knowledge to properly
understand the script.

The idea behind the script is as follows:

1. UPX packs the program and moves the original entry point (OEP) away
from the .text section, which is the first section.

The script calculates the bounds of the first section and starts tracing.

If instruction pointer (EIP) is outside of the program image, then the script
issues a gu to return to the caller.

4. Tracing continues until EIP is inside the first section. At that point, it is
assumed that the program has been unpacked.

Here is the script:

$$ Get image base

$$ Get image base

aS /x IMG BASE @@c++(@$peb->ImageBaseAddress); (1)

$$ Declare some user-named aliases that equate to UDPRs
aS SEC_START @$t19; (2)

aS SEC_END @St18;

aS IMG START  @$t17;

aS IMG_END @$t16;

$$ Go to the program entrypoint
g @Sexentry

.catch

{

$$ Get pointer to NT headers
(3)
r $tO = ${IMG_BASE} + @@c++(((_IMAGE DOS HEADER *)${IMG_BASE})->e _lfanew)

$$ Now from the IMAGE NT HEADERS.FileHeader, get the size of optional
header
(4)
vr Stl = @@c++( ((! IMAGE NT _HEADERS*) @$t0) ->FileHeader.SizeOfOptionalHeader )

$$ Compute the address to the first section
$$ skip signature, size of file headers and size of optional headers
vr $t2 = @St0O + 4 + @@c++(sizeof(ole32! IMAGE FILE HEADER)) + @St1; (5)

---

**Page 143**

Chapter 4 = Debugging and Automation

$$ (6) Get first section boundaries
r ${SEC_START} = IMG BASE +

@@c++(((_IMAGE SECTION HEADER *) @$t2) ->VirtualAddress) ;
r ${SEC_END} = IMG BASE +
@@c++(((_IMAGE SECTION HEADER *) @$t2)->Misc.VirtualSize) ;

$$ Compute the image bounds (7)
rx ${IMG_START} = IMG BASE;
x ${IMG_END} = IMG_START +
@@c++(((_IMAGE NT HEADERS *) @$t0) ->OptionalHeader.SizeOfIm-
age) ;

$$ The logic is as follows:

$s 1. Trace

$$ 2. If IP is outside of image then "gu"
.for (r $t0=0; 1; r StO = @StO + 1) (8)

{

$s Trace once more to see where it leads (9)
t;

$$ IP outside image boundaries?
if (@Sip < ${IMG_START}) or (@Sip > ${IMG_END}) (10)
{

gu;

.continue;

$s IP within the first section?
if (@Sip >= ${SEC_START}) and (@$ip <= ${SEC_END}) (11)

{

-printf "--- Reach first section ---\n";
u;

. break;

}

At marker 1, we take the image base of the current running program from
the speb typed pseudo-register by accessing its ImageBaseAddress field using
the C++ evaluator, and then store it in an alias called Imc_BASE.

At marker 2, we create a bunch of user-named aliases that correspond to
some UDPRs. This is a nice trick to give names to those UDPRs. At marker 3,
we assign the address of the _IMAGE_NT_HEADERS to the $to UDPR by adding
the image base to the value of the field in IMAGE_DOS_HEADER.e_lfanew.

At marker 4, we retrieve the size of the optional headers into the st1 UDPR.
This will be useful to skip over all the PE headers and land in the first image
section header.

---

**Page 144**

252

Chapter 4 = Debugging and Automation

At marker 5, we compute the address of first image section into the $t2 UDPR.
At marker 6, we parse from the IMAGE_SECTION_HEADER both the section virtual
address (section start) and the section end (section start + section size).

At marker 7, we compute the program’s start and end addresses. The start
address is the image base, and the end address is the image base plus the con-
tents of the IMAGE_OPTIONAL_HEADER.SizeOf Image field.

At marker 8, we start looping infinitely using a for loop, $to0 as the counter,
and the value 1 as the condition.

At markers 9-11, we use the t command to trace a single instruction. Don’t
trace if EIP is not within the image’s boundaries and stop tracing if the EIP is
within the first section’s boundaries.

Although this method is too long, it illustrates how to write a more complex
tracing script and logic in case the unpacking process is more sophisticated.

The following is a simpler version of the unpacker that searches for a code
pattern that is executed just before the program is about to transition to the
original entry point (OEP):

$$ UPX unpack w/ pattern

SS UPX1:0107D7F5 39 C4 cmp esp, eax

$$ UPX1:0107D7F7 75 FA jnz short loc_107D7F3

$$ UPX1:0107D7F9 83 EC 80 sub esp, -80h

SS UPX1:0107D7FC EQ ?? ?? ?? jmp near ptr word_103FC62

$$ Go to program entry point (not the original entry point, but the packed
one)
$$ only if no arguments were specified
if ${/d:$arg1} ==
{
g @Sexentry;

}

$$ Pattern not found!
r $t0O = 0; (1)
.foreach (addr { s -[1]b @Sip L200 39 c4 75 fa 83 EC}) (2)
{
$$ Pattern found!
r $tO = 1;
x $tl = ${addr} + 7; (3)
-printf /D "The JMP to OEP @<link cmd=\"u %x\">%x</link>\n",@$t1,@St1;
(4)
ga @$tl1;
(5)
t; u;
. break;

-printf "Could not find OEP jump pattern. Is the program packed by
UPX?\n";

}

---

**Page 145**

Chapter 4 = Debugging and Automation

253

At marker 1, we use the sto UDPR as a Boolean variable to indicate whether
the pattern was found.

At marker 2, we search for the pattern starting from the entry point and for
at most 200 bytes using the 1 flag with the search command s. This will return
just the address where the match occurred. If no match is found, an empty string
is returned and thus the . foreach has nothing to tokenize.

At marker 3, we skip seven bytes past the matched pattern location to point to
the long relative jump (which jumps back to the OEP). Store that address into $t1.

At markers 4 and 5, we run the program until the gMP OEP instruction is
reached (the ga command was used, so a hardware breakpoint is used rather
than a software breakpoint), and then we trace once over the UMP OEP instruc-
tion and thus reach the first instruction of the unpacked program.

Writing a Basic File Monitor

This example creates a script that illustrates how to use scripts in combination
with conditional breakpoints to track all calls to ASCII and Unicode versions
of various file I/O API functions: createFile, DeleteFile, GetFileAttributes,
CopyFile, and so on.

The script is designed to be called once with the init parameter to initialize
it and then multiple times as a command to the breakpoints it creates when it
initializes.

The following parameters are passed when the script is called from the
breakpoint:

™ ApiName—Used for display purposes only.

m™ IsUnicode—Pass zero to specify that this is the ASCII version of the API,
and pass one to specify that it is the Unicode version.

m FileNamePointerIndex—The parameter number on the stack that contains
the pointer to the filename buffer

™ Apirtp—An ID of your choice, this parameter is optional. This is helpful
if you want to add extra logic when this breakpoint occurs. In this script,
CreateFile[A|w] is given the ID 5. Later you check whether this API is
triggered, and then check what filename is accessed and act accordingly.

Here is the contents of the bp_displayfn.wds script:

.catch

{

if 'S${Sarg1}' == 'init' (1)

{

---

**Page 146**

254 Chapter 4= Debugging and Automation

(2)
bp kernelbase!CreateFileA @"$$>a<${S$arg0} CreateFileA 0 1 5";
bp kernelbase!CreateFileW @"$$>a<${Sarg0O} CreateFileW 1 1 5";

(3)
bp kernelbase!DeleteFileA @"$$>a<${$arg0} DeleteFileW 0 1";
bp kernelbase!DeleteFileW @"$$>a<${SargO} DeleteFileW 1 1";
bp kernelbase!FindFirstFileA @"$$>a<${Sarg0} FindFirstFileA 0 1";
bp kernelbase!FindFirstFileW @"$$>a<${$arg0} FindFirstFileW 1 1";
bp kernel32!MoveFileA @"$$>a<${$arg0} MoveFileA 0 1";
bp kernel32!MoveFileW @"$$>a<${$arg0} MoveFileW 1 1";
bp kernelbase!GetFileAttributesA
@"$$>a<${$argO} GetFileAttributesA 0 1";
bp kernelbase!GetFileAttributesExA
@"$$>a<${$argO} GetFileAttributesExA 0 1";
bp kernelbase!GetFileAttributesExw
@"$$>a<${$argO} GetFileAttributesExW 1 1";
bp kernel32!CopyFileA @"$$>a<${$arg0} CopyFileA 0 1";
bp kernel32!CopyFileW @"$$>a<${$arg0} CopyFileW 1 1";

$$ Ignore some debug events (to lessen output pollution)
sxi ld;

$$ Display the list of the newly installed breakpoints
bl;
(4)
. leave;
}
(5)
$$ Display API name
-printf "S${Sarg1}: >";
(6)
$$ Fetch the file name pointer
rx $t0O = poi(@sScsp + 4 * ${Sarg3});
(7)
$$ Is it a unicode string pointer?
if ${Sarg2} == 1

{
(8)

-printf£ "%Smu<\n", @St0;
}
.else
{

$$ Display as ASCII SZ (9)

-printf "Sma<\n", @St0;
}
$$ ApiID parameter set? (10)
if ${/d:$arg4} == 1
{

$$ ID of CreateFile API? (11)
if ${Sarg4} == 5

---

**Page 147**

Chapter 4 = Debugging and Automation

255

$$ Grab the name of the file so we compare it
aS /mu ${/v:FILE_NAME} @S$t0O; (12)
- block

{
(13)
.if Ssicmp(@"${FILE_NAME}", @"c:\temp\eb.txt") == 0

{

.leave; (14)

}
}

ad /q ${/v:FILE_NAME} ;

}

$$ Continue after breakpoint
gc; (15)

}

At marker 1, we check whether the script is called with init; if so, then ini-
tialize the script (markers 2-4) and exit the script. At marker 2, we create two
breakpoints for createFileA/w and set the condition to be the script itself, and
pass ApiID = 5.

At markers 3 and 4, we add breakpoints for the rest of the APIs without pass-
ing the ApiID argument, and then return from the script. At markers 5 and 6,
we print the API name then assign into sto the pointer of the filename (using
the passed parameter index). At markers 7-9, we check if the script is called for
the ASCII or Unicode version of the API and then appropriately use the smu or
the sma format specifier. At markers 10-12, we check if an ApiID was passed
and is the CreateFile ApilD.

At markers 12-14, we extract the filename into an alias called FILE_NAME, create
a block so that the alias is expanded properly, and then compare the FILE_NAME
alias against a desired file path. (Notice the use of @ to indicate literal string
expansion.) If the path matches what we are looking for, the script terminates
and suspends execution. Finally, at marker 15, the script will resume execution
after any of the defined breakpoint is reached.

To use this script, run it with the init parameter first:

0:000> $$>a<P:\book\scripts\bp displayfn.wds init; g;

Writing a Basic String Descrambler

This script implements a simple descrambling routine. Imagine the C scrambling
routine is as follows:

void descramble(unsigned char *p, size_t sz)

{

for (size_t 1=0;i<sz;i++, ++p)

---

**Page 148**

256 Chapter 4= Debugging and Automation

A

*p = *p (235 + (i & 1));

kee The descrambling routine can be more sophisticated. If the routine involves
the use of tables and whatnot, remember that you have access to those tables because
the script has full access to the debuggee’s memory.

The following is the same routine implemented using the DbgEng’s scripting
language. Note how it makes use of the @ec++ evaluator to easily mimic the
original algorithm:

.catch

{
SS Take the Source
r $tO = ${Sargl1};

$$ Take the Destination
rx $tl = ${Sarg2};

SS Take the Size
rx $t2 = ${Sarg3};

.for (r $t3=0; @$t3<@St2; r $t3 = @St3 + 1, $tO = @St0+1, $t1=@$t1+1)

{

A

rv $t4 = @@c++((* (unsigned char *)@St0) (235 + (@St3 & 1)));
eb @St1 @St4;
}

$$ Display the descrambled result
db ${S$arg2} L ${Sarg3};

The scrambled memory contents is as follows:

0:000> db 0x4180a4 L 30

004180a4 bb 9e 8a 8f 9F 85 88 8d-87 cc 99 89 9d 89 99 OF ... ee eee eee ee eee
004180b4 8e cc 8e 82 8c 85 85 89-8e 9e 82 82 Bc ec eb ec ....... eee eee.
004180c4 eb ec eb ec eb ec eb ec-eb ec eb ec eb ec eb ec ..... ee eee.

To descramble, run the script:

0:000> @dvalloc 1; ? St0O

Evaluate expression: 131072 = 00020000

0:000> $$>a<descramble.wds 0x4180a4 0x20000 30

00020000 50 72 61 63 74 69 63 61-6c 20 72 65 76 65 72 73 Practical revers
00020010 65 20 65 6e 67 69 6e 65-65 72 69 6e 67 00 00 00 e engineering...
00020020 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ...... eee eee eee

---

**Page 149**

Chapter 4 = Debugging and Automation

257

Using the SDK

So far we have covered how to automate tasks using the scripting facilities
provided by the debugging tools. The SDK that ships with the debugging tools
provides another way to automate or extend the debugger. It ships with header
files, library files to link your extension with, and various examples that show
you how to use the DbgEng programmatically.

The SDK is found in the sdk subdirectory where the debugging tools are
installed. It has the following directory structure:

™ Help—Contains references to the DbgHelp library.
™ Inc—Contains the includes needed when using the SDK.

™ Lib—Contains the appropriate library files used during the linking build
stage. It contains libraries for WOA (Windows on ARM), AMD64, and i386.

™ Samples—Contains samples of various examples written using the different
frameworks that can be used to write debugger extensions. There are also
samples on how to use the DbgEng instead of writing an extension for it.

Although covering the SDK is beyond the scope of this chapter, the following
sections briefly discuss how to use the SDK to write DbgEng extensions for the
debugger. The material covered should be just enough to give you a head start,
making it easy for you to understand the sample extensions and start learning
and writing your own.

To begin, you should know that the SDK provides three frameworks with
which you can write extensions:

m WdbgExts extension framework—These are the original WinDbg exten-
sions. To interact with the DbgEng, they require exporting a few callbacks
in order to work with the WinDbg Extension APIs instead of the debug-
ger client interface. The programmer can later acquire a debugger client
interface or other interfaces on demand if more functionality is required.

m DbgEng extension framework—These newer types of extensions can
provide extra functionality to the extension writer. The extension com-
mands have access to a debugger client interface instance that enables
them to acquire other interfaces and interact further with the DbgEng.

m EngExtCpp extensions—Built on top of the DbgEng extension framework,
these extensions are created by subclassing the Ext Extension base class.
The Ext Extension class provides a variety of utility functions that enable
the extension to perform complex tasks.

---

**Page 150**

258

Chapter 4 = Debugging and Automation

The following sections briefly illustrate how to write extensions using the
WdbgExts extension framework. Please note that writing extensions using either
of the other frameworks is fairly straightforward and can be done by following
the SDK samples that ship with the Debugging Tools package.

Concepts
This section describes two methods for accessing the DbgEng APIs:
m Via the debugger interfaces, which can be retrieved using a debug client
object instance.

m Via a structure passed to the WogExts extension initialization callback.
The structure contains a set of API function pointers that can be used by
the extension.

The Debugger Interfaces

The DbgEng provides seven base interfaces to be used by the programmer.
Over time, more functionality has been added, and in order to preserve back-
ward compatibility, new versions of those interfaces have been introduced. For
example, at the time of writing, IDebugCont rol is the first interface version and
IDebugControl14 is the latest version of this interface.

Following is the list of interfaces and a brief explanation of their purpose and
some of the functions they provide:

m IDebugClient5—This interface provides various useful functions to start
or stop a debugging session and set the necessary DbgEng callbacks
(input/output/events). In addition, its QueryInterface method is used
to retrieve interfaces of the remaining interfaces.

m CreateProcess/AttachProcess—Creates a new process or attaches
to an existing one:

m AttachKernel—Attaches to a live kernel debugger.
m Get ExitCode—Returns the exit code of a process.
m™ OpenDumpFile—Starts a debugging session from a dump file.

m Set InputCallbacks/SetEventCallbacks—Sets the input/output
callbacks.

m™ IDebugContro14—This interface provides process-control-related functions:
m AddBreakpoint—Adds a breakpoint.

m Execute—Executes a debugger command.

---

**Page 151**

Chapter 4 = Debugging and Automation

259

m Set Interrupt—Signals the DbgEng to break into the target.

m WaitForEvent—Waits until a debugger event occurs. This is similar to
the WaitForDebugEvent () Win32 API.

m SetExecutionStatus—Sets the DbgEng’s status. This allows the pro-
grammer to resume execution, request a step into or step over, etc.

IDebugDataSpaces4—This interface provides memory and data-related
functionality:

m ReadVirtual—Reads memory from the target’s virtual memory.

m™ QueryVirtual—Equivalent to Win32’s virtualQuery (), this function
queries the virtual memory of the target’s virtual address space.

m™ ReadMsr—Reads the model-specific register value.
m WritePhysical—Writes physical memory.

IDebugRegisters2—Provides register introspection (enumeration, infor-
mation query) and set/get functionality. The DbgEng assigns registers an
index. To work with a named register you have to first figure out its index:

m GetDescription—Returns a description of the register (size, name,
type, etc.).
m SetValue/GetValue—Sets/gets the value of a register.

m Get IndexByName—Finds a register index given its name.

IDebugSymbols3—Provides functionality to deal with debugging symbols,
source line information, querying types, etc:

m Get ImagePath—Returns the executable image path.
M@ GetFieldName—Returns the name of a field within a structure.

IDebugSystemObjects4—Provides functionality to query information
from the debugged target(s) and the system it runs on:

m GetCurrent Processid—Returns the DbgEng process id of the currently
debugged process.

m Get Current ProcessHandle—Returns the system handle of the current
process.

m SetCurrentThreadId—Switches the current thread given its DbgEng
id. This is equivalent to the ~Nk command.

IDebugAdvanced4—Provides more functionality not necessarily present
in the other interfaces:

M Get ThreadContext /SetThreadContext—Gets/sets the thread context.

M GetSystemObject Information—Returns information about the desired
system object.

---

**Page 152**

260

Chapter 4 = Debugging and Automation

In order to use the APIs via the interfaces, you need to have an instance of
the IDebugClient (debugger client) interface or any of its derived interfaces. In
the following code snippet, the IDebugClients interface instance is passed to
the CreateInterfaces utility function. The latter then calls QueryInterface
repetitively to retrieve the needed interfaces:

bool CreateInterfaces(IDebugClient5 *Client)
{

// Interfaces already created?

1£ (Control != NULL)

return true;

// Get the debug client interface
1£f (Client == NULL)
{
m_LastHr=m_pDebugCreate(__uuidof (IDebugClient5) , (void**) &Client) ;
if (m_LastHr != S OK)
return false;

// Query for some other interfaces that we'll need.
do
{
m_LastHr = Client->QueryInterface (
__uuidof (IDebugControl4) ,
(void**) &Control) ;
if (m_LastHr != S OK)
break;
m_LastHr = Client->QueryInterface (
__uuidof (IDebugSymbols3) ,
(void**) &Symbols) ;
if (m_LastHr != S_OK)
break;
m_LastHr = Client->QueryInterface (
__uuidof (IDebugRegisters2) ,
(void**) &Registers) ;
if (m_LastHr != S OK)
break;
m_LastHr = Client->QueryInterface (
__uuidof (IDebugSystemObjects4) ,
(void**) &SystemObjects) ;
if (m_LastHr != S OK)
break;
m_LastHr = Client->QueryInterface (
__uuidof (IDebugAdvanced3) ,
(void**) &Advanced) ;
if (m_LastHr != S_OK)
break;
m_LastHr = Client->QueryInterface (
__uuidof (IDebugDataSpacesé4) ,
(void**) &DataSpace) ;
} while ( false);

---

**Page 153**

Chapter 4 = Debugging and Automation

261

}

The interface variables are defined like this:

return SUCCEEDED (m_LastHr) ;

IDebugDataSpaces4 *DataSpace;
IDebugRegisters2 *Registers;
IDebugSymbols3 *Symbols;
IDebugControl4 *Control;
IDebugSystemObjects4 *SystemObjects;
IDebugAdvanced3 *Advanced;

To acquire a debugger client interface (IDebugClient), use either the DebugCreate
function or the DebugConnect (connect to a remote host) function. The following

example acquires a debugger client interface using DebugCreate:

HRESULT Status;
IDebugClient *Client;
((Status = DebugCreate(__uuidof (IDebugClient),

if

}

(void**) &Client) )

printf ("DebugCreate failed,
return -1;

OxsX\n",

!= S OK)

Status) ;

// Okay, now ready to query for other interfaces...

WinDbg Extension APIs

Debugger extensions receive a pointer to a WINDBG_EXTENSION_APIS structure
via the WinDbgExtensionD11lInit extension initialization callback routine. The

structure has the following API pointers:

// wdbgexts.h
typedef struct _WINDBG EXTENSION APIS {

ULONG
PWINDBG_OUTPUT_ROUTINE
PWINDBG_GET_EXPRESSION
PWINDBG_GET_SYMBOL
PWINDBG_DISASM
PWINDBG_CHECK_ CONTROL _C

PWINDBG_READ PROCESS MEMORY ROUTINE

PWINDBG_WRITE PROCESS MEMORY ROUTINE

PWINDBG_GET_THREAD CONTEXT ROUTINE
PWINDBG_SET_THREAD CONTEXT ROUTINE

PWINDBG IOCTL ROUTINE
PWINDBG STACKTRACE ROUTINE

nSize;

lpOutputRoutine;
lpGetExpressionRoutine;
lpGetSymbolRoutine;
lpDisasmRoutine;
lpCheckControlCRoutine;
lpReadProcessMemoryRout ine;
lpWriteProcessMemoryRoutine;
lpGetThreadContextRoutine;
lpSetThreadContextRoutine;
lpIoctlRoutine;
lpStackTraceRoutine;

} WINDBG EXTENSION APIS, *PWINDBG EXTENSION APIS;

---

**Page 154**

262

Chapter 4 = Debugging and Automation

When the extension receives this structure, it should copy and store it ina
global variable, preferably named ExtensionApis. The reason to choose this
particular variable name is because the header file wdbgexts.h defines some
macros that refer to ExtensionApis to access the API pointers:

extern WINDBG EXTENSION APIS ExtensionApis;
#define dprintf ExtensionApis.1lpOutputRoutine)
#define GetExpression ExtensionApis.1lpGetExpressionRoutine)
#define CheckControlc

#define GetContext

(
(
(ExtensionApis.1lpCheckControlCRoutine)
(

ExtensionApis.lpGetThreadContextRoutine)

#define ReadMemory (ExtensionApis.lpReadProcessMemoryRout ine)

#define WriteMemory (ExtensionApis.lpWriteProcessMemoryRoutine)
#define StackTrace (ExtensionApis.lpStackTraceRoutine)

These macros enable extension writers to directly call SstackTrace or
WriteMemory, for instance, instead of using pExtension.1pStackTraceRout ine
Or pExtension.WriteMemory.

Apart from being able to use only the functions declared in the WINDBG_
EXTENSION_APTIS structure, it is also possible to use a whole range of other
functions that are based on the ExtensionApis.1lpIoct1Routine function.
For example, ReadPhysical () is an inline function that calls Ioct1() with the
IG_READ_PHYSICAL control code while passing it the appropriate parameters.

Please refer to the DbgEng help file for a list of functions that you can use
inside WdbgExts extensions.

Writing Debugging Tools Extensions

In the previous section you learned the concepts behind the SDK; now you are
ready to delve into more details about what a WdbgExts extension looks like
and how to write a very basic extension.

A debugger extension is simply a Microsoft Windows DLL. The DLL has to
export two mandatory functions needed by the DbgEng and then export as
many functions as the extension is providing to the debugger.

The first function that should be exported is WinDbgExtensionD11Init. It is
called when the debugger loads your extension:

VOID WinDbgExtensionD11lInit (
PWINDBG EXTENSION APIS lpExtensionApis,
USHORT MajorVersion,
USHORT MinorVersion)

ExtensionApis = *lpExtensionApis; // Take a copy

// Optionally also save the version information
SavedMajorVersion = MajorVersion;

---

**Page 155**

Chapter 4 = Debugging and Automation

263

SavedMinorVersion = MinorVersion;

return;

Notice that you save the passed 1pExtensionApis pointer contents. The passed
version information variables denote the Microsoft Windows build type and
build number, respectively. Optionally save those variables if you want to check
their values in the extension commands later.

The second function that should be exported is ExtensionApiVersion. It is
called by the DbgEng when it wants to query the version information from
your extension:

EXT_API VERSION ApiVersion =

{
5, // Major
1, // Minor
EXT API VERSION NUMBER64, // Revision
0 // Reserved

};

LPEXT_API_ VERSION ExtensionApiVersion (VOID)

{

return &ApiVersion;

Now that the mandatory functions (or callbacks) have been defined, you
proceed by declaring the extension commands.
An extension command has the following declaration:

CPPMOD VOID myextension (

HANDLE hCurrentProcess,
HANDLE hCurrentThread,
ULONG dwCurrentPc,
ULONG dwProcessor,
PCSTR args)

The most notable passed arguments are as follows:
m™ dwProcessor—The index of the current processor
m dwCurrentPc—The current instruction pointer

m args—The arguments passed (if any)

Another preferred way to declare an extension function is to use the DECLARE _
API (api_s) macro:

DECLARE API( test )

{

dprintf("This is a test extension routine") ;

}

---

**Page 156**

264

Chapter 4 = Debugging and Automation

kee At any time, any extension command can call DebugCreate () and then get
any interface it wants in order to gain extra functionality.

The final step is to export the two mandatory functions and the extension
commands that you plan to expose to the DbgEng. The usual way is to create a
.def file and call the linker with an additional /DEF: filename.def switch. This
is what the DEF file for the test extension we wrote looks like:

EXPORTS

; Callbacks provided for the debugger
WinDbgExtensionD11Init
ExtensionApiVersion

; Command callbacks
test

Place the resulting DLL in the debugging tools directory (or in the winext
subdirectory) or in the Windows system directory. Use !1load extname to load
your compiled extension and then !extension_command or !extname.ext_com-
mand to execute the extension command.

Useful Extensions, Tools, and Resources

Following is a short list of useful extensions, tools, and resources that can enhance
your debugging experience:

m narly (https: //code.google.com/p/narly/)—A handy extension that lists
/ SAFESEH handlers, displays information about /cs and DEP, searches for
ROP gadgets, and provides other miscellaneous commands.

m SOS—This extension, which ships with the Windows Driver Kit (WDk),
facilitates managed code debugging.

m !analyze—A very useful extension (ships with the DbgEng) that displays
information about the current exception or bugcheck.

m VirtualKd (http: //virtualkd.sysprogs.org/)—This is a tool that improves
the kernel debugging speed when used with VMWare or VirtualBox.

m windbg.info—This website provides a very comprehensive WinDbg/
DbgEng command reference and a discussion forum for users.

m kdext.com—This website provides a pair of DbgEng extensions. A nota-
ble extension is the assembly syntax highlighting and UI enhancements
extension.

---

**Page 157**

Obfuscation

Reverse engineering compiler-generated code is a difficult and time-consuming
process. The situation gets even worse when the code has been hardened, delib-
erately constructed to resist analysis. We refer to such techniques for hardening
programs under the general umbrella of obfuscation. Some examples of situations
in which obfuscation might be applied are as follows:

m Malware—Avoiding the scrutiny of both antivirus detection engines
and reverse engineers is a primary motive of the criminals who employ
malware in their operations, and therefore this has been a traditional
application of obfuscation for many years now.

m Protection of intellectual property—Many commercial programs have
some sort of protection against unauthorized duplication. Some systems
employ further obfuscation for the purpose of obscuring the implementa-
tion details of certain parts of the system. Good examples include Skype,
Apple’s IMessage, or even the Dropbox client, which protect their com-
munication protocol formats with obfuscation and cryptography.

267

---

**Page 158**

268

Chapter 5 = Obfuscation

m Digital Rights Management—DRM schemes commonly protect certain
crucial pieces of information (e.g., cryptographic keys and protocols) using
obfuscation. Apple’s FairPlay, Microsoft’s Media Foundation Platform and
its PlayReader DRM, to cite only two, are examples of obfuscation applica-
tion. Currently, this is the leading contemporary application of obfuscation.

Speaking in the abstract, “obfuscation” can be viewed in terms of program
transformations. The goal of such methods is to take as input a program, and
produce as output a new program that has the same computational effect as the
original program (formally speaking, this property is called semantic equivalence
or computational equivalence), but at the same time it is “more difficult” to analyze.

The notion of “difficulty of analysis” has long been defined informally, without
any backing mathematical rigor. For example, it is widely believed that—insofar
as a human analyst is concerned—a program’s size is an indicator of the difficulty
in analyzing it. A program that consumes 20,000 instructions in performing a
single operation might be thought to be “more difficult” to analyze than one
that takes one instruction to perform the same operation. Such assumptions are
dubious and have attracted the scrutiny of theoreticians (such as that by Mila
Dalla Preda’”’ and Barak et al.’).

Several models have been proposed to represent an obfuscator, and (in a
dual way) a deobfuscator. These models are useful to improve the design of
obfuscation tools and to reason about their robustness, through adapted criteria.
Among them, two models are of special interest.

The first model is suited for the analysis of cryptographic mechanisms, in
the so-called white box attack context. This model defines an attacker as a proba-
bilistic algorithm that tries to deduce a pertinent property from a protected
program. More precisely, it tries to extract information other than what can be
trivially deduced from the analysis of the program’s inputs and outputs. This
information is pertinent in the sense that it enables the attacker to bypass a
security function or represents itself as critical data of the protected program.
In a dual way, an obfuscator is defined in this model as a virtual black box’s
probabilistic generator, an ideal obfuscator ensuring that the protected program
analysis does not provide more information than the analysis of its input and
output distributions.

Another way to formalize an attacker is to define the reverse engineering action
as an abstract interpretation of the concrete semantics of the protected program.
Such a definition is naturally suited to the static analysis of the program’s data
flow, which is a first step before the application of optimization transformations.
In a dual way, an obfuscator is defined in the abstract interpretation model as
a specialized compiler, parameterized by some semantic properties that are
not preserved.

The goal of these modeling attempts is to get some objective criteria relative to
the effective robustness of obfuscation transformations. Indeed, many problems

---

**Page 159**

Chapter 5 = Obfuscation

269

that were once thought to be difficult can be efficiently attacked via judicious
application of code analysis techniques. Many methods that have arisen in the
context of more conventional topics in programming language theory (such as
compilers and formal verification) can be repurposed for the sake of defeating
obfuscation.

This chapter begins with a survey of existing obfuscation techniques as
commonly found in real-world situations. It then covers the various available
methods and tools developed to analyze and possibly break obfuscation code.
Finally, it provides an example of a difficult, modern obfuscation scheme, and
details its circumvention using state-of-the-art analysis techniques.

A Survey of Obfuscation Techniques

For simplicity of presentation, we begin by dividing obfuscations into two
categories: data-based obfuscation and control-based obfuscation. You will
see later that the two combine in complex and difficult ways and are, in fact,
inseparable. Before wandering deeply down these paths, however, we begin
with a representative example of the types of code that one might encounter in
real-world obfuscation. Note that the example is particularly simple because it
involves only data-based obfuscations, not control-based ones.

The Nature of Obfuscation: A Motivating Example

When targeting the x86 processor, compilers tend to generate instructions drawn
from a particular, tiny subset of the available instruction set, and the control
structure of the generated program follows predictable conventions. Over time,
the reverse engineer develops a style of analysis tailored to these patterns of
structured code. When confronted by nonconformant code, the speed of one’s
analysis can suffer tremendously.

This phenomenon can be illustrated simply by a concrete example. Because
one of the goals of a compiler optimizer is to reduce the amount of computa-
tional resources involved in performing a task, and 50 years’ worth of research
have imbued them with formidable capabilities toward this pursuit, one does
not commonly spot obvious inefficiencies in the translation of the original
source code into assembly language. For example, if the source code were to
dictate that some variable be incremented by five (e.g., due to a statement such
asx += 5;),a compiler would likely generate assembly code akin to one of
the following:

01: add eax, 5
02: add dword ptr [ebp-10h], 5
03: lea ebx, [ecx+5]

---

**Page 160**

270

Chapter 5 = Obfuscation

In obfuscated code, one might instead encounter code such as the following,
assuming that EAx corresponds to the variable x, and that the value of EBx is
free to be overwritten (or “clobbered”):

Ol:
02:
03:
04:
O05:
06:
O7:
08:
09:
10:
11:
12:
13:
14:
15:
16:
17:
18:
19:
20:
21:

xor ebx, eax

xor eax, ebx

xor ebx, eax

inc eax

neg ebx

add ebx, 0A6098326h
cmp eax, esp

mov eax, 59F67CD5h
xor eax, OFFFFFFFFh
sub ebx, eax

rel eax, cl

push OF9CBE47Ah

add dword ptr [esp], 6341B86h
sbb eax, ebp

sub dword [esp], ebx
pushf

pushad

pop eax

add esp, 20h

test ebx, eax
pop eax

You can see a variety of obfuscation techniques at work in this example:

m Lines 1-3 use the “xor swap trick” for exchanging the contents of two

locations—in this case, the EAx and EBX registers.

Line 4 shows an assignment to the EAx register that is actually “junk” (as
EAX is overwritten with a constant on line 8).

On lines 5-6, the EBx register is negated and added to the constant
0A6098326h: EBX = - EAX + 0A6098326h.

On line 7, AX is compared with Esp. The cmp instruction modifies only
the flags, and the flags are overwritten on subsequent lines before being
used again, so this code is junk.

Lines 8-9 move the constant 59F67CD5h into the EAX register and xor it with
-1h (which, in binary, is all one bits). xoring with all ones is equivalent
to the NoT operation; therefore, the effect of this sequence is to move the
constant 0A609832Ah into EAX.

Line 10 subtracts the constant in EAX from EBX: EBX = - FAX + 0A6098326h
- 0A609832Ah, or EBX = - EAX - 5, or EBX = -( EAX + 5).

Line 11 modifies zax through use of the RcL instruction. This instruction
is junk because EAX is overwritten on line 18.

---

**Page 161**

Chapter 5 = Obfuscation

271

m Lines 12-13 push the constant 0F9CBE47Ah and then add the constant
6341B86h to it, resulting in the value oh on the bottom of the stack.

m Line 14 modifies EAx through use of the sBB instruction, involving the
extraneous register EBP. This instruction is junk, as EAX is overwritten on

line 18.
m Line 15 subtracts EBx from the value currently on the bottom of the stack
(which is oh). Therefore, dword ptr [ESP] = 0 - -( EAX + 5), Or dword

ptr [ESP] = EAX+5.

m Lines 16-19 demonstrate operations involving the stack: nine dwords are
pushed, one is popped into £ax, and the stack pointer is then adjusted to
point to the same location that it pointed to before the sequence executed.

m Line 20 tests EBX against the EAX register and sets the flags accordingly. If
the flags are redefined before their next use, then this instruction is dead.

m Line 21 pops the value on the bottom of the stack (which holds £ax + 5)
into the EAX register.

In summary, the code computes EAX = EAX + 5.

Needless to say, the obfuscated code does not at all resemble the compiler-
generated code, and one faces considerable difficulty in ascertaining the function-
ality of the snippet. Several obfuscation techniques are present in this example:

m Pattern-based obfuscation
m Constant unfolding

m Junk code insertion

m Stack-based obfuscation

m The use of uncommon instructions, such as RCL, SBB, PUSHF, and PUSHAD

Correspondingly, a variety of existing compiler transformations can be used
to render the code into a form that is closer to the original:

m Peephole optimization
m Constant folding
m Dead statement elimination

m Stack optimization

The Interplay Between Data Flow and Control Flow

Consider the following instruction sequence:

01: mov eax, dword ptr [ebp-10h]
02: jmp eax

---

**Page 162**

272

Chapter 5 = Obfuscation

Suppose you wish to construct a “correct,” classical control-flow graph for a
program containing sequences like this one. In order to determine what the next
instruction will be after line 2 has executed—or, perhaps the set of potential
successor instructions—you need to determine the set of possible value(s) for
the EAx register at that location. In other words, the control flow for this snip-
pet is dependent upon the data flow as it pertains to the location [EBP-10h]
at the program point I1 (line 1). However, in order to determine the data flow
with respect to [EBP-10h], you need to determine the control flow with respect
to the line 1 location: You must know all possible control transfer instructions
(and the associated data flow leading to those locations) that could possibly
target the line 1 location. It is not meaningful to talk about control flow without
simultaneously talking about data flow, or vice versa.

The situation is even more difficult than it might appear on the surface. Program
analysis tries to answer questions such as “What values might the location [EBP-
10h] assume under any possible circumstance?” To combat intractability and
undecidability, many forms of program analysis employ approximations of the
state space. Some approximations are fine (e.g., approximating the set {1,3} by
{1,2,3} ), and some are coarse (e.g., approximating that same set by {0,1,...,2° -l}).
(Fine and coarse are not technical terms in this paragraph.) If you cannot finely
approximate the set of potential values of the [EBP-10h] location (for example,
if you must assume that the location could take on any possible value), then
you do not know where the jump will point, so you must assume that it could
target any location within the address space. Then, the data flow facts from the
line 2 location must be propagated into those at every other location. In practical
settings, such a decision will severely impact the analysis, most likely causing
it to conservatively conclude that all states are possible at all locations, which
is correct but useless.

Worse yet, if you ever must assume that a jump could target any location,
then due to variable-length instruction encoding on x86, many of these trans-
fers will be into locations that do not correspond to the beginning of a proper
instruction. Such bogus instructions are likely to wreak havoc on any analysis,
especially when combined with the observations in the previous paragraph.

Academic work in this area, such as that by Kinder*’ and Thakur et al.*1, seeks
to construct systems that can return correct answers for all possible inputs. These
systems prefer to tell users that they cannot determine precise information,
return correct but grossly imprecise results, or die trying (e.g., by exhausting
all available memory or failing to terminate due to tractability issues), rather
than give an answer that is not fully justified. This goal is laudable, given the
motivation from whence these disciplines were founded: to ensure absolute
correctness of programs and analyses. However, it is not in line with our moti-
vations as obfuscation researchers.

---

**Page 163**

Chapter 5 = Obfuscation

273

Deobfuscation is a creature of a different sort than formal verification or
program analysis, even if we prefer to use techniques developed in those con-
texts. Whereas an obfuscator transforms a program P,,;,into a program P,,, we
seek either a translator from P,,,into P,,;, or enough information about P,,;to
answer questions proximate to some reverse engineering effort. We hesitate to
use unsound methods, but we prefer actual results when the day is finished, so

we may employ such methods, albeit consciously and grudgingly.

Data-Based Obfuscations

We begin by looking at obfuscation techniques that can be best described in
terms of their effect on data values and noncontrol computations. In particular,
assume that the presented snippets occur within a single basic block of the pro-
grams control-flow graph. The discussions of control-based obfuscations, and
their combination with data-based obfuscations, are deferred to later sections.

Constant Unfolding

Constant folding is one of the earliest and most basic compiler optimizations. The
goal of this optimization is to replace computations whose results are known at
compile-time with those results. For example, in the C statement x = 4 * 5;,
the expression 4 * 5 consists of a binary arithmetic operator (*) that is supplied
with two operands whose values are statically known (4 and 5, respectively). It
would be wasteful for the compiler to generate code that computed this result
at run-time, as it can deduce what the result will be during compilation. The
compiler can simply replace the assignment with x = 20;.

Constant unfolding is an obfuscation that performs the inverse operation. Given
a constant value that is used somewhere in the input program, the obfuscator
can replace the constant by some computation process that produces the con-
stant. You have already encountered this obfuscation in the motivating example:

01: push OF9CBE47Ah
02: add dword ptr [esp], 6341B86h

Neglecting the modifications that this sequence has upon the flags, this was
found to be equivalent to push 0h.

Data-Encoding Schemes

The fundamental flaw of this technique is that constants have to be dynamically
decoded (thus exposed, as well as the decode function) at run-time before being
processed. We have the encoding function f(x) = x — 6341B86h, whose result f(x) is
pushed on the stack, and then the decoded function is applied: f, (x)= x + 6341B86h.

---

**Page 164**

274

Chapter 5 = Obfuscation

This construct is trivial; deobfuscation is done by simply applying the standard
compiler’s constant folding optimization.

Efforts have been made to harden these statements and propose more resilient
encoding schemes. Some techniques, such as polynomial encoding and residue
encoding, have been described in patent US6594761 B1 by Chow, Johnson and
Gul". Affine maps are also commonly used.

What if one could find an encoding such that it is not mandatory to decode
variables to manipulate them (an equivalent operation can be defined on the
encoded variables)? This property, called homomorphism, has been discussed
in an obfuscation-oriented view, as well as a refinement of the residue coding
technique in works such as those of Zhu and Thomborson.“

In abstract algebra, a homomorphism is an operation-preserving mapping between
two algebraic structures. Consider, for example, two groups, G and H, equipped
respectively with operations +, and +,. We want to construct a mapping f between
the sets underlying G and H, and we want your mapping to respect the opera-
tions +, and +, In particular, we must have that f (x+, y) = f(x) +, f(y).

The notion of a homomorphism can be generalized beyond groups to arbitrary
algebraic structures. For example, you can consider ring homomorphisms that
simultaneously preserve both the addition and the multiplication operators. In
contrast to mappings that preserve only one of the ring’s operations and not
the other, or induce restrictions upon the operators or their usage, unrestricted
mappings are considered fully homomorphic.

Fully homomorphic mappings have a natural application to obfuscation.
If the source algebra is the unencoded domain, and the target algebra is the
encoded one, then a homomorphic mapping enables us to perform computa-
tions directly upon the encoded data without having to decode it beforehand
and re-encode it afterward.

At the time of writing, the topic of homomorphic cryptography is still in
its infancy. Fully homomorphic cryptosystems have been shown to exist, and
they enable the computation of encrypted programs upon encrypted data. That is
to say, rigorous statements can be made concerning the hardness of determin-
ing specifics about the program being executed, and which data it is operating
upon. At present, the schemes are too inefficient for practical usage, and how to
best apply the technology to arbitrary computer programs is an open question.

Dead Code Insertion

Another common compiler optimization is known as dead code elimination, which
is responsible for removing program statements that do not have any effect on
the programs operation. For example, consider the following C function:

int £()

{

int x, y;

---

**Page 165**

Chapter 5 = Obfuscation

275

x = 1; // this assignment to x is dead
y= 2; // y igs not used again, so it is dead
x = 3; // x above here is not live

return x; // x is live

}

Ultimately, the function returns the number 3. It does so after several mean-
ingless computations that do not affect the function’s output. The first assign-
ments to x and y are said to be dead, as they have no effect on live computations.

Obfuscators perform the inverse of this operation by inserting dead code for
the purpose of making the code harder to follow—the reverse engineer has to
manually decide whether a given instruction participates in the computation of
some meaningful result. The ability to insert “dead” code requires the obfuscator
to know which registers are “live” at every given program point; for example, if
EAX contains an important value (it’s live), and EBx does not (it’s dead), then you
can insert statements that modify EBx.

Deobfuscation of this construct is done by simply applying the standard
compiler’s dead statement elimination optimization, which can be done either
on a single basic block or across an entire control-flow graph.

Arithmetic Substitution via Identities

Mathematical statements can be made relating the results of certain operators
to the results of combinations of other operators. You have already seen an
instance of this general phenomenon in the motivating example, when you
encountered the instruction XOR EAX, 0FFFFFFFFh (where the binary representa-
tion of OFFFFFFFFh is all one bits). Because 0 XOR 1 = 1,and1 xoR 1 = 0, this
instruction actually flips each of the bits in Zax; in other words, it is synonymous
with the Not operator. Similarly, you can make the following statements:

m -x = ~x + 1 (by definition of two’s complement)

M rotate left(x,y) = (x << y) | (x >> (bits(x)-y))
M rotate right(x,y) = (x >> y) | (x << (bits(x)-y))
mox-1 = ~-x

Mx+l = - x

Pattern-Based Obfuscation

Pattern-based obfuscation, a staple of many contemporary protections, has a
simple underlying concept. The protection author manually constructs trans-
formations that map one or more adjacent instructions into a more complicated
sequence of instructions that has the same semantic effect. For example, a pat-
tern might convert the sequence

O01: push reg32

---

**Page 166**

276

Chapter 5 = Obfuscation

into this sequence (which we will call #1):

01: push imm32
02: mov dword ptr [esp], reg32

Or, it might convert that same sequence into this sequence (#2):

01: lea esp, [esp-4]
02: mov dword ptr [esp], reg32

Or this one (#3):

O01: sub esp, 4
02: mov dword ptr [esp], reg32

Patterns can be arbitrarily complicated. A more complex example might

substitute the pattern:

O01: sub esp, 4

for this pattern (#4):

01: push reg32

02: mov reg32, esp
03: xchg [esp], reg32
04: pop esp

Some protections have hundreds of patterns. Most protections apply patterns

randomly to the input sequence, such that two obfuscations of the same piece
of code result in a different output. Also, the patterns are applied iteratively.
Consider the following input:

01: push ecx

Imagine that it is transformed via substitution #3:

O01: sub esp, 4
02: mov dword ptr [esp], ecx

Now suppose that the obfuscator is run a second time, and the first instruc-

tion is replaced according to pattern #4:

O01: push ebx

02: mov ebx, esp

03: xchg [esp], ebx

04: pop esp

05: mov dword ptr [esp], ecx

This process can be applied indefinitely, resulting in an arbitrarily large

output sequence. With enough patterns, one can transform one instruction into
millions of instructions.

Note a few things about these substitutions. #1 and #2 preserve semantic

equivalence: After those sequences execute, the CPU will be in the same state

---

**Page 167**

Chapter 5 = Obfuscation

277

that it would have been if the original one were executed instead. #3 does not
preserve semantic equivalence, because it uses the sub-instruction that changes
the flags, whereas the original push does not. As for sequence #4, the original
does change the flags, whereas the substitution does not; also, whereas the
original does not modify memory at all, the substitution writes the value of
ESP onto the bottom of the stack (hence, you could also consider this as being
equal to the PUSH ESP instruction).

These considerations illustrate the difficulty of obfuscating assembly code
post-compilation. The protection is only safe to execute substitution #3 if it is
known that the flags modified by the instruction are not used before the next
modification to those flags. Substitution #4 is similarly safe if the flags are dead,
and if the resultant code is indifferent to the contents of [ESP] after the original
SUB ESP, 4 operation. Ensuring flag liveness requires building the function’s
control-flow graph, which can be difficult due to indirect branches. Ensuring
that the stack memory modification is safe would be extremely difficult due to
memory aliasing. These specific concerns are unlikely to affect normal functions
generated by a compiler for which control-flow graphs can be generated, but it
is hoped that they illustrate the perils of applying semantically non-equivalent
transformations to compiled code.

Owing to the complexities of obfuscating compiled assembly language, pro-
tections most commonly apply these transformations against the code cor-
responding to the protection itself, rather than the target’s code. This way, the
protection authors can guarantee that the input code will be oblivious to those
transformations that do not preserve strict semantic equivalence.

Deobfuscation of this type of obfuscation is simple, although it can be time-
consuming to write the deobfuscator. One can construct inverse pattern substitu-
tions, which instead map the target sequences into the original ones. In fact, this
corresponds to a routine compiler optimization known as peephole optimization.
Academic works, such as that by Jacob et al.* or Bansal,! have discussed the
automated construction of both pattern-obfuscators and peephole optimizers.

This brings us back to the question of practical results versus academic ones.
Suppose you are dealing with a pattern-based obfuscator that contains errors
(e.g., erroneous pattern substitutions that do not preserve semantic equiva-
lence). Suppose further that you, as a deobfuscation researcher, are aware of
the errors and are able to correct them at deobfuscation time. This means that
your deobfuscator will similarly not preserve semantic equivalence and is there-
fore “incorrect” in absolute terms as far as transformation goes, but it actually
produces “correct” results with respect to the pre-obfuscated code. Should you
make the substitution? The formal correctness crowd would say no; we would
answer in the affirmative.

---

**Page 168**

278

Chapter 5 = Obfuscation

Control-Based Obfuscation

When reverse engineering compiler-generated code, reverse engineers are able to
rely on the predictability of the compiler’s translations of control flow constructs.
In doing so, they can quickly ascertain the control flow structure of the original
code at a level of abstraction higher than assembly language. Along the way,
the reverse engineer relies upon a host of assumptions about how compilers
generate code. Ina pure compiled program, all code in a basic block will be most
often sequentially located (heavy compiler optimizations can possibly render
this basic premise null and void). Temporally related blocks usually will, too.
A CALL instruction always corresponds to the invocation of some function. The
RET instruction, too, will almost always signify the end of some function and its
return to its caller. Indirect jumps, such as for implementing switch statements,
appear infrequently and follow standard schemas.

Control-based obfuscation attacks these planks of standard reverse engineering,
in a way that complicates both static and dynamic analyses. Standard static analy-
sis tools make similar assumptions as human reverse engineers, in particular:

m The CALL instruction is only used to invoke functions, and a function
begins at the address targeted by a call.

m= Most calls return, and if they do, they return to the location immediately
following the CALL instruction; ret and RETN statements connote function
boundaries.

m Upon encountering a conditional jump, disassemblers assume that it was
placed into the code “in good faith”—in particular that:

m Both sides of the branch could feasibly be taken.
m Code, not data, is located down each side of the branch.
m They will be able to easily ascertain the targets of indirect jumps.

m Indirect jumps and calls will only be generated for standard constructs
such as switches and function pointer invocations.

m All control transfers target code locations, not data locations.

m Exceptions will be used in predictable ways.

With respect to control transfers, disassemblers assume a model of “nor-
mality” based around the patterns of standard compiled code. They explicitly
create functions at call targets, end them at return statements, continue disas-
sembling after a call instruction, traverse both sides of all conditional branches,
assume all branch targets are code, use syntactic pattern-matching to resolve
indirect jump schema, and generally ignore exceptional control flow. Violating
the assumptions laid out previously leads to very poor disassembly. This is a

---

**Page 169**

Chapter 5 = Obfuscation

279

consistent thorn in the side of obfuscation researchers, and an open research
topic (as discussed previously) in verification.

Dynamic analysis has an easier time with respect to indirect control transfers,
since it can explicitly follow execution flow. However, the attacker still faces ques-
tions involving determining the targets of indirect transfers, and suffers from
the lack of sequential locality induced by so-called spaghetti code. The following
sections elaborate upon what happens when these assumptions are challenged.

Functions In/Out-Lining

The call graph of a program carries a lot of its high-level logic. Playing with the
notion of a function can break some of the reverser’s assumptions. It’s possible to:

m Inline functions—The code of a subfunction is merged into the code of
its caller. Code size can grow quickly if the subfunction is called multiple
times.

m= Outline functions—A subpart of a function is extracted and transformed
into an independent function and replaced by a call to the newly created
functions.

Combining these two operations over a program leads to a degenerated call
graph with no apparent logic. It goes without saying that functions’ prototypes
can also be toyed with to reorder arguments, add extra, fake arguments, and so
on, to contribute to logic obscurity.

Destruction of Sequential and Temporal Locality

As stated, and as understood intrinsically by those who reverse engineer com-
piled code, the instructions within a single, compiled basic block lie in one
straight-line sequence. This property is called sequential locality. Furthermore,
compiler optimizers attempt to put basic blocks that are related to one another
(for example, a block and its successors) nearby, for the purpose of maximizing
instruction cache locality and reducing the number of branches in the compiled
output. We call this property the sequential locality of temporally related code. When
you reverse engineer compiled code, these properties customarily hold true. One
learns in analyzing such code that all of the code responsible for a single unit of
functionality will be neatly contained in a single region, and that the proximate
control-flow neighbors will be nearby and similarly sequentially located.

A very old technique in program obfuscation is to introduce unconditional
branches to destroy this aspect of familiarity that reverse engineers organically
obtain through typical endeavors. Here is a simple example:

O01: instr _1:

02: push offset caption

03: jmp instr 4

---

**Page 170**

280 Chapter 5 = Obfuscation

04:

05: instr 2:

06: call MessageBoxA
O07: jmp instr_5

O08:

09: instr 3:

10: push 0

11: jmp instr 2

12:

13: start:

14: push 0

15: jmp instr 1

16:

17: instr 4:

18: push offset dlgtxt
19 jmp instr 3

20:

21: instr_5:

22: ;

This example shows the lack of sequential locality for instructions within a
basic block, and not temporal locality of multiple basic blocks. In practice, large
amounts of the program’s code will be intertwined in such a fashion (usually
with more than one instruction on a given basic block, unlike the preceding
example).

From a formal perspective, this technique does not even deserve to be called
“trivial,” as it has no semantic effect whatsoever on the program. Constructing
a control-flow graph and removing spurious unconditional branches will defeat
this scheme entirely. However, in terms of analysis performed manually by a
human, the ability to follow the code has been dramatically slowed.

Processor-Based Control Indirection

For most processors, two essential displacement primitives are the ump-like
branch and the cauL-like save instruction pointer and branch. These primi-
tives can be obfuscated by using dynamically computed branch addresses or
by emulating them. One of the most basic techniques is the couple PUSH-RET
used as a UMP instruction:

01: push target_addr
02: ret

That’s (almost) semantically equivalent to the following:

01: jmp target_addr

---

**Page 171**

Chapter 5 = Obfuscation

281

The CALL instruction is an easy target for obfuscators because most disas-
semblers assume the following about its high-level semantics:

m The target address is a subfunction entry point.

= A call returns (i.e., the instruction after the CALL is executed).

It is actually easy to break these assumptions. Consider the following example:

01: call target_addr
02: <junk code>

03: target_addr:

04: add esp, 4

The CALL is used as a JMp; it will never return to line 2. The stack is fixed (the
return address is discarded from the stack) on line 3. Next consider, these two
elements:

01: basic _block_a:
02: add [esp], 9
03: ret

and

01: basic _block_b:

02: call basic_block_a
03: <junk code>

04: true_return_addr:
05: nop

basic _block_b’s line 2 CALL instruction points to basic_block_a, which actu-
ally is only a stub that updates (see basic_block_a’s line 2) the return address
stored onto the top of the stack before the RET instruction uses it (basic_block_a’s
line 3). In these two examples the result is an interval between CALL’s natural
(expected) and effective return addresses; an obfuscator can (and will) take
advantage to insert code that thwarts disassemblers and creates confusion.

The following example is an interesting enrichment of the standard PUSH-RET
used as JMP previously:

01: push addr_branch default
02: push ebx

03: push edx

04: mov ebx, [esp+8]

05: mov edx, addr_branch_jmp
06: cmovz ebx, edx

07: mov [esp+8], ebx

08: pop edx

09: pop ebx

10: ret

---

**Page 172**

282

Chapter 5 = Obfuscation

The basis of this construction actually is a PUSH-RET. Line 7 writes the target
address onto the stack; it is used by the RET at line 10. The pushed address comes
from EBX (line 7), which is conditionally updated by the cmovzx instruction at
line 6. If the condition is satisfied (the z flag is tested), then the instruction acts
like a standard mov (EBx is overwritten by EDx, which contains the branch target
address), otherwise it acts like a Nop (thus EBx contains the default branch address).
In the end, one can clearly see this pattern stands for a conditional jump (72).

Operating System-Based Control Indirection

The program can make use of operating system primitives (even though it may
imply a loss of portability). The Structured Exception Handler (SEH), Vectored
Exception Handler (vEH), and Unhandled Exception Handler, in Windows, and
signal handlers and set jmp/longjmp functions, in Unix, are commonly used to
obfuscate the control flow.

The basic algorithm can be decomposed as follows:

1. Obfuscated code triggers an exception (using invalid pointer, invalid
operation, invalid instruction, etc.).

2. The operating system calls the registered exception handler(s).

3. The exception handler dispatches the instruction flow according to its
internal logic and sets back the program in a clean state.

The following example has been seen billions of times within x86 binaries:

01: push addr_seh_handler

02: push fs: [0]

03: mov fs:[0], esp

04: xor eax, eax

05: mov [eax], 1234h

06: <junk code>

07: addr_seh handler:

08: <continue execution here>
09: pop fs: [0]

10: add esp, 4

Lines 1-3 set up the szH. An exception is then triggered in the form of an
access violation as line 5 attempts to write at 0x0. Assuming the program is not
debugged, the operating system will transfer execution to the SEH handler. Please
also note that when a SEH handler is called, it receives a copy of the thread’s
context as one of its arguments, and the instruction pointer register value can
be modified to further obfuscate the control flow redirection.

Keegy This technique also efficiently acts as an anti-debugger. Basically, the job of
a debugger is to handle exceptions. These exceptions have to be passed to the debug
target; otherwise, the target’s behavior will be modified and tampering detected.

---

**Page 173**

Chapter 5 = Obfuscation

283

More interesting, the concept can also be reversed. What if a protection inserts
exceptions in the original program and catches them with its own attached debug-
ger? The protected program consists of a debuggee and debugger. A well-known
example of this is the namomites feature from Armadillo. Namomites actually
replace (conditional) jumps by INT 3 instruction. The exception is caught by the
protection’s debugger, which updates the debuggee’s context appropriately to
emulate the (conditional) jumps. One cannot simply detach the debugger from
the debuggee; otherwise, exceptions would not be handled and the program
would crash. An implementation of this concept has been proposed by Deroko.”

Opaque Predicates

An opaque predicate (introduced by Collberg in “A Taxonomy of Obfuscating
Transformations”? and “Manufacturing Cheap, Resilient, and Stealthy Opaque
Constructs’) is a special conditional construct (Boolean expression) that always
evaluates to either true or false (respectively noted P’ and P"). Its value is known
only at compilation/obfuscation time and should be unknown to an attacker as
well as computationally hard to prove, to meet a sufficient degree of resilience.
Used in combination with a conditional jump instruction, it introduces an
additional, spurious branch—i.e., an additional edge in the control-flow graph
(CFG). This dead branch can be used to insert junk code or special properties
like cycles in the CFG to harden the analysis. However, the spurious branch has
to look real enough to escape simple detection by a human attacker (for example,
only one of the two branches contains necessary variable initializations).

It has the appearance of a conditional jump but its semantics are that of an
unconditional jump. Computationally complex mathematical problems can be
used to implement opaque predicates. You can also use some environmental
variables whose values are constant and known at compilation/obfuscation
time. This last technique may be less resilient because there is a limited, finite
set of candidate variables, thus limiting the potential diversity.

Designing resilient opaque predicates is a tough job. They are superfluous
pieces of code mixed with existing code that has its own logic/style; if no special
care is taken they are easily detectable. A good practice is to create dependen-
cies between the predicate and the program’s state/variables. A human attacker
(you) is usually quite efficient at detecting dubious patterns. Using an absurdly
complex predicate may effectively thwart a static analysis tool but it will prob-
ably be easily detected by a human attacker.

An interesting variation on the original concept uses a predicate that ran-
domly returns either true or false (noted P’). As both branches are potentially
executed at run-time, they have to be semantically equivalent. In most cases
that amounts to cloning (and possibly diversifying) a basic block (or a larger
piece of code), producing a “diamond-like” construct.

---

**Page 174**

284

Chapter 5 = Obfuscation

Simultaneous Control-Flow and Data-Flow Obfuscation

For the sake of clarity, we have dissociated control-flow and data-flow obfusca-
tion so far. In practice, however, both are intimately linked. This section presents
techniques based on this interplay.

Inserting Junk Code

This technique is intimately tied to control flow obfuscation. It basically consists
of inserting a dead (that is, never executed) code block between two valid code
blocks. The objective is to totally thwart a disassembler that has already been
tricked into following an invalid path (typically a case of opaque predicates).
Instructions contained within the junk code may be partially invalid, or may
create branches to invalid addresses (such as in the middle of valid instructions)
to over-complicate the CFG.

The most trivial example of junk code insertion could be as follows:

O01: jmp label

02: <junk>

03: label:
04: <real code>

Here is something a bit more elaborate, using a dummy opaque predicate:

O01: push eax
02: xor eax, eax

03: jz 9

04: <junk code start>
05: jg 4

06: inc esp

O07: ret

08: <junk code end>
09: pop eax

The conditional jump at (address) line 3 is always true because the EAX reg-
ister is zeroed by the xor instruction at line 1. That means you have six bytes
of junk code. This junk block uses instructions that will influence the disas-
sembler, creating a new branch and seemingly inserting a function end (the
RET instruction at line 9).

When generated appropriately, junk code blocks may be quite difficult to spot
at first sight. Most often they will be removed from the disassembler’s reach as
a side effect of control flow deobfuscation (see http: //www.openrce.org/blog/
view/1672/Control_ Flow Deobfuscation_ via Abstract Interpretation). In
the last example, if the opaque predicate is detected as such, then no more paths
lead to the junk code block. Like all the other techniques, if it is not differenti-
ated sufficiently—for example, using a limited database of static patterns—its
resilience and strength tend to be minimal.

---

**Page 175**

Chapter 5 = Obfuscation

285

Control-Flow Graph Flattening

The basic idea behind graph flattening is to replace all control structures with a
unique switch statement, known as the dispatcher. A subgraph of the program's
control-flow graph is selected (implementations often work at the level of func-
tions) and transformed, at which time basic blocks may be reworked (split or
merged). Each basic block is then responsible for updating the dispatcher’s
context (i.e., the subprogram’s state) so that the dispatcher can link to the next
basic block (see Figure 5-1). Relationships between basic blocks are now “hidden”
within the dispatcher context’s manipulation operations. Conditional jumps (as
in block d) can easily be emulated using flags testing and ImuL instructions, or
simple cmov instructions.

Figure 5-1

It goes without saying that a large part of this technique’s resilience against
static analysis rests on the ability to obfuscate the context’s manipulations and
transitions. Various features can be implemented to harden the problem, such
as inter-procedural relationships, pointer aliasing, inserting dummy states,
and so on.

In the same fashion as opaque predicates, CFG flattening can also be used
to insert dead code paths and spurious basic blocks. A lot can be said about
graph flattening and how to harden an implementation. The resulting graph
offers no clues about the structure of the algorithm, and dispatch and context
manipulation code also add an overhead that contributes to hiding the protected
code. This technique is conceptually the same as code virtualization (virtual

---

**Page 176**

286

Chapter 5 = Obfuscation

machine); it can be seen as partial virtualization that targets (virtualizes) only
the control flow (not the data flow).

Should you want to see flattened code yourself, just grab a copy of a Flash
plugin (such as NPSwF32.d11), disassemble the file, and look for functions with
the biggest size. Flattened functions are easily recognizable.

Virtual Machines

Virtual machines (VMs) are a potent class of software protection and an espe-
cially complex transformation. A VM basically consists of an interpreter and
some bytecode. The language supported by the interpreter is at the discretion
of the protection. At compile-time, selected parts of code are compiled with
respect to the VM’s target architecture (they are retargeted) and then inserted
into the protected program alongside the associated interpreter. At run-time,
the interpreter assumes the bytecode execution (i.e., the translation from target
architecture to original architecture). VMs usually come with sizeable overhead
in terms of performance (particularly CPU time), which is why typically only
specific, selected parts of the original program are virtualized.

Examples of well-known, VM-centered protections include VMProtect and
CodeVirtualizer. We will later delve into the delightful activity of VM analysis.
For now, suffice it to say that an attacker has to understand the interpreter in
order to analyze the bytecode and eventually to create a compiler from target
architecture to native architecture (unvirtualization).

White Box Cryptography

When the application to be protected cannot base its security on the use of a
hardware component, or on a network server, you must hypothesize an attacker
able to execute the application in an environment that he or she perfectly con-
trols. The attacker model matching this situation, called the white-box attack
context (WBAC), imposes a particular software implementation of classical
cryptographic primitives.

Such mechanisms are tailor-made to ensure confidentiality of a secret key
within an algorithm. Such a transformation (hiding a key in an encryption
algorithm, with or without the help of environment interaction) can be formal-
ized as an obfuscation transformation.

This section describes some negative and positive results concerning code
obfuscation, and their impact on this key management problem.

A probabilistic algorithm O is an obfuscator if it satisfies the following prop-
erties, given by Barak et al.”:

m P and O(P) compute the same function.

m The growth of execution time and space of O(P) is at most polynomial in
regard to execution time and space of program P.

---

**Page 177**

Chapter 5 = Obfuscation

287

m For any polynomial time probabilistic algorithm A, there exists a polynomial
time probabilistic algorithm S and a negligible function m (a negligible
function is a function that grows much slower than the inverse of any
polynomial), such as the following: for all programs P,

| p[A(O(P))=1] - p[S?(1!"!)=1] | <m(| P|)

The virtual black box property expresses the fact that the outputs distribution of
any probabilistic analysis algorithm A applied to the obfuscated program O(P)
is almost everywhere equal to the outputs distribution of a simulator S making
oracle access to program P. (Program S does not have access to the description
of program P, but for any entry x, it is given access to P(x) in polynomial time in
regard to the size of P. An oracle access to program P is equivalent to an access
to sole inputs/outputs of the program P.)

Intuitively, the virtual black box property simply stipulates that everything
that can be calculated from the obfuscated version O(P) can also be calculated
via oracle access to P.

One of the main points about such an ideal obfuscator is that it does not exist.
The proof is based on the construction of a program that cannot be obfuscated.
This impossibility result demonstrates that a virtual black box generator—which
could protect the code of any program by preventing it from revealing more
information than is revealed by its inputs/outputs—does not exist. This impos-
sibility result naturally leads to important outcomes for designers of obfuscation
mechanisms (adapted to WBAC context).

Consider a practical application of obfuscation that consists of transforming
a symmetric encryption into an asymmetric encryption, by obfuscating the pri-
vate key encryption scheme. An unobfuscatable private key encryption scheme
does exist if a private key encryption scheme exists. This clearly indicates that
private key encryption schemes are not all well suited for obfuscation.

Note that this result does not prove that there is not some private key encryption
scheme such that we can give to the attacker a circuit calculating the encryption
algorithm without security loss. It does prove, however, that there is no general
method enabling the transformation of any private key encryption scheme into
a public key encryption system by obfuscating the encryption algorithm.

The problem of constructing a private key encryption scheme verifying the
virtual black box property (thus resilient in the WBAC context) remains of inter-
est for cryptography researchers, even if the impossibility result concerning
a generic way to manage it may seem discouraging. White box DES and AES
implementations proposals illustrate this interest.

Obfuscation by using a network of encoded lookup tables makes it possible
to obtain from DES and AES algorithm versions that are more resilient in the
white box attack context. However, effective cryptanalysis of DES (such as the
one done by Goubin”) and AES (by Billet?) white box implementations has

---

**Page 178**

288

Chapter 5 = Obfuscation

established that the problem of constructing a private key encryption scheme
verifying the virtual black box property remains unsolved.

The ideal model of an obfuscator able to transform any program into a virtual
black box cannot be implemented. In particular, there is no general transforma-
tion that enables, starting from an encryption algorithm and a key, obtaining an
obfuscated version of this algorithm that could be published without leaking
information about the key it contains.

However, this formalism does not establish that it is impossible to hide a key
in an algorithm in order to transform a private key algorithm into public key
encryption.

A method has been published (by Chow’) to make the extraction of the key
difficult in the white box context. The principle is to implement a specialized
version of the DES algorithm that embeds the key K, and which is able to do only
one of the two operations, encrypt or decrypt. This implementation is resilient
in a white box context because it is difficult to extract the key K by observing
the operations carried out by the program and because it is difficult to forge
the decryption function starting from the implementation of the encryption
function, and inversely.

The main idea is to express the algorithm as a sequence (or a network) of
lookup tables, and to obfuscate these tables by encoding their input/output. All
the operations of the block cipher, such as the addition modulo 2 of the round
key, are embedded in these lookup tables. These tables are randomized, in order
to obfuscate their functioning.

Obfuscation of AES (described by Chow") is done in a similar way as DES.
The goal is still to embed the round keys in algorithm code, in order to avoid
storing the key in static memory or loading it in dynamic memory at the time
of execution. The technique used to securely embed these keys is (as for DES) to
represent AES as a network of lookup tables, and to apply input/output encod-
ings in order to hide the keys.

Achieving Security by Obscurity

So far, you have seen a great number of obfuscation techniques. Most of them
are simple transformations that seem quite weak at first sight—and they are
actually weak considered individually. How one can build security or trust from
such primitives? The strength of an obfuscation system (or obfuscator) comes
from the iterative and combined applications of a set of these techniques. Each
successive application of a simple technique accrues into a strong indiscernible
global transformation (well, at least that is the objective). An interesting analogy
has been proposed by Jakubowski et al.”° between round-based cryptography
and iterated obfuscation. A cryptographic algorithm’s round is made of basic
arithmetic operations (addition, exclusive or, etc.) that perform trivial transfor-
mations on the inputs. Considered individually, a round is weak and prone to

---

**Page 179**

Chapter 5 = Obfuscation

289

multiple forms of attacks. Nevertheless, applying a set of rounds multiple times
can result in a somewhat secure algorithm. That is the objective of an obfuscator.
The objective of the attacker is to discern the rounds from the global obfuscated
form and to attack them at their weakest points.

Keep in mind that even if the obfuscator is not perfect, as soon as it raises the
bar required to break into the protected code by a sufficient amount, this may be
sufficient for the defender. For example, if a few weeks or months are required
to break into a new version of software, the defender can take advantage of
that period to work on new protections, protocol updates, and so on, and thus
always be ahead of the game.

A Survey of Deobfuscation Techniques

Now that you have a better understanding of code obfuscation, the question
is how can you, as a reverse engineer, take up the challenge? What means and
tools are at your disposal to break into obfuscated code? Manual analysis of
obfuscated code is a tedious, if not impossible, task; you'll want to boil down
the problem to clean code analysis.

Because a manual approach using standard program analysis tools is fas-
tidious, and considering the wide variety of obfuscation mechanisms that an
analyst may face, it is necessary to find some models and criteria to design and
evaluate deobfuscation algorithms. This section provides a brief overview of the
problem from a more theoretical perspective, and describes some well-studied
formal methods that can be used to design more generic deobfuscation tools
and automate as much as possible the tasks undertaken by an analyst.

The Nature of Deobfuscation: Transformation Inversion

In order to undo obfuscation transformation, several software analysis tech-
niques are available. This section covers the following:

m The notion of decidable approximation

m Some methods, either static or dynamic, that can be used, and advantages
that can be gained from hybrid static dynamic methods (some of them
are presented later through the use of specialized tools)

m Some criteria that can always been applied to evaluate an analysis algo-
rithm and from which it is possible to derive some security criteria about
obfuscation robustness (and in a dual way a deobfuscation transforma-
tion efficiency)

m Open problems and new trends concerning hybrid dynamic/static analysis
and formalization of deobfuscation

---

**Page 180**

290

Chapter 5 = Obfuscation

The subject is vast, and there is still no consensus about the terminology
for the various specialized areas of research in the literature. The goal of this
section is thus to provide readers with some keywords to enable a global view,
and some useful references for interested readers who want to supplement their
knowledge in this domain.

You can observe several dichotomies in the field of software analysis. Some
analysis techniques are described as static or dynamic, even if this distinction some-
times seems quite artificial. (This distinction is discussed by Yannis Smaragdakis
and Christoph Csallner**.) Otherwise, analysis algorithms are qualified as sound
or complete, but these important characteristics may have different meanings in
the literature. Finally, program analyses are described as over-approximation or
under-approximation, but this distinction also seems somewhat artificial because
some analysis methods appear to use both over- and under-approximation.

The remainder of this section discusses both the “synergy” and “duality” of
static and dynamic analysis (also discussed by Michael D. Ernst”), first intro-
ducing the formal model of abstract interpretation and then providing several
analysis examples in relation to deobfuscation.

Finding a Decidable Approximation of the Concrete Semantics

The purpose of any program analysis is to check whether the program satisfies
a certain property. Unfortunately, the question is generally undecidable for any
non-trivial property—that is to say, you cannot design an algorithm to determine
whether the property holds for the program. To overcome this difficulty, one
solution is to abstract the concrete behaviors of the program into a decidable
approximation. The purpose of abstract interpretation is to formalize this idea
of approximation in a unified framework. (Readers can refer to the paper by
Patrick Cousot and Radia Cousot."*)

The semantics of a program represent all of its possible concrete behavior,
including its interaction with any possible computer system environment.
Among the most precise (concrete) semantics are the so-called trace semantics.
This semantics includes all finite and infinite sequences of states and transi-
tions. Where X is the set of execution traces (finite and infinite), you can express
the trace semantics as the least solution (for the computational partial ordering)
of a fixpoint equation X=F(X).

An abstract domain is an abstraction of a concrete semantics. The goal of abstract
interpretation is to provide computable, fixpoint approximations of abstract
domains, thus defining computable abstract semantics. Obviously, the coarser
the abstract semantics, the fewer questions it can answer.

All abstractions of a semantics can be organized in a hierarchy (described by
Cousot'®), from the most precise to the coarsest. More precisely, abstract seman-
tics can be placed on a lattice, and the approximation partial ordering of this lattice

---

**Page 181**

Chapter 5 = Obfuscation

291

can be used to characterize the concreteness (or precision) of abstract semantics,
and thus the sets of questions they are able to answer.

Abstract interpretation generally applies to static analysis, through an over-
approximation of the concrete semantics. You might notice that, in a dual way
and according to the “dual principle” of lattice theory, it should also apply to
dynamic analysis, even if there are not currently many works on this subject.
You will see in the next section that relations and synergy between static and
dynamic analysis lead to practical hybrid dynamic/static methods, making
it possible both for a dynamic approach to gain in coverage and for a static
approach to gain in precision.

Dynamic and Static Analyses Form a Continuum

Static analysis is the discipline of automatically inferring information about com-
puter programs without running them (it thus applies to a “static” representation
of the program). Static analysis tries to derive properties (invariants) that hold
for all executions of the program, through a conservative over-approximation
of its concrete semantics.

An example of such static analysis is the constant propagation algorithm, which
aims to determine for each program instruction whether a variable has a constant
value whenever the control flow reaches that instruction. Information about
constants is useful in the context of program compilation, optimization, and
recompilation. It is used, for example, for dead code and dead execution path
deletion (by replacing all uses of constant variables by their constant values, you
may be able to identify constant conditional branches, which are conditioned
by constant predicates).

Among the many optimization techniques, partial evaluation techniques
(described by Beckman et al.°) must be kept in mind in the context of reverse
engineering. A partial evaluator specializes a program with regard to part of its
input data. You expect the program’s concrete semantics to be preserved by the
specialization process and the resulting program’s syntactic representation to
be optimized for the class of inputs used, and as a result simpler to understand.

Another important class of optimization techniques includes slicing tech-
niques (described by Weiser*’), which also aim to simplify the program under
consideration, but in this case by deleting those parts of the program that are
irrelevant according to a criterion provided by the analyst. A static slicing crite-
rion includes a set of variables and a chosen point of interest. A dynamic slicing
criterion completes a static criterion with the information corresponding to some
concrete execution. Slicing is of great interest in the reverse engineering context,
because it is representative of the way a reverser mentally slices a program when
attempting to understand its inner working.

---

**Page 182**

292

Chapter 5 = Obfuscation

In contrast to static analysis, dynamic analysis is the discipline of automatically
inferring information about a running computer program. Dynamic analysis
derives properties that hold for one or more executions of a program, through
a precise under-approximation.

A common method of dynamic analysis is dynamic testing, which executes a
program with several inputs and checks the program’s response. Generally, test
cases explore only a subset of the possible executions of the program.

In order to enlarge the coverage of dynamic testing, the principle of sym-
bolic execution (described by Boyer®) uses symbolic values rather than concrete
inputs. At any point during symbolic execution, a symbolic state of the program
is updated. This symbolic state consists of a symbolic store and a path constraint.
The symbolic store contains the symbolic values, and the path constraint is
a formula that records the history of all conditional branches taken until the
current instruction.

At a given instruction of the program, you can use a constraint solver (SMT or
SAT solver) to determine the corresponding path constraint. A satisfying assign-
ment provides concrete inputs with which the program reaches the program
instruction. By generating new tests and exploring new paths, you can increase
the coverage of dynamic testing.

Unfortunately, constraints generated during symbolic execution may be too
complex for the constraint solver. If the constraint solver is unable to compute a
satisfying assignment, you cannot determine whether a path is feasible or not.

Concolic execution (described by Godefroid”? and Sen*’) provides a solution to
this problem in many situations. The idea is to perform both symbolic execution
and concrete execution of a program. When the path constraint is too complex
for the constraint solver, you can use the concrete information to simplify the
constraint (typically by replacing some of the symbolic values with concrete
values). You can then expect to find a satisfying assignment of this simplified
constraint.

Because symbolic execution is unable to handle an unbounded loop, which
results in infinite symbolic execution paths, it must under-approximate the
concrete semantics of the program. You can perform this simplification by fix-
ing some arbitrary loop limit. Another solution is to use symbolic execution in
conjunction with a static analysis inferring loop invariants.

It appears that dynamic and static analysis approaches form a continuum. As
an illustration, dynamic testing, symbolic execution, and abstract interpretation
are three ways of approximating the concrete semantics of a program. Dynamic
analysis uses concrete values and explores a subset of concrete transitions.
Symbolic execution clearly lies between dynamic testing and static analysis.
It rests on a more abstract semantics, but also an under-approximation. An
abstract interpreter over-approximates the concrete semantics of the program.

---

**Page 183**

Chapter 5 = Obfuscation

293

However, the borderline between those analysis approaches is not so easy
to define. For example, symbolic execution can be defined as a logical abstract
interpreter, operating over the abstract domain of logical formulas.

In conclusion, many static analysis methods are improved by the use of a
dynamic analysis—based refinement. Conversely, the coverage of many dynamic
analysis methods can be increased by using traditional static analysis methods.
Thus, the investigation of hybrid dynamic/static approaches is of great interest,
especially in the context of reverse engineering. The soundness and complete-
ness criteria can be used to capture this synergy.

Soundness and Completeness

You can formulate any program analysis problem as verification that the pro-
gram Satisfies a property. Two fundamental concepts can be used to character-
ize an analysis algorithm: its soundness and its completeness. These concepts,
traditionally applied to logical systems, can also be applied to program analysis.
Unfortunately, because of their dual natures (soundness and completeness cor-
respond to converse implications in logic), there is still no consensus regarding
their application to the various specialized areas of research in the literature.

Given a property, a sound program analysis identifies all violations of the
property. However, because it over-approximates the behaviors of the program,
it may also report violations of the property that cannot occur. For example, a
sound error detection algorithm detects every possible error, though some of
them may not occur at run-time.

A sound partial evaluation algorithm preserves the original program’s con-
crete semantics, in the sense that the specialized program does not produce
any output value that is not produced by the original program (even if it may
not be able to produce all of them).

A sound symbolic execution guarantees that because a symbolic constraint
path is satisfiable, there must be a concrete execution path that reaches the cor-
responding concrete state (even if some reachable concrete state does not have
a corresponding symbolic state).

A sound abstract interpreter preserves the program’s concrete semantics. If it
claims that an optimization transformation is possible for a program, then the
optimization can be applied without breaking the program semantics. Observe,
however, that it may be unable to answer the question for some optimizations.
It can claim that an optimization is unsafe even if it is in fact possible to apply
the transformation (without any destructive effect). Some potential optimiza-
tions will not be applied. The soundness of the abstract interpreter is relative to
which questions it can answer correctly, despite the loss of information. In that
sense, it is conservative. Technically, the least fixpoints computed by an abstract
interpreter represent at least all occurring run-time concrete states.

---

**Page 184**

294

Chapter 5 = Obfuscation

For example, a constant propagation algorithm is sound when any constant
it detects is indeed a constant. However, some constants may be not detected.
Given a property, a complete analysis algorithm reports a violation of the prop-
erty only if there is a concrete violation of the property. However, because it
under-approximates the behaviors of the program, some concrete violations of
the property may not be reported.

A complete partial evaluation algorithm results in the generation of a spe-
cialized program that is able to produce the same output values as the original
program for the intended input values. If unsound, it may produce unexpected
output values (i.e., not produced by the original program).

A complete symbolic execution covers all concrete transitions. It guarantees
that if a concrete execution state is reachable, then there must be a corresponding
symbolic state. Because symbolic execution is unable to handle an unbounded
loop, which results in infinite symbolic execution paths, it must under-approximate
the concrete semantics of the program (typically by providing some loop limit).
Therefore, symbolic execution algorithms are most often incomplete.

A complete abstract interpreter is the most precise for answering a given set
of questions. Technically, this means that every state represented by the least
fixpoint is reachable for some concrete input. For example, a complete constant
propagation algorithm would be able to detect every constant in a program.

We have presented some criteria (soundness and completeness) that can
always be applied to evaluate an analysis algorithm. It is possible to derive from
them some security criteria about obfuscation robustness (and, in a dual way,
deobfuscation transformation efficiency).

Abstract interpretation can be used for modeling any program transformation
(refer to the paper by Patrick and Radia Cousot’). By considering the syntax
of a program as an abstraction of its concrete semantics, we can formalize any
syntactic program transformation as an abstract interpretation of the corre-
sponding semantic transformation.

A particular application of this concerns obfuscation and deobfuscation trans-
formations modeling. Mila Dalla Preda and Roberto Giacobazzi'* investigate
the semantic transformations corresponding to opaque predicate insertion.
By modeling deobfuscation as an abstraction interpretation, they observe that
breaking opaque predicates corresponds to having complete abstraction. The
completeness criterion turns out to be of special interest in terms of qualifying
both deobfuscator effectiveness and opaque predicate robustness.

In conclusion, many methods already used in program analysis and compila-
tion are of interest in the context of reverse engineering. As demonstrated earlier,
the frontier between static and dynamic analysis is not so obvious. Currently,
the abstract interpretation model seems to be sufficiently general to apply to
both types of analyses. The soundness and completeness criteria are of special
interest when modeling obfuscation and deobfuscation transformations in the

---

**Page 185**

Chapter 5 = Obfuscation

295

abstract interpretation framework. You have seen that both the soundness and
the completeness of an algorithm can be defined for static and dynamic analy-
ses (data flow analyses, partial evaluation, slicing, symbolic execution), which
are good candidates to represent the actions conducted by reversers when they
try to simplify the representation of an obfuscated program. Using the abstract
interpretation model, static and dynamic analyses appear to be dual in nature.
This duality and the gain that can be obtained from a synergy between static
and dynamic methods lead to new possibilities that must be investigated in the
future, through the study of hybrid methods.

This section presented some academic models and criteria, as well as dynamic
and static analysis methods, that can be useful for designing and evaluating
deobfuscation algorithms. It also stressed the importance of hybrid methods.
The next section presents some of the tools currently available to assist in undo-
ing obfuscation transformations.

Deobfuscation Tools

In this section we discuss some of the tools that you can use to reverse engineer
obfuscated code and especially the features they offer to ease your job. Please
note that this list is not meant to be exhaustive in any way; it is based on the
experience of some of the authors and seeks to present different categories of tools.

IDA

IDA is the state-of-the-art tool for reverse engineering binary code. Throwing
the binary one wants to analyze into IDA is a common reflex, so there’s prob-
ably no need to introduce this tool here; otherwise, readers can refer to the The
IDA Pro Book by Chris Eagle (No Starch Press, 2011). Regarding the specific topic
that interests us here, dealing with obfuscated code using IDA is problematic
(although not impossible) for a few reasons:

m That’s not the purpose for which IDA is primarily intended. Obfuscated
code is a very particular case, and handling every specific situation/trick
would be an endless job; thus it’s better not to start on this path.

m We have very little control over the disassembler, a point that greatly
impedes us when encountering obfuscation schemes that break/disrupt/
destroy the control-flow graph. IDA’s disassembler is really easy to confuse
and one often ends up with the chicken-and-egg problem: To recover the
control flow one needs to clean the data flow, but to clean the data flow
one needs the control flow.

m IDA itself doesn’t offer any sort of intermediate representation (IR) or at
least instruction semantics, so advanced analysis of its output is not trivial.

---

**Page 186**

296

Chapter 5 = Obfuscation

In 2008 at the ICAR workshop (http: //www.hex-rays.com/ products/ida/
support /ppt/caro_obfuscation.ppt), Ilfak Guilfanov offered some useful tips
on how to use specific features of IDA:

m Graph-level block merging to simplify the CFG

m Event-driven, on-the-fly modification of the graph using hooks like grcode_
changed_graph (see graph. hpp in the SDK)

m Develop specific plugins

IDA can be extended using scripts (either IDc or IDAPython) or plugins (see
IDA‘s SDK). If you were to implement some advanced analysis, that’s where you
would be able to interact.

To that end, some plugins have been developed as deobfuscation frame-
works (for example, Branko Spasojevic’s Optimice plugin, http: //optimice.
googlecode.com). Trying to address some of the issues previously mentioned,
including instruction semantics—based on the x86 Opcode and Instruction
Reference (http: //ref .x86asm.net /)—the plugin offers CFG reduction, peep-
hole optimizations, and dead code removal.

Metasm

Metasm (http: //metasm.cr0.org) is open source framework (released under
the GNU Lesser GPL v2) developed by Yoann Guillot. It defines itself as an
assembly manipulation suite. The framework, written in Ruby, actually offers
cross-architecture assembler, disassembler, compiler, linker, and debugger fea-
tures. Currently supported processors are Intel x86/x64, MIPS, PPC, Sh4, and
ARCompact. Most common file formats are supported as well, such as MZ, PE/
COFF, ELF, Mach-O, and so on.

Disassembler Callbacks

The behavior of the disassemblery can be dynamically modified using a set of
exported callbacks of the Disassembler class. The two most useful for deob-
fuscation are as follows:

™ callback_newaddr—This is called each time a path is discovered and is
about to be disassembled. At this point you can inspect the path back-
ward or forward for unseemliness; most important, you can modify the
behavior of the disassembly engine—removing a spurious control transfer,
thwarting a disassembler trap, etc.

™ callback_newinstr—As its name suggests, your callback is called each
time a new instruction is disassembled.

---

**Page 187**

Chapter 5 = Obfuscation

297

Instruction Semantics

One of the framework’s key features is backtracking (think of it as program
slicing). This feature is at the heart of its disassembly engine. It enables very
precise control flow recovery, at the cost of performance. Built on top of this
feature, the framework’s API also offers a method to compute the semantics
of a basic block. Metasm does not use a strict intermediate language, however;
it relies on a description of the semantics of each instruction. The associated
terminology in the framework is binding. Metasm separates control flow and
data flow semantics encoding. Four types are used to describe the semantics
of an instruction:

m Numerical value
m™ =Symbol—Whatever is not a numerical value, based on Ruby’s symbol type

m Expression: Expression[operandl, (operator), (operand2)]—An
operand can be any of the four types.

= Indirection—Memory indirection Indirection[target, size, origin]

The following snippet will introduce you to the Metasm instructions’ binding:

# encoding: ASCII-8BIT
#!/usr/bin/env ruby
require "metasm"
include Metasm

# produce x86 code

sc = Metasm: :Shellcode.assemble (Metasm::Ia32.new, <<EOS)
add eax, 0x1234

mov [eax], 0x1234

ret

EOS

dasm = sc.init disassembler

# disassemble handler code
dasm.disassemble (0)

# get decoded instruction at address 0
# then its basic block
bb = dasm.di_at(0) .block

# display disassembled code
puts "\n[+] generated code:"
puts bb.list

# run though the basic block's list of decoded instruction
bb.list.each{ | di|

puts "\n[+] #{di.instruction}"

sem = di.backtrace_binding()

---

**Page 188**

298 Chapter 5 = Obfuscation

puts " data flow:"
sem.each{|key, value| puts * #{key} => #{value}"}

# does instruction modify the instruction pointer ?
if di.opcode.props[:setip]

puts " control flow:"

# then display control flow semantics

puts " * #{dasm.get_xrefs_x(di) }"
end

}

For each DecodedInstruction, you call the backtrace_binding method.
It returns a hash. Each key/value pair represents an assignment of the key
according to the value and expresses outputs with respect to inputs. Running
the scripts produces the following result:

[+] generated code:
0 add eax, 1234h
5 mov dword ptr [eax], 1234h
Obh ret ; endsub entrypoint_0

[+] add eax, 1234h
data flow:

* eax => eaxt+1234h

* eflag z => ((eax+1234h) &OffELLLE Lh) ==

* eflag_s => (eax+1234h) >>1f£h) &1) !=0
eax&OffffLFLLfLFh) +1234h) >OffLLLLFLFh
(eax>>1f£h) &1) ==0) &&( ( ( (eax>>1fh) &1) !=0) !=
((eax+1234h) >>1f£h) &1) !=0) )

* eflag_c =>
* eflag_o =>

((
((
((
((

[+] mov dword ptr [eax], 1234h
data flow:
* dword ptr [eax] => 4660

[+] ret
data flow:
* esp => esp+4+0
control flow:

* [Indirection[Expression[:esp], 4, Oxb]]

The RET instruction is quite representative of the distinction between data
flow and control flow. The get_xrefs_x method provided by the disassembler
object returns a list (a Ruby Array object) of possible values for the instruction
pointer. For that specific instruction, it is an indirection whose target is the ESP
register and whose size is 4 (for the [a32 architecture)—i.e., dword ptr [ESP] ;
Oxb is the address in the program where the indirection occurs.

Backtracking and Slicing

So far, you have seen how the semantics are described for each isolated instruc-
tion. Now consider instructions within a control flow and how an instruction’s

---

**Page 189**

Chapter 5 = Obfuscation

299

binding can be used. For this purpose, the following example demonstrates a
typical dynamic jump computation pattern:

# encoding: ASCII-8BIT
#!/usr/bin/env ruby
require "metasm"
include Metasm

# produce handler's x86 code
sc = Metasm: :Shellcode.assemble (Metasm::Ia32.new, <<EOS)
entry:

mov ecx, 1

shl ecx, OxA

add edx, OxBADCOFFE

mov eax, 0x100000

lea eax, [ecx+eax]

add ecx, OxBADCOFFE

jmp eax
EOS

# disassemble handler code
dasm = sc.init_disassembler
dasm. disassemble (0)

# get basic block

bb = dasm.block_at (0)

target = dasm.get_xrefs x(bb.list.last) .first
puts "[+] jmp target: #{target}"

# backtrace
values = dasm.backtrace(target, bb.list.last.address,
{:log => bt_log = [], :include_start => true})

get_xrefs_x tells you which target is the final jump instruction. Then the
backtrace method is used to walk back through the control flow, following
variable dependencies, until it reaches variable assignations or simply hits its
complexity limit. Each step of the backtracker is stored within the array bt_log.
The following adds a few more lines to nicely output the record:

bt_log.each{|entry|
case type = entry.first
when :start
entry, expr, addr = entry
puts "[start] backtacking expr #{expr} from Ox#{addr.to_s(16) }"

when :di
entry, to, from, instr = entry
puts "[update] instr #{instr},\n -> update expr from #{from} to
#{to}\n"

when :found
entry, final = entry

---

**Page 190**

300

Chapter 5 = Obfuscation

puts "[found] possible value: #{final.first}\n"

when :up

entry, to, from, addr_down, addr_up = entry

puts "[up] addr Ox#{addr_down.to_s(16)} -> Ox#{addr_up.to_s(16) }"
end

}
Here is the output from the sample:

[+] jmp target: eax
[start] backtacking expr eax from Oxlc
[update] instr 13h lea eax, [ecx+eax],

-> update expr from eax to ecx+eax
[update] instr Oeh mov eax, 100000h,

-> update expr from ecx+eax to ecx+100000h
[update] instr 5 shl ecx, Oah,

-> update expr from ecx+100000h to (ecx<<0ah)+100000h
[update] instr 0 mov ecx, 1,

-> update expr from (ecx<<0Oah)+100000h to 100400h
[found] possible value: 100400h

The backtracking engine has been able to walk back the instruction flow to
compute the final value of the backtracked expression. A simplification engine
enables solving (or at least reducing) expressions at both the symbolic and
numerical levels.

From the log record it is even possible to extract a slice—that is, the minimal
subset of the original program that produces the studied effect (the slicing
criterion). In this case the slice will contain all the instructions involved in the
computation of the ump destination:

# DecodedInstruction object is the 3rd item of :id entry

slice = bt_log.select{|e| e.first==:di}.map{|e| e[3]}.reverse
puts slice

The slice is as follows:

O mov ecx, 1

5 shl ecx, Oah

Oeh mov eax, 100000h
13h lea eax, [ecx+eax]

Note how nonsignificant computations/assignations (e.g., the ones using the
constant 0BADCOFFEh) have been eliminated from this list.

That sample is an ideal case: The expression can statically be reduced/solved
into a numerical value. Now, imagine you remove the first assembly line (Mov Ecx,
1)—within the basic block scope Ecx is undefined—and then redo the analysis:

[+] jmp target: eax

[start] backtacking expr eax from 0x17

{update] instr Oeh lea eax, [ecx+eax],
-> update expr from eax to ecx+eax

---

**Page 191**

Chapter 5 = Obfuscation

301

[update] instr 9 mov eax, 100000h,
-> update expr from ecx+eax to ecx+100000h
fupdate] instr 0 shl ecx, Oah,

-> update expr from ecx+100000h to (ecx<<0ah) +100000h

The return value is an object of type Expression whose value is

(ECX<<0Ah) +100000h.

This example is fairly trivial. The capacity of the backtracker goes far beyond
that. The following modifies the preceding sample to include a more complex

control-flow graph:

# produce handler's x86 code
sc = Metasm: :Shellcode.assemble (Metasm: :I1a32.new,
entry:
mov ecx, 1
test edx, edx
jnz label inc cl
label:
shl ecx, OxA
add edx, OxBADCOFFE
mov eax, O0x100000

lea eax, [ecx+eax]
add ecx, OxBADCOFFE
jmp eax

EOS
# disassemble handler code
dasm = sc.init_disassembler

dasm. disassemble (0)

# get last basic block

<<EOS)

bblist = dasm.instructionblocks.sort{|bl, b2| bl.address <=> b2.address}

bblist.each{|bb| puts "-\n", bb.list}
bb = bblist.last

Basically, this has inserted an instruction (TEST EDX, EDX) controlling a con-
ditional jump; in one case ECx is incremented, in the other it is not. The updated

output is as follows:

[+] jmp target: eax
[start] backtacking expr eax from 0x21
[update] instr 18h lea eax, [ecx+eax],

-> update expr from eax to ecx+eax
[update] instr 13h mov eax, 100000h,

-> update expr from ecx+eax to ecx+100000h

[update] instr Oah shl ecx, Oah,

-> update expr from ecx+100000h to (ecx<<0ah)+100000h

[up] addr Oxa -> 0x9
[up] addr Oxa -> 0x7
[update] instr 0 mov ecx, 1,

-> update expr from (ecx<<0ah)+100000h to 100400h

[found] possible value: 100400h

---

**Page 192**

302

Chapter 5 = Obfuscation

[update] instr 9 inc ecx,
-> update expr from (ecx<<0ah)+100000h to ((ecx+1)<<0ah)+100000h
[up] addr 0x9 -> Ox7
[update] instr 0 mov ecx, 1,
-> update expr from ((ecx+1)<<0ah)+100000h to 100800h
[found] possible value: 100800h

The backtracker returns an array of two possible values: 100400h or 100800h.
Note how it has followed the control flow over the CFG. (Both branches of the
conditional have been followed.) An [up] tag indicates a basic block’s crossing.
Backtracking really is at the heart of the disassembler and produces a more
accurate disassembly. Obviously, this feature comes with severe performance
penalties (remember the trade-off between computability and precision).

Code Binding

You know how to obtain the semantics of an isolated instruction, and you know
how to backtrack a value and compute a slice for that particular value. What if
you could generalize this process and compute the semantics of a basic block?
This is another very powerful feature of Metasm: the code_binding method,
provided by the disassembler object. It totally relies on the backtracking feature.
Here is its usage on the last basic block of the previous example:

# compute basic block's semantics

bbsem = dasm.code binding(bb.list.first.address, bb.list.last.address)

puts "\n[+] basic block semantics"
bbsem.each{|key, value| puts " * #{key} => #{value}"}

Its output is as follows:

[+] basic block semantics
* eax => ((ecx<<0ah) +100000h)
* ecx => ((ecx<<0ah) +badcOffeh)
* edx => (edx+badc0ffeh)

Miasm

Miasm (http: //code.google.com/p/smiasm) is a reverse engineering framework
developed by Fabrice Desclaux that offers PE/ELF manipulation, assembling,
and disassembling (currently supports Ia32, ARM, PPC, and Java bytecode).
Like Metasm, Miasm is open source and released under the GNU Lesser GPL
v2, so you can delve into its engine to customize specific needs. The examples
provided in this section are based on the latest revision of MIASM available at
the time of writing (changeset : 270: 6ee8e9a58648).

The framework relies on an intermediate language. That means most com-
mon instructions have their semantics encoded as a list of expressions. “List”
is to be understood in its Python meaning (i.e., an ordered set of objects).

---

**Page 193**

Chapter 5 = Obfuscation

303

The grammar of Miasm’s IR makes use of nine basic expression types, the most
important of which are as follows:

ExpriInt—Numerical value

Exprid—lIdentifier /symbol, whatever is not a numerical value; for example,
registers are defined as Exprid

Expraff—Affectation a = b
ExprCond—Ternary/conditional operator a ? b : c
ExprMem—Memory indirection

ExprOp—Operation op (a,b,...)

It also provides full support for slices (think of it as an object to represent
bitfields) and slice composition. The IR allows symbolic computations and is
equipped with an expression simplification engine.

For each supported processor, a “sem” suffixed file describes the semantics
of most common instructions. See, for example, the ADD semantics as defined

in “miasm/arch/ia32 sem.py”:

def add(info, a, b):

e= []

c = ExprOp('+', a, b)
e+=update flag arith(c)
e+=update_ flag af (c)
e+=update flag add(a, b, c)
e.append(ExprAff(a, c))
return e

This function builds the semantics of the instructions based on its two operands
(a and b). One can easily write a piece of script to demonstrate these features:

# !

/usr/bin/env python

from miasm.arch.ia32_ arch import *

from miasm.tools.emul_helper import *

# assemble instruction asm at given address

def instr_sem(instr, address) :

2

print "\n[+] instruction %s @ 0x%x" % (instr, address)
binary = x86 _mn.asm(instr)

di = x86 _mn.dis (binary [0] )

semantics = get_instr_expr(di, address)

for expr in semantics:

2

print "  %s" % expr

---

**Page 194**

304

Chapter 5 = Obfuscation

instr _sem("add eax, 0x1234", 0)
instr _sem("mov [eax], 0x1234", 0)
instr _sem("ret", 0)

instr _sem("je 0x1000", 0)

Here is the output:

[+] instruction add eax, 0x1234 @ 0x0

z— = ((eax + 0x1234) == 0x0)
nf = ((0x1 == ((eax + 0x1234) >> Ox1F)) & Ox1)
pf = (parity (eax + 0x1234)) af = (((eax + 0x1234) & 0x10) == 0x10)
cf = ((0x1 == (((eax * 0x1234) * (eax + 0x1234)) >> Ox1F)) *
(Oxl == ((((eax + 0x1234)) & (! (eax * 0x1234))) >> Ox1F)))
of = (0x1 == (((eax * (eax + 0x1234)) & (! (eax * 0x1234))) >> Ox1F))
eax = (eax + 0X1234)
[+] instruction mov [eax], 0x1234 @ 0x0
@32 [eax] = 0x1234

[+] instruction ret @ 0x0
esp = (esp + (0x4 + 0x0) )
eip = @32 [esp]

[+] instruction je 0x1000 @ 0x0
eip = (zf == 0x1) ?(0x1000,0)

The app instruction’s semantics seem the most complex, due to the flags
update. Here is the Mov instruction’s semantics with an explicit typing of object:

[+] instruction mov [eax], 0x1234 @ 0x0
ExprAff( ExprMem(@32 [Exprid(eax)]) = ExpriInt (0x1234) )

This is a very appreciable and powerful feature. Built upon the IR, there is a
just-in-time (JIT) compilation feature whereby code is first disassembled, trans-
lated into IR, then regenerated as native code for execution. The documentation
and samples provide use cases of Miasm for packer/VM analysis as well as
binary instrumentation.

VxStripper

VxStripper is a binary rewriting tool, developed by Sébastien Josse. Designed
for analysis of protected and potentially hostile binary programs, it dynami-
cally extracts an intermediate representation of a binary executable and all the
necessary information to apply certain simplifications, making the binary inner
workings easier to understand for the analyst.

One of the main motivations behind the design and implementation options
of this tool is to circumvent current limitations of existing malware and binary
programs analysis solutions. (Many tools come with their own intermediate
representation—non-exportable, sometimes proprietary—making difficult
their integration. Moreover, many of them are not suitable for analysis of hos-
tile or protected code.) The goal is to get as much information as possible from

---

**Page 195**

Chapter 5 = Obfuscation

305

a binary program that uses all available techniques and tools to protect this
information. The idea is to instrument a virtual computer processing unit and
a guest operating system in a non-intrusive way to dynamically get informa-
tion required to rebuild the program and simplify its representation. This tool
is based on the dynamic binary translator engine of QEMU and on the LLVM
compilation chain.

LLVM (Low Level Virtual Machine) is a compilation chain that comes with
a consequent set of optimizations that can be applied across the entire lifetime
of a program. LLVM uses a strongly typed RISC-like instruction set and a static
single assignment (SSA) representation (using this representation, each temporary
variable is assigned only once). LLVM includes many binary back-ends (x86,
x86-64, SPARC, PowerPC, ARM, MIPS, CellSPU, XCore, MSP430, MicroBlaze,
PTX) and some source code back-ends (C, C++). Readers can refer to the paper
by Lattner*! for further details about LLVM.

The QEMU (Quick EMUlator) Dynamic Binary Translator (DBT) is used to
dynamically translate the binary code from the guest CPU architecture to the host
CPU architecture, through the use of an IR called TCG (Tiny Code Generator).
This language consists of simple RISC-like instructions called micro-operations.
The binary translation consists of two stages. The guest binary code is first
translated in sequences of TCG instructions, called translation blocks (DBT front
end). Then, the translation blocks are converted into code executable by the host
CPU (DBT back end). QEMU’s DBT comes with many binary front ends (x86,
x86-64, ARM, ETRAX CRIS, MIPS, Micro Blaze, PowerPC, SH4, and SPARC).
Readers can refer to the paper from Bellard* for further details about QEMU.

VxStripper inherits from QEMU the many binary front ends, and from LLVM
the many back ends, providing at reasonable cost a complete binary rewriting
framework. The rewriting functions are implemented as LLVM passes.

Its current design builds upon work already done to convert TCG IR to LLVM
IR (LLVM-QEMU, described by Scheller*®, and S2E, described by Chipounov’),
as well as upon design algorithms presented by Josse.*” 78

One of the goals of this tool is collaboration with the many software analysis
tools based on the LLVM compilation chain, through an “exported” representa-
tion of the malware program. This binary analysis tool is especially designed
to solve the problem of hostile programs analysis. The goal is to automate the
often fastidious and repetitive tasks driven by an analyst.

This compilation chain is based on a modular and evolutionary architecture,
making it possible to apply the same transformations to a wide variety of soft-
ware and hardware architectures. It is based on a modern compilation chain,
providing efficient intermediate representation and functionalities.

Vellvm (Verified LLVM), described by Zhao,*? provides formal tools to reason
on transformations that operate on LLVM’s intermediate representation. Vellvm
can be used to extract formally verified implementations of deobfuscation passes
implemented in VxStripper.

---

**Page 196**

306

Chapter 5 = Obfuscation

QEMU DBT Extension

You have seen that the QEMU DBT engine performs the dynamic translation
of the binary code from the guest processor architecture to the host processor
architecture by using the TCG intermediate representation.

Using a simple example, the following instruction demonstrates what this
language looks like:

0x0040104c: push Oxa

The preceding instruction is translated as follows in the QEMU TCG
representation:

(1) movi_i32 tmp0,$0xa

(2) mov_i32 tmp2,esp

(3) movi_1i32 tmp13,SOxfffffffic
(4) add_i32 tmp2,tmp2,tmp13
(5) gemu_st32 tmp0,tmp2,$0x1
(6) mov_i32 esp,tmp2

(7) movi_i32 tmp4,$0x40104e
(8) st_1i32 tmp4,env,$0x30

(9) exit_tb $0x0

This TCG instructions block emulates the execution of the push instruction
on the software CPU. The performed operations are as follows: The integer oxa
is stored in the variable tmpo (line 1). This variable is then stored on the stack
(lines 2-6). The address of the instruction following the current instruction is
stored in tmp4 (line 7) and then stored in the QEMU VPU register cc_op. The
last instruction (line 9) indicates the end of the TCG block.

The tool modifies the DBT mechanism in such a way that the instrumentation
function of the virtual CPU is systematically invoked before the execution of a
translation block. To achieve this, you add an extra micro operation (op_callback)
that takes as operand the address of the instrumentation function (vpu_callback).

The resulting TCG code is as follows:

BH

) op callback @vpu_callback

Nb

movi_i32 tmp0,S$0Oxa

mov_i32 tmp2,esp

movi_i32 tmp13,S0xfffffffic
add_i32 tmp2,tmp2,tmp13

nN of W

gqemu_st32 tmp0O,tmp2,$0x1

movi_i32 tmp4,$0x40104e
st_i32 tmp4,env,$0x30
) exit_tb $0x0

8
9

(
(
(
(
(
(
(
(
(
(1

)
)
)
)
7) mov_i32 esp, tmp2
)
)
0)

This mechanism enables you to execute your instrumentation code at each
execution cycle of the virtual CPU. With access to VPU registers and to the
virtual PC memory, you can acquire a process context and extract information
about its interactions with the guest operating system.

---

**Page 197**

Chapter 5 = Obfuscation

307

By also instrumenting the load and storing TCG instructions, you can extract
information about the interactions of the target process with the memory of
the guest system. Thanks to this information, you can recover the relocation
information of the process.

Now that you have seen how to modify the QEMU virtual CPU to enable
the systematic invocation of your instrumentation function, let’s examine the
translation of TCG intermediate representation to LLVM representation. The
result of translating the preceding TCG block is as follows:

) Sesp_v.i = load i32* @esp ptr

) Stmp2_v.i = add i32 tesp_v.i, -4

) %4 = inttoptr 132 Stmp2_v.i to i32*
) store i32 10, i32* %4

) store 132 Stmp2_v.i, 132* @esp ptr
) store i132 4198478, i32* Snext.i

) store i132 0, 132* Sret.i

(
(
(
(
(
(
(

NNO U FPF WN HB

The integer 0xa is stored at the address pointed to by the variable <4, which
is equivalent to storing it on the stack (lines 1—4). The address of the instruction
following the current instruction is stored in the variable snext . i (line 6). The
last instruction (line 7) finishes the LLVM block.

After the normalization process, this LLVM block is compiled to the follow-
ing assembly code:

401269! mov dword ptr [esp-14h], Oah
Now that you have an overview of the main modifications applied to the

QEMU emulator, as shown schematically in Figure 5-2, the following section
describes the general architecture of the tool.

VPU
Instrumentation
code
TargetCPU HostCPU
instructions TCG IL instructions
op_callback —J
Guest VPUISA | Gen Dyngen \| Host CPU ISA Gen
Inter. code func.
Binary Rewriting

SSA IL (LLVM) Deobfuscation

Decompilation

D
Vv

Figure 5-2

---

**Page 198**

308

Chapter 5 = Obfuscation

Architecture of VxStripper

VxStripper implements an extended DBT engine and several specialized analy-
sis functions (see Figure 5-3) to observe the target program and its execution
environment.

VPU State Transl.Block
ee VPU TCG IL VPU |__»
— Front-End LLVM IL Back-End
VPU API

VPU callbacks and shell commands

Guest OS Symbol
Provider

Unpacking
Module

External
Analysis
Tool

Normalization
Module

Guest OS <
API Hooking Description
Module

A module manager handles activation and collaboration between these analysis
functions, implemented as plugins.

These analysis functions extract semantic information from the target pro-
gram. This information can be the trace of its interactions with APIs of the
guest operating system, or the way it handles objects and structures of the guest
operating system’s executive or kernel, or more simply its machine code trace.

The extraction of this information rests on a description of the guest operat-
ing system, which can be provided, for example, by a symbol server, as is the
case for the family of Windows operating systems.

Among the modules already implemented, you notably find the following:

m An API hooking module

m A forensics analysis module

—c
-<
;

Figure 5-3

m An unpacking module

m A normalization module

---

**Page 199**

Chapter 5 = Obfuscation

309

API Hooking

The native and Windows API hooking module of VxStripper is based on forensic
analysis of the guest operating system’s memory, without any interaction with
the guest operating system.

The Windows executive maintains a set of structures that contains information
about the loaded modules for a given process inside its memory space. These
data structures can be recovered by using the process environment block (PEB),
which can itself be accessed as an offset of segment register FS. The native and
Windows API hooking modules of VxStripper use this information to locate
and instrument Windows API.

Forensics/Root-Kit Analysis

The forensics module of VxStripper comes with additional features to monitor
and check the integrity of many locations within the guest platform where a
hook can be installed. It walks through executive structures of the operating
system in order to identify potential targets of a root-kit attack and monitor
hardware components that could be corrupted by a root-kit. This information
is crucial for the analyst to understand low-level viral attacks.

For the purposes of this chapter, you can consider these features to be similar
to those expected from a kernel debugger. You can attach a process, view its CPU
state and disassembled code, and trace the interaction of the target program
with the operating system API. This inspection is done in a safe and controlled
environment, without any intrusive interaction with the guest operating system.

The following two sections take a closer look at the working of Vxstripper’s
two most important analysis modules: the unpacking module and the normal-
ization module.

Unpacking Module

The unpacking module locates the original entry point (OEP) of the target execut-
able, gets information relative to its interactions with the operating system API,
and extracts the relocation information.

The underlying idea is a simple integrity check of the target program’s execut-
able code: For each translation block of the program, a comparison between its
value in virtual memory and its value on the host file system is made. As long
as the values are identical, nothing is done. As soon as a difference is identi-
fied, the current translation block is written into the raw file in place of the old
translation block. The first instruction of the newly generated translation block
is identified as the OEP of the protected program. At the end of the analysis,
data sections are written into the raw file in place of original data sections.

The same monitoring algorithm is applied for each translation block. The
protection loader of the packed executable can have several deciphering layers.
As soon as the last deciphered translation block has been reached, the only thing

---

**Page 200**

310

Chapter 5 = Obfuscation

to be done is to repair the target executable. In order to recover the PE (Portable
Executable) structure of an unprotected executable, several tasks have to be car-
ried out: Set the original entry point, rebuild the imports and relocations tables,
and consistency check the PE header.

The method used by the unpacking engine in order to reconstruct the Import
Address Table (IAT) and relocations is based on Win32 and native API hooking.
During the unpacking process, all API calls are traced. A sorted table of API
calls is initialized at load-time, by walking NT executive structures.

Next, after process execution has resumed, each API call is traced. This table
is updated regularly during the target process execution, and is used to dynami-
cally resolve API function names. Finally, after a dump of the target process
memory space is completed, this table is used to fix the IAT in the PE executable.

Thanks to the load and store TCG instructions instrumentation, you can
dynamically extract the program’s relocation information, which can also be
added to a new section of the executable.

For example, here is the (useful) information extracted during the unpacking
stage of a program that displays a dialog box (function MessageBoxaA):

[INFO] eip=0x00401000

[RELOC] value=0x00403000 va=0x00401003

[RELOC] value=0x0040300f va=0x00401008

[RELOC] value=0x00402008 va=0x00401010

[APICALL] api_pc=0x77d8050b api_oep=0x77d8050b
dll_name=C: \WINDOWS\system32\user32.d1l1l
func_name=MessageBoxA
value=0x00402008 va=0x00401010

The relocation information consists of pairs (va, value), providing the vir-
tual address and the value to relocate, respectively. Note that for this packer,
the prologue of the function MessageBoxa is not emulated by the protection.
Otherwise, the external address that is effectively called (api_pc) is different
from the entry point of the API function (api_oep).

Normalization

In most cases, after the unpacking stage, you are able to get (automatically) a binary
stripped of its protection loader and without any rewritable code. Unfortunately,
some obfuscation mechanisms (control-flow flattening, VM-based obfuscation
transformations, etc.) have to be handled now in order to fully understand the
inner workings of a malware.

A first attempt to provide a solution to these problems has been implemented
in VxStripper, through the use of the LLVM intermediate representation. Rather
than try to work on the binary after its memory image has been dumped, the
idea is to work on its intermediate representation and increase the amount of
information (that has been dynamically collected) by embedding it in the LLVM
module. Such a representation is more suitable for further analysis.

---

**Page 201**

Chapter 5 = Obfuscation

311

The normalization module uses the output of previous analyses to generate
the LLVM representation of translation blocks, to which several optimization
transformations are applied. Examining this in more detail, during the execu-
tion of the target program, the LLVM back end of QEMU TCG outputs the
LLVM representation of translated blocks. This LLVM code is linked with an
initialization LLVM module (see Figure 5-4).

INITIALIZATION MODULE
- System API CLANG _

- Virtual CPU and Stack INIT Module
- Load and Store Callbacks MAIN
>| INIT Code
VIRTUAL GPU TCGtoLLVM | LLVM Module Pass _

\

rN id

(QEMU)

_| IMPORTS
| INFORMATION

,| LOAD/STORE
- MAP

Figure 5-4

This initialization module implements load and store callbacks, declares
system API prototypes, and sets a virtual processor unit and its stack.

The normalization module uses the information dynamically collected during
target program execution to resolve imports, process relocations, and retrieve
data sections. Import table information is used to build LLVM API call instruc-
tions. The load/store memory map is used to apply relocations and inject data
from the target program into the LLVM module.

When the LLVM module is rebuilt, some additional optimization passes are
applied to its representation. The LLVM can next be compiled to the chosen
architecture, by using one of available LLVM back ends. It can also be translated
to C or C++ code.

First results show that standard optimization used in conjunction with the
partial evaluation induced by the dynamic translation of target code to its
LLVM representation are sufficient to drastically reduce and simplify the code
under analysis.

---

**Page 202**

312

Chapter 5 = Obfuscation

Final Thoughts

This section has discussed only four tools (and with a bias toward static analy-
sis). Alongside the Metasm and Miasm frameworks, we could have cited the
Radare framework (http://www. radare.org/y/), for example. Rolf Rolles’s
efforts to extend IDA with his idaocaml interpreter (https: //code.google.
com/p/idaocaml1/) merit attention as well. There are plenty of others that we
did not mention or only briefly mentioned here, and we encourage you to try
them for yourself.

To put these tools into perspective, although IDA is a good disassembler, it
cannot help much when it comes to dealing with obfuscated code. The Metasm
and Miasm frameworks go a step further, offering more control, an IR to play
with, and so on. Tools such as VxStripper go even further. You can probably
feel it—there is an arms race going on. A huge amount of effort is put into the
development of obfuscators, so our tools have to evolve as well.

As a reverse engineer, developing tools is an investment you make in order to
fulfill your objectives; and you expect some sort of return on investment from
it. Most advanced tools can take weeks if not months to build and require a lot
of knowledge.

Practical Deobfuscation

Now you will see how some of the tools presented earlier can be used for
practical deobfuscation. Again, there is no ambition of exhaustiveness in the
following sections. Instead, the goal is to illustrate some common use cases of
deobfuscation techniques.

Pattern-Based Deobfuscation

This may be the simplest and cheapest deobfuscation, operating at the syntactical
level and matching known patterns. Don’t forget that early obfuscation patterns
were mainly manually crafted and protected code (like some packer code) and
exhibited only a limited set of patterns; listing them all was thus “acceptable.”
This deobfuscation technique comes down to a search and replace algorithm
at the binary (opcode) level (eventually using wildcard searching). The main
drawback is that it leaves you with a binary plagued with NOP instructions.
To illustrate this, take a look at the following old OllyDbg script. Packers are a
classic example of software using obfuscation techniques (in that case to protect
their stubs). For years OllyDbg has been (and probably still is) the favorite tool for
unpacking, and many scripts were released to assist in that task. This (random)
old script (2004, by loveboom, http: //tuts4you.com/download.php?view.601)
targets ASProtect 2.0x versions (a commonly used packer at that time). It takes

---

**Page 203**

Chapter 5 = Obfuscation

313

advantage of the OllyScript’s REPL commands to search and replace a set of
patterns. A REPL definition is as follows:

repl addr, find, repl, len
Replace find with repl starting att addr for len bytes.

All patterns are based on the same technique : an unconditional jump inside
its successor instruction is used to confuse disassemblers. The diversity is slightly
improved using instruction prefixes (like REP or REPNE). The rep1 instruction is
used to replace these patterns with Nops:

repl eip, #2EEB01??#,#90909090#, 1000

repl eip, #65EB01??#,#90909090#, 1000

repl eip, #F2EB01??#, #90909090#, 1000

repl eip, #F3EB01??#, #90909090#, 1000

repl eip, #EB01??#,#909090#, 1000

repl eip, #26EB02????#, #9090909090#, 1000

repl eip, #3EEB02????#, #9090909090#, 1000

Here we only operate at the syntactic level. Considering a target with a lim-
ited set of patterns, this deobfuscation technique is trivial, however efficient:

m Application cost is limited if not negligible.

m Development cost is also almost null.

Of course, as with virus signatures and AV engines, polymorphism and
diversity make it useless. An equivalent script could have been developed using
IDA’s scripting capabilities. That’s typically the kind of script you can create
when analyzing trivially obfuscated malware and/or packers, when speed of
analysis has priority.

Program-Analysis-Based Deobfuscation

Now consider the following obfuscated code sample (this is only a very small
extract; obfuscated code continues like this for thousands of instructions):

.text:00405900 loc _ 405900:

. text :00405900 add edx, 67E37DA7h
.text:00405906 push esi
.text:00405907 mov esi, ODOB763Ah
. text :0040590C push eax
.text:0040590D mov eax, 15983FC8h
.text:00405912 neg eax
.text:00405914 inc eax
.text:00405915 inc eax
.text:00405916 jmp loc_4082AD
.text:004082AD loc 4082AD:

. text :004082AD not eax
.text:004082AF and eax, 1D48516Ch

. text :004082B4 sub eax, OACE1B37Ah

---

**Page 204**

314

Chapter 5 = Obfuscation

. text :004082B9 xor esi, eax
. text :004082BB pop eax
. text :004082BC xor edx, esi
.text:004082BE pop esi
.text:004082BF and ecx, edx

.text:004082C1 jmp loc_407C54

You likely recognize, from the first sections of this chapter, some of the obfus-
cation techniques used here, especially constant unfolding. Please also note
that unconditional jumps are inserted to split code into basic blocks that are
then distributed (randomly reordered) across the binary. There is no obvious
pattern, at least none you could possibly and effectively match at the syntactical
level using signatures.

You need to step up to the semantical level. Based on the output of a disas-
sember, you could start working on the control flow, merging the basic blocks
405900h and 4082ADh. Then, you could work on the data flow, considering the
two instructions:

.text:0040590D mov eax, 15983FC8h
.text:00405912 neg eax

Based on the semantics of these instructions, you know that the EAx register
is first assigned with a constant value and then negged. You could precompute
the NEG instruction and rewrite this in a simpler form, by assigning EAx with
the negged value:

.text:0040590D mov eax, EA67C038h

Rewriting programs in a simpler form, precomputing values that do not
depend on the program’s input, removing useless code—that is program opti-
mization, and compilers have done that almost since their creation. You can
adapt and reuse these techniques for your own purposes, and an abundant

body of literature is available on this topic. Some classical compiler optimiza-
tion techniques include the following:

m Peephole optimization

= Constant folding / propagation
m Dead store elimination

m Operation folding

m Dead code elimination

m Etc.

This approach is exactly what is proposed by the Optimice deobfuscation
plugin for IDA. Some previous works, by Gazet and Guillot” and by Josse,” have
also been presented, respectively as a Metasm plugin and a VxStripper plugin.
The idea is to normalize the code in order to get a reduced/optimized/canonical
form, which is simpler to analyze and closer to the original, unprotected, code.

---

**Page 205**

Chapter 5 = Obfuscation

315

These attempts to provide deobfuscation frameworks/utilities are still far
from perfect. In addition, not many tools are available to the average reverser to
attack obfuscated programs (of course, some private advanced tools exist here
and there). The future of deobfuscation will probably take the form of elaborated
tools and analysis platforms based on formal IR. Rolf Rolles presented some of his
results with his own framework written in OCam1™. Other popular frameworks
that could be used include LLVM-based SecondWrite (Smithson et al., 2007°”),
S2e/revgen (Chipounov, 2001’), or BitBlaze (Song et al., 2008*° and their works
since). Efforts in deobfuscation will have to match those put into obfuscation.

Complex Analysis

This section discusses two of the most impactful obfuscation techniques: code
virtualization and code flattening. For these techniques, you clearly need to
work at a semantic level.

Simple VM Implementations

There are mainly two forms of VM implementations. The most straightforward
form is to develop a simple processor emulator. Algorithmically speaking, it
would include the following steps:

1. Loop:
a. Fetch —Read the bytecode stream at the instruction pointer.
b. Decode—Decode the instruction’s opcode and its operands.
c. Execute—Call the appropriate opcode handler.

2. Update the instruction pointer or exit the loop.

In this configuration, each instruction handler is responsible for updating
the context of the VM. The context represents the underlying emulated archi-
tecture. It probably consists of a set registers, and eventually a memory area.
Each handler implements a distinctive instruction of the emulated processor
(one handler for the app, one for the sup, etc.).

This form is often used by the simpler implementations. Handlers are totally
independent of one another, and the instruction pointer is increased by the size
of the instruction (except for instructions that directly modify it).

From an attacker's point of view, this type of implementation is easily recogniz-
able. Following is a detailed look at the steps generally required to analyze a VM:

1. Understand how an instruction is decoded from raw bytecode: which
part encodes for the operation (handler number), which part encodes the
operand(s), and so on.

2. Deduct VM’s architecture from instructions’ operands: number of registers,
memory layout, 1/0 interfaces, etc.

---

**Page 206**

316

Chapter 5 = Obfuscation

3. Undertake handler analysis. Once operand decoding is known, you can
look at the way each handler manipulates the various operand(s) it pos-
sibly takes as argument(s). This step is the essence of VM analysis: Each
handler is associated with its own semantics.

With all these pieces of knowledge, you can finally build a disassembler-like
tool that enables you to disassemble the bytecode of the VM.

In 2006, Maximus published two great papers about VM reversing: “Reversing
a simple virtual machine” and “Virtual machines re-building”*’. One of the
targets he used (HyperUnpackme2) was also covered in depth by Rolf Rolles the
same year”.

Although these are useful contributions from talented reversers, VM analy-
sis remains a somewhat manual and repetitive job: One has to develop a new
disassembler for each new instance of VM. Moreover, protections authors have
also reacted, hardening their implementations of VMs.

Advanced VM Implementations

More advanced VM implementations derive from the simple type but add
important features to harden the implementations and make them more resil-
ient to analysis:

m Loop unrolling—This classical compiler optimization technique favors
the time (speed) aspect of a program’s space vs. time trade-off. It replaces
the loop structure by the sequential invocations of the loop body (thus
unrolled). Applied to a VM, each handler is made responsible for fetching
and decoding its own operand(s), and then updates the context accordingly.

m Code-flattening—The VM’s main execution loop is flattened. That means
each handler is responsible for updating the instruction pointer (pointer
on the bytecode). Actually, code-flattening and VM-based obfuscation are
basically the same thing. Code-flattening only virtualizes/retargets the
control flow of the protected code, whereas virtual-machine obfuscation
virtualizes /retargets both the control flow and the data flow. You can use
almost the same algorithms to follow a code-flatten dispatcher’s context
and a VM context.

m Bytecode encoding/encryption—Each invocation of the VM depends on
an encryption key that is passed to the VM as part of its context initializa-
tion. Each handler updates that key, resulting in a turning key. The han-
dlers depend on the turning key to decode their operands from encoded
bytecode. An attacker cannot start analyzing the VM at a chosen point,
as the value of the key at this point would be unknown.

m Code obfuscation—The native code of the VM is obfuscated using tech-
niques like the one described at the beginning of this chapter. Simply
looking at a handler’s code provides no clue about its semantics.

---

**Page 207**

Chapter 5 = Obfuscation

317

In summary, hardened implementations of VMs are more difficult to analyze
statically by an order of magnitude. For each state of the VM, an attacker has to
know at least the following mandatory values:

m Bytecode pointer
m Instruction pointer, the value of the next handler to be executed

m Turning encryption key

VMs have reached a new level of complexity, thus necessitating a new level
of attack. Handlers are more complex to analyze; moreover, they cannot be
analyzed in isolation (one would not know the value of the encryption key,
for example). An attacker wants to limit the manual analysis to a minimum.
Nevertheless, a manual review is most often required to “capture” the general
behavior of a VM and thus infer possible attacks on it.

One of the first places of interest is the VM invocation stub—i.e., the transi-
tion between native (nonvirtualized) code and the VM/interpreter. The context
initialization indicates the nature of the mapping between the native architecture
and the VM‘°s architecture. It may be a carbon copy of native registers to the
VM‘s registers or something more complicated. Also, at this point, it is helpful
to distinguish (as much as possible) between mandatory initialization variables
(such as a VMs key, handler number, or entry point) for which a numerical value
is required, and extra variables that can be kept symbolic.

The second place of major interest is the VM’s dispatcher (if it exists). Most
often there is a single point of dispatch that basically retrieves the next handler
from a handlers table based on an index stored somewhere within the VM’s
context. A question to answer is, what is the break condition of this execution
loop? In this configuration it is possible to consider the VM as a generalization
of code-flattening. Code-flattening virtualizes only the control flow, whereas
the VM virtualizes both the control and data flows. Moreover, code-flattening
most often only operates at single function level, whereas the VM operates at
the program level. The other possibility is a distributed dispatch, whereby each
handler is responsible for updating the VM’s instruction pointer and linking
to the next handler.

These are general ideas; each reverser has his or her own tricks and abstrac-
tions of the problem.

Using Metasm

The approach we are going to explore is based on the Metasm framework.
It relies on symbolic execution to make the VM (i.e., interpreter) process the
bytecode (with respect to static data) and compute the residual program. On
the one hand, there is a program (the interpreter); on the other hand, there is
its static data (the bytecode); we will specialize the program with respect to
its static data.

---

**Page 208**

318

Chapter 5 = Obfuscation

Considering an obfuscated program and its data as a whole would be too
complex, the solution is to break this complex problem into multiple, simpler
sub-problems. Considering virtual machine’s instruction handlers level provides
a far more appropriate granularity. From now on, we will consider instruction
handlers as the interpreter’s smallest unit of semantics.

Based on that basic premise, you can apply the following pseudo algorithm:

1. Capture the current context (VM’s bytecode, static parameters, known
environment, etc.).

Disassemble the current handler.

Deobfuscate code, if necessary.

Compute its semantics (i.e., transfer function).
Generate output from solved semantics.

Compute next state (i.e., apply the transfer function to the current context).

NDA FF YN

If the handler’s dispatcher doesn’t reach a break/exit condition, repeat
from step 1.

Optionally, you may be able to regenerate native code from the transfer func-
tion computed at step 4. As expressed by Futamura”!, given an interpreter of
Linterpreted Written in a given native language L it is possible to automatically
compute a compiler from Linterpreted tO Lnative:

This is suitable for the theoretical concepts. Now suppose that you face an
instance of a VM. Where do you start? Let’s take a practical example.

The following script makes use of Metasm to compile and then disassemble
what could be a handler from a VM. For the sake of simplicity, this example
deals only with the VM’s part (thus, code is not obfuscated). The handler’s code
is located in 10000000h, while a data section containing the handler’s bytecode
is located in 1a000000h:

native /

# encoding: ASCII-8BIT
#!/usr/bin/env ruby

require "metasm"
include Metasm

$SPAWN GUI = false

CODE_BASE ADDR = 0x10000000
HTABLE BASE ADDR = 0x18000000
DATA_BASE ADDR = 0x1A000000
INJECT MAX ITER = 0x20

NATIVE REGS = [:eax, :edx, :ecx, :ebx, :esp, :ebp, :esi, :edi]
def display (bd)

bd.each{|key,value| puts "| #{Expression[key]} => #{Expression[value] }"}
end

---

**Page 209**

Chapter 5= Obfuscation 319

# produce handler's x86 code

sc = Metasm: :Shellcode.assemble (Metasm: :Ia32.new, <<EOS)
lodsd

mov ecx, eax

xor ecx, ebp

movzx eax, cl

push eax

mov eax, [edit+teax]

movzx edx, ch
mov edx, [edi+edx]

xor eax, edx

pop edx
mov [edi+edx], eax

lodsd xor ebp, 0x35ef6al4

xor eax, ebp

jmp [#{HTABLE BASE ADDR}+eax*4]
EOS

handler = sc.encode_ string

# data section hex
data_section_hex = "\xA3\xCB\xDB\x5F\x60\xBD\x34\x6A"

# add a code section
dasm = sc.init_disassembler
dasm.add_section(EncodedData.new(handler) , CODE BASE ADDR)

# add a data section
dasm.add_section(EncodedData.new(data_section hex), DATA BASE ADDR)

# disassemble handler code
dasm.disassemble fast _deep(CODE BASE ADDR)

The first thing to do is automatically get the semantics of that handler. As men-
tioned previously, Metasm offers a method called code_binding that computes
the function transfer (Metasm’s terminology is binding) of a set of instructions.
Thus, you can write the following:

# compute handler's semantics

bb = dasm.di_at (CODE_BASE ADDR) .block

start_addr = bb.list.first.address

end_addr = bb.list.last.address

puts "[+] from Ox#{start_addr.to_s(16)}, to Ox#{end_addr.to_s(16) }"
binding = dasm.code_binding(start_addr, end_addr)

display (binding)

The preceding produces the following output:

[+] from 0x10000000, to address 10000021
adword ptr [esp] => (dword ptr [esi]*ebp) &0ffh
dword ptr [edi+((dword ptr [esi]*ebp) &0ffh)] =>

---

**Page 210**

320 Chapter 5 = Obfuscation

A

dword ptr [edi+((dword ptr[esi] *ebp) &0ffh) ]
dword ptr [edi+(((dword ptr[esi] >>8) * (ebp>>8) ) &Offh) J

eax dword ptr [esi+4]* (ebp*35ef6al4h) ) <OfFEEfFEEh

ecx => (dword ptr [esi] *ebp) &Offffffffh
edx
ebp => (ebp*35ef6al4h) cOffffffF£h

(
(
=> (dword ptr [esi] *ebp) &0ffh
(
(

esi esit+8) SOffLLLLELH

From both the assembly and the binding, you can say the following about
the VM:

m It seems to use a turning key store in EBP. (Note how it is used to decrypt
the instruction’s operands from bytecode.)

m Its context seems to be pointed to by EDI.
That’s a good start, but you are still far from the objective. You are still stuck

at the assembly level, so let’s step back and consider the VM initialization, which
we have identified as follows:

pushad

pop [edi]

pop [edi+0x4]
pop [edi+0xs8]
pop [edi+0xC]
pop [edi+0x10]
pop [edi+0x14]
pop [edi+0x18]
pop [edi+0x1C]

First, native registers are pushed onto the stack, and then they are read from
the stack into a memory area pointed to by EDI, which in turn is responsible for
pointing at the VM’s context. This information enables you to create a mapping
between the VM’s symbolic internals and assembly expression:

vm_symbolism = {

:eax => :nhandler,

:ebp => :vmkey,

:€Si => :bytecode_ ptr,

Indirection[[:edi], 4, nil] => :vm_edi,
Indirection[[:edi, :+, 4], 4, nil] => :vm esi,
Indirection[[:edi, :+, 8], 4, nil] => :vm_ebp,
Indirection[[:edi, :+, OxC], 4, nil] => :vm_esp,
Indirection[[:edi, :+, 0x10], 4, nil] => :vm_ebx,
Indirection[[:edi, :+, 0x14], 4, nil] => :vm_edx,
Indirection[[:edi, :+, 0x18], 4, nil] => :vm_ecx,
Indirection[[:edi, :+, Oxlc], 4, nil] => :vm_eax,

}

This symbolism is injected into the binding (each occurrence of a left value
is replaced by its associated right value). Expressions have a special method
named bind that does exactly that. The following example first defines a symbolic

---

**Page 211**

Chapter 5 = Obfuscation

321

expression: the addition of two terms, one of them being an indirection; and
two symbols are involved, :a and :b. Next, symbol :a is associated (bound)
with the value 1000h:

expr = Expression[[:a, 4], :+, :b]
sym = {:a => 0x1000}

puts expr
>> dword ptr [a]+b

puts expr.bind(sym)
>> dword ptr [1000h]+b

You can generalize this for each expression of the binding. This mapping is
the key that enables abstracting VM’s code from its implementation level up to
the VM semantics level. Moreover, a positive side effect of this step is often a
significant reduction of the binding’s complexity. The new binding is as follows:

[+] symbolic binding

dword ptr [esp] => (dword ptr [bytecode ptr] “vmkey) &0ffh

dword ptr [edi+((dword ptr [bytecode_ptr] “vmkey) &0ffh) ] =>

dword ptr [edi+dword ptr [bytecode ptr] *vmkey) &0ffh) ]~*

dword ptr[edi+(((dword ptr [bytecode_ptr] >>8) * (vmkey>>8) ) &£0ffh) ]
nhandler => (dword ptr [bytecode _ptr+4] *(vmkey*35ef6al14h) ) SOfffFFFfEhH

vmkey => (vmkey*35ef6al4h) GOffFEEff£h
bytecode ptr => (bytecode _ptr+8) &0ffffffF£h

We have made progress, but the encryption is still problematic and we
cannot go further if the VM’s context at the execution time of this handler is
unknown: bytecode pointer, turning key, and optionally the handler number
are all required values. Assuming you know these values (you are at the VM’s
entry point or you have dynamically traced the VM up to that point), you can
define a pseudo-context:

context = {
:nhandler => 0x84,
:vmkey => 0x5fdbd7b7,
:bytecode_ptr => DATA BASE ADDR,
:virt_eax => Oxffeeffee,
:virt_ecx => 0,
:virt_edx => 0x41414141,
:virt_ebx => 1,
:virt_edi => :virt_edi,

}

Note that the context contains both symbolic and numerical values. For example,
nhandler is defined as equal to 84h, while the VM's register virt_edi is symbolic.
The context is then injected within the binding, as well as the symbolism
defined previously. In practice that’s an iterative process, but let’s not get over-
loaded with implementation details. Expressions are progressively solved and

---

**Page 212**

322 Chapter 5 = Obfuscation

reduced with respect to all known values, which include the current context
and the program's data (i.e., the bytecode). At the end you have a solved bind-
ing, which actually represents the context of the VM after the execution of the
handler. We call that step symbolic execution:

[+] binding solver
[+] key: dword ptr [esp]
=> solved key: dword ptr [esp]

[+] value: (dword ptr [bytecode _ptr] “vmkey) &0ffh
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
=> solved value: 14h

[+] key: dword ptr [edi+((dword ptr [bytecode ptr] “vmkey) &0ffh) ]
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
=> solved key: virt_edx

[+] value: dword ptr [edi+((dword ptr [bytecode ptr] *vmkey) &0ffh) ]*
dword ptr [edi+(((dword ptr [bytecode_ptr] >>8) * (vmkey>>8) ) &0ffh) ]
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
=> solved value: Obeafbeafh

[+] key: nhandler
=> solved key: nhandler

[+] value: (dword ptr [bytecode _ptr+4] *(vmkey*35ef6al4h) ) &Offffffffh
[+] solved memory read at 0x1a000004, size 4
[+] value 6a34bd60h
=> solved value: Oc3h

[+] key: vmkey
=> solved key: vmkey
[+] value: (vmkey*35ef6al4h) &Offfffff£Fh
=> solved value: 6a34bda3h

[+] key: bytecode_ptr
=> solved key: bytecode _ptr
[+] value: (bytecode _ptr+8) &0ffffffffh
=> solved value: 1a000008h

[+] solved binding
virt_edx => Obeafbeafh
nhandler => Oc3h
vmkey => 6a34bda3h
bytecode _ptr => 1a000008h

---

**Page 213**

Chapter 5= Obfuscation 323

The expression solver helps to compute the final values of the first handler’s
binding: the next handler to be executed as well as the updated value of the
turning key. Updating the context is a trivial operation:

updated_context = context .update(solved_binding)

puts "\n[+] updated context"
display (updated_context)

[+] updated context
nhandler => Oc3h
vmkey => 6a34bda3h
bytecode ptr => 1a000008h
virt_eax => Offeeffeeh
virt_ecx => 0
virt_edx => Obeafbeafh
virt_ebx => 1
virt_edi => virt_edi

You can repeat this process and walk through the whole control-flow graph of
the VM. This is a quite appreciable result; nevertheless, pure numerical values
somewhat hide the semantics of the handler. Moreover, one of the objectives is
to regenerate native assembly code equivalent to the contextualized execution
of the handler.

A trick we often use when analyzing a VM with Metasm is to proceed to a
double symbolic execution for each handler: one with the full context (mainly
numerical values, used to update the context) and another one with an almost
purely symbolic context (used to extract the high-level semantics). The next code
sample demonstrates the use of a symbolic context:

symbolic context = {
:mhandler => 0x84,
:vmkey => Ox5fdbd7b7,
:bytecode_ptr => DATA BASE ADDR,
:virt_eax => :virt_eax,
:virt_ecx => :virt_ecx,
:virt_edx => :virt_edx,
:virt_ebx => :virt_ebx,
:virt_edi => :virt_edi,

}

solved_symolic binding = sym_exec(symbolic context,
symbolic binding,
vm_symbolism)

puts "\n[+] solved binding" display (solved_symbolic_ binding)

This time the output is as follows:
[+] binding solver

[+] key: dword ptr [esp]
=> solved key: dword ptr [esp]

---

**Page 214**

Chapter 5 = Obfuscation

[+] value: (dword ptr [bytecode _ptr] “vmkey) &0ffh
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
=> solved value: 14h

[+] key: dword ptr [edi+((dword ptr [bytecode ptr] *vmkey) &0ffh) ]
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
=> solved key: virt_edx

[+] value: dword ptr [edi+((dword ptr [bytecode_ptr] “vmkey) &0ffh) ]*
dword ptr edi+(((dword ptr [bytecode _ptr]>>8) *(vmkey>>8) ) &0ffh) ]
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h
[+] solved memory read at 0x1a000000, size 4
[+] value 5fdbcba3h

=> solved value: virt_edx*virt_eax

[+] key: nhandler
=> solved key: nhandler

[+] value: (dword ptr [bytecode _ptr+4] *(vmkey*35ef6al4h) ) &Offffffffh
[+] solved memory read at 0x1a000004, size 4
[+] value 6a34bd60h
=> solved value: Oc3h

[+] key: vmkey
=> solved key: vmkey

[+] value: (vmkey*35ef6a14h) &OffFEFLEF EH
=> solved value: 6a34bda3h

[+] key: bytecode_ptr
=> solved key: bytecode ptr

[+] value: (bytecode_ptr+8) &OffffffF£h
=> solved value: 1a000008h

[+] solved binding
virt_edx => virt_edx*virt_eax
nhandler => Oc3h
vmkey => 6a34bda3h
bytecode ptr => 1a000008h

Finally, you can simply reject VM control stuff from the solved binding, leav-
ing you with the following:

vm_edx => vm_edx*vm_eax

From that final result, native code regeneration is pretty straightforward.
You iterate this process over the VM’s control-flow graph for each handler. As
a general observation, when using this technique, a sensitive choice is when to
keep symbolic values and when to reduce to numerical values. The first option

---

**Page 215**

Chapter 5 = Obfuscation

325

favors the recovery of high-level semantics, while the second enables an easier
VM's control-flow recovery. At the end, it is also possible to further proceed the
output. Imagine a VM that looks like a stack-based interpreter:

01: push vm_edx
02: add [esp], vm_eax
03: pop vm_edx

Using classic deobfuscation methods such as compiler optimizations would
rewrite the preceding three lines as follows:

01: add vm_eax, vm_eax

Please note that the bytecode itself could have been obfuscated.

Code-Flattening Deobfuscation

As previously stated, code-flattening can be viewed as partial virtualization (only

the control flow is virtualized). Thus, techniques described for VM analysis, and

especially symbolic execution, can also be applied for flattened code analysis.
There are still some difficulties that are specific to this technique:

m Code-flattening transformation is most often applied at the function level
and sometimes there may be more than one flattened “node” in the same
function. Overall that means there are multiple instances of the techniques;
thus a tool has to be bulletproof and fully automatic.

m Discerning between a function’s original code and added dispatcher’s code
is difficult when code-flattening implementation is robust (program and
dispatcher data flows are firmly interleaved /interdependent).

m Inverse transformation is not trivial to implement.

Using VxStripper

To illustrate the use of VxStripper on a simple “toy” example, consider the fol-
lowing program (which displays y = 22) after unpacking and reconstruction:

tees ! entrypoint:

see ! push ebp

401001 ! mov ebp, esp

401003 ! sub esp, 10h

401006 ! mov dword ptr [ebp-4], 0
40100d ! mov dword ptr [ebp-Och], 2
401014 ! mov dword ptr [ebp-8], Oah
40101b !

Lee ! loc_40101b:

tee ee ! cmp dword ptr [ebp-Och], 6
40101f ! jnl loc_40108c

401021 ! mov eax, [ebp-Och]

401024 ! mov [ebp-10h], eax

401027 ! mov ecx, [ebp-10h]

40102a ! sub ecx, 2

---

**Page 216**

326 Chapter 5 = Obfuscation

40102d ! mov [ebp-10h], ecx

401030 ! cmp dword ptr [ebp-10h], 3
401034 ! ja loc_40108a

401036 ! mov edx, [ebp-10h]

401039 ! jmp dword ptr [edx*4+data_4010a4]
401040 mov dword ptr [ebp-4], 2
401047 mov dword ptr [ebp-Och], 3
40104e jmp loc_40108a

401050 cmp dword ptr [ebp-8], 0
401054 jng 40105fh

401056 mov dword ptr [ebp-Och], 4
40105d jmp 401066h

40105f£ mov dword ptr [ebp-Och], 6
401066 jmp loc_40108a

401068 mov eax, [ebp-4]

40106b add eax, 2

40106e mov [ebp-4], eax

401071 mov dword ptr [ebp-Och], 5
401078 jmp loc_40108a

40107a mov ecx, [ebp-8]

40107d sub ecx, 1

401080 mov [ebp-8], ecx

401083 mov dword ptr [ebp-Och], 3
40108a !

sees ! loc_40108a:

tees ! jmp loc_40101b

40108c !

sees ! loc_40108c:

wee ! mov edx, [ebp-4]

40108f ! push edx

401090 ! push strz yd 402008

401095 ! call dword ptr [msvcert.dll:printf]
40109b ! add esp, 8

40109e ! xOor eax, eax

4010a0 ! mov esp, ebp

4010a2 ! pop ebp

4010a3 ! ret return 0;

The control-flow graph (CFG) of such a program is flattened.
The normalization module’s execution produces (when you do not apply all
optimizations) the following code:

see ! push eax

4011f1 ! mov dword ptr [esp-Och], Oah
4011f£9 ! mov dword ptr [esp-8], 4
401201 ! dec dword ptr [esp-0Och]
401205 ! add dword ptr [esp-8], 2
40120a ! dec dword ptr [esp-0Och]
40120e ! add dword ptr [esp-8], 2
401213 ! dec dword ptr [esp-Och]
401217 ! add dword ptr [esp-8], 2
40121c ! dec dword ptr [esp-Och]

401220 ! add dword ptr [esp-8], 2

---

**Page 217**

Chapter 5

Obfuscation

327

401225
401229
40122e
401232
401237
40123b
401240
401244
401249
40124d
401252
401256
40125a
40125e
401266
401268
40126c
40126e
401273
401275
401277
40127b
40127d
40127£
401281
401282

Note that the dynamic generation of code performed by VxStripper naturally
unflattens the flattened code. Applying standard optimization transformations

!

dec
add
dec
add
dec
add
dec
add
dec
add
dec
mov
mov
mov
mov
lea
mov
call
mov
mov
lea
mov
mov
xor
pop
ret

dword ptr [esp-0Och]

dword ptr [esp-8], 2

dword ptr [esp-0Och]

dword ptr [esp-8], 2

dword ptr [esp-0Och]

dword ptr [esp-8], 2

dword ptr [esp-0Och]

dword ptr [esp-8], 2

dword ptr [esp-0Och]

dword ptr [esp-8], 2

dword ptr [esp-0Och]
eax, [esp-8]
[esp-18h],

dword ptr [esp-ich],

eax
strz yd 402010
ebp, esp
eax, [esp-l1ch]
esp, eax

ertdll.dll:printf£_4012d8
esp, ebp
ebp, esp
eax,
esp,

esp,

[esp+8]
eax
ebp
eax, eax

edx

results in a program stripped of this obfuscation:

4011f1
4011f9
401201
401203
401207
401209
40120e
401210
401212
401216
401218
40121la
40121c
40121d

push
mov
mov
mov
lea
mov
call
mov
mov
lea
mov
mov
xor
pop
ret

eax
dword ptr [esp-18h], 16h

dword ptr [esp-l1lch], strz yd 402010
ebp, esp

eax, [esp-l1ch]

esp, eax

crtdll.dll:printf_401268

esp, ebp

ebp, esp

eax, [esp+8]

esp, eax

esp, ebp

eax, eax

edx

Even if work remains before obtaining software that supports the set of soft-
ware protection tools usable by malware authors, these first results encourage us
to pursue the study of generic methods of unpacking and normalization, with
the goal of automating as much as possible the tasks conducted by an analyst.

---

**Page 218**

328

Chapter 5 = Obfuscation

This tool provides a self-sufficient piece of software for malware analysis.
However, one of the future goals of this project is to enable the tool to interact
with other analysis tools. By design, this tool may be able to collaborate with
any software analysis tool based on the LLVM compilation chain.

The LLVM compilation chain and the many LLVM-based tools already provide
a great library of program analyses that can be used together to defeat malware
protection mechanisms.

In addition, Vellvm (Verified LLVM) may be used to formally extract verified
implementations of deobfuscation passes implemented by VxStripper. In addition
to malware threat analysis, other uses of this tool can also be imagined, such
as detection scheme extraction, software protections, and antivirus software
robustness analysis.

Case Study

The sample we’ll use for this case study is actually a crackme originally posted
on Crackmes.de by quetz in 2007. Even though it is a “only” a crackme, it features
most of the concepts that one would find in a professional-grade protection.
Among other rejoicings it contains the following:

m Code-flattening
m Variable encoding

m Code virtualization

Here is how the author introduces its challenge:

Lately, protection from static analysis becomes more and more popular.
Almost every protector employs some kind of obfuscation, virtual machine,
etc... This keygenme is an attempt to show what happens if you abuse idea
of obfuscation. Can human effectively analyze such code? Maybe with an
assistance of a tool?

—http://crackmes.de/users/quetz/q_keygenme_1.0/

Fortunately, we have tools and in this section we will use them. Before start-
ing, we recommend that you not look at the symbols section contained within
the binary. As an aside, previous versions of IDA Pro (maybe inferior to 6.2)
didn’t load these symbols and the author of these lines cheerfully failed to look
for them.

First Impressions

Launching the executable offers you the opportunity to input a username and a
password. After clicking the Check button, a message box appears and displays
the validity of your credentials.

---

**Page 219**

Chapter 5 = Obfuscation

329

If you've carefully read the previous chapters of this book, you have probably
already fired up your favorite disassembler and targeted the GUI’s DialogProc
callback function.

Let’s first look at the general architecture of the protected code. The control-
flow graph is way too messy to be natural compiler-generated code: We have an
obfuscated DialogProc calling two code-flattened functions (func1@0x430DB0,
func2@0x431E00). These two functions themselves call what seems to be a VM
(vm@0x401360).

We have already discussed the VM’s single dispatch point; this one is pretty
straightforward to spot (look for an important jump table in the absence of any
other clues):

Ol: .text:00401F20

02: mov ebp, [esp+13Ch]

03: cmp ebp, 3E2Dh; switch 15918 cases

04: ja short loc_401F36

05: jmp ds:off 43D000[ebp*4]; switch jump

These are our two first and almost free pieces of knowledge about the VM:
It stores its current handler number in [ESP+13Ch] and there are 15,918 entries
in the dispatcher (for now, we cannot conclude whether they are all different
handlers).

Before getting our hands dirty, we can try to do some black-box analysis
of the funci and func2 functions. We know func1 and func2 call the VM; we
simply log every call to the VM and especially the number of the first handler
that is called (a sort of entry point in the VM code). That seems quite trivial but
one should never disregard low-hanging fruit.

Results are immediately revealing: func2 is called before funci, so we will
start with func2. As soon as you look at the logs of the VM’s entry point, these
patterns stand out:

m 546h-OBFFh-7B2h-9 A2h-405h-919h-3B9h—624 times
m OCF5h-15Eh-184h-39Ch-5BO0h-3COh-0F75h—624 times
m 0A06h-0xA29h-0x268h-0xCB3h—227 times

m 736h-13Ah-1EBh-897h—3%6 times

m 150h-8ABh-843h-697h-474h—200 times

That’s actually already a lot of information. If you look at the . data section,
an extra hint is waiting:

O01: .data:0043CA44 dword_43CA4402: .data:0043CA48 dd 9908BODFh

Where does 9908B0DFh come from? And 624? And 227? Well, either you are
really familiar with random number generators or you look for these values;
they identify a Mersenne twister pseudo-random generator algorithm. 624
and 397 are the period parameters, while 9908BoDFh is a constant used during
number generation.

---

**Page 220**

330

Chapter 5 = Obfuscation

We have identified a critical weakness of the protection: Virtualized code
leaks some information about the structure of the protected algorithm, mak-
ing it trivial to recover loop iterations. Nevertheless, do we have nicely crafted
virtualized code nullified with one breakpoint? Not yet. We have an algorithm
candidate but it needs to be confirmed.

Again, one should never reverse engineer some code when it is possible to
guess (and validate) information! In this case, a black-box analysis reveals a lot
simply by looking at the inputs/outputs of functions func1 and func2. A basic
strategy like this or differential analysis of VM execution can sometimes be of
great help. Let’s refine our analysis of these two functions:

@ func2

m Input—Two arguments: an address on the stack that seems to be an
array of integers, and a 32-bit value that seems to depend on the length
of the name.

m= Output—Nothing remarkable except that the integers array has been
updated.

m Occurrence—Called a single time, at the beginning and before func1.

m Guess—Mersenne twister initialization, the array is actually the state
of the PNRG. The 32-bit value is the initialization seed. This can be
further validated by matching loop parameters (learned from the logs)
with a standard initialization function.

@ funcl

m Input—TIwo arguments: the address of the (supposed) PRNG state and
a 32-bit value that seems to be a letter from the username.

= Output—Returns a 32-bit random value.
m Occurrence—Called 100 times.

m Guess—Mersenne twister rand32-like function.

Analyzing Handlers Semantics

It is now time to analyze the VM. The main dispatcher has already been found
at [ESP+13ch]. It is often a good idea to manually check a few handlers to see
how they access the VM’s context, how they update the program counter and/
or bytecode pointer, and so on.

This process can be applied on a random handler—for example, the one
starting at 0x41836c:

O1: .text:0041836C loc_41836C:

02: ; DATA XREF: .rdata:off 43D000

03: ; jumptable 00401F2F cases 2815,4091
04: .text:0041836C movzx ecx, [esp+3D8h+var_2A2]

---

**Page 221**

Chapter 5 = Obfuscation

331

05: .text:00418374 mov esi, 97Fh

06: .text:00418379 mov ebx, [esp+3D8h+var_3C8]
O07: .text:0041837D movzx edi, [esp+3D8h+var_29E]
08: .text:00418385 add [esp+3D8h+var_3C0], 94Eh
09: .text:0041838D imul eax, ecx, 1Ch

10: .text:00418390 sub [esp+3D8h+var_3C4], OFFOh
11: .text:00418398 imul ecx, edi, 5DDh
12: .text:0041839E mov [esp+3D8h+var_37C], esi

13: .text:004183A2 lea edx, [eaxt+ebx+5C8h]

14: .text:004183A9 mov ebx, 97Fh

15: .text:004183AE mov [esp+3D8h+var_3C8], edx
16: .text:004183B2 sub ebx, eCcx

17: .text:004183B4 lea edx, [ebpt+tebx+29Dh+var_8BC]

18: .text:004183BB mov [esp+3D8h+var_378], ebx
19: .text:004183BF mov [esp+3D8h+var_380], ebx
20: .text:004183C3 mov [esp+3D8h+var_29D+1], edx

21: .text:004183CA jmp loc_401F20

Let’s get some help from Metasm. As shown previously, we can use the code-
binding method to compute the semantics of a chunk of code:

dword ptr [esp+10h] => lch*byte ptr [esp+136h]+dword ptr [esp+10h]+5c8h
dword ptr [esp+14h] => dword ptr [esp+14h]-0ff0h

dword ptr [esp+18h] => dword ptr [esp+18h]+94eh

dword ptr [esp+58h] => -5ddh*byte ptr [esp+13ah]+97fh
dword ptr [esp+5ch] => 97fh

dword ptr [esp+60h] => -5ddh*byte ptr [esp+13ah]+97fh
dword ptr [esp+13ch] => ebp-5ddh*byte ptr [esp+13ah]+360h
eax => (lch*byte ptr [esp+136h] ) &OfffffLffh

ecx => (5ddh*byte ptr [esp+1l3ah] )&o0ffffffffh

edx => (ebp-5ddh*byte ptr [esp+13ah]+360h) &0ffffffffh

ebx => (-5ddh*byte ptr [esp+13ah]+97fh) &offffffffh

esi => 97fh

edi => byte ptr [esp+1l3ah] &0ffffffffh

The VM’‘s context is stored on the stack and no values are passed by registers
between handlers; that means all register modification can be dropped to get
a clearer view:

dword ptr [esp+10h] => lch*byte ptr [esp+136h]+dword ptr [esp+10h]+5c8h

dword ptr [esp+14h] => dword ptr [esp+14h]-0ff0h

dword ptr [esp+18h] => dword ptr [esp+18h]+94eh

dword ptr [esp+58h] => -5ddh*byte ptr [esp+13ah]+97fh

dword ptr [esp+5ch] => 97fh

dword ptr [esp+60h] => -5ddh*byte ptr [esp+13ah]+97fh

dword ptr [esp+13ch] => ebp-5ddh*byte ptr [esp+13ah]+360h

We already know that the handler number is stored at [ESP+13Ch]. It is updated
by the handler. Its final value depends on the value of byte ptr [ESP+13ah]. By
analyzing a few other handlers, we can guess it is a Boolean value, and a few
other Booleans are stored in the context. This one is stored in second position,
and it will be named flag2.

---

**Page 222**

332

Chapter 5 = Obfuscation

[ESP+58h], [ESP +5Ch],and [ESP +60h] are firmly tied with the handler
number computation. They respectively contain the delta between the old and
new handler number in case the condition (here £1ag2) is true or false.

[ESP +10h], [ESP +14h],and [ESP +18h] are also of high interest. They are
updated by almost every handler and are supposed to decrypt the bytecode:
They access the large undefined constants table stored in the . data section).
They are actually like a running key; they’ll be named respectively key_a,
key_b, and key c.

The following is an example of key usage taken from handler oxa0a at address
0x427b17:

nHandler => dword ptr [4*key_c+436010h] *
dword ptr [4*key_b+436010h] *
dword ptr [4*key_a+436010h]

The names can be injected within the handler’s binding, making it more under-
standable (even if that’s not our main objective here) and easy to manipulate:

key_a => lch*flagé+key_a+5c8h
key_b => key _b-Off0h

key_c => key_c+94eh

delta_true => -5ddh*flag2+97fh
delta_false => 97fh

delta => -5ddh*flag2+97fh
nHandler => ebp-5ddh*flag2+360h

This handler has almost the semantics of a conditional jump. By analyzing a
few other handlers, it is possible to recover and validate a mapping of the VM’s
symbolic variables, which will be represented by a hash object:

SYMBOLIC_VM = {

Indirection[Expression[ :esp, , 0x10], 4, nil] => :key a,
Indirection[Expression[ :esp, , 0x14], 4, nil] => :key_b,
Indirection[Expression[ :esp, , 0x18], 4, nil] => :key_c,
Indirection[Expression[ :esp, , 0x58], 4, nil] => :delta,
Indirection[Expression[ :esp, , Ox5c], 4, nil] => :delta_false,
Indirection[Expression[ :esp, , 0x60], 4, nil] => :delta_true,
Indirection[Expression[ :esp, , OX134], , nil] => :flag8,

0x135],
0x136],
0x137], , nil] => :flag5,

1
Indirection[Expression[ :esp, 1
1
1

0x138], 1, nil] => :flag4,
1
1
1
4

, nil] => :flag7,

Indirection[Expression[ :esp, , nil] => :flage6,

Indirection[Expression[ :esp,

Indirection[Expression[ :esp,

0x139],
Oxl1l3a],
0x13b],
Ox13c],

Indirection[Expression[ :esp, , nil] => :flag3,

Indirection[Expression[ :esp, , nil] => :flag2,

Indirection[Expression[ :esp, , nil] => :flagl,

+ t+ t+ t+ + FF tt tH +H + tT

Indirection[Expression[ :esp, , nil] => :nHandler

}

Other memory locations do not seem to have a dedicated purpose; they can
be considered/mapped as general-purpose registers. With this mapping, we

---

**Page 223**

Chapter 5 = Obfuscation

333

have all we need to process a symbolic execution of the VM (ie., step-by-step
execution of handler’s semantics).

Symbolic Execution

In order to process a symbolic execution, you must have some clues about the
initialization context of the VM; recall the initial value of the turning key or the
value of the program counter (handler number). In our case, calls to the VM are
themselves obfuscated (remember the previously discussed graph-flattened func-
tions), making the initialization context quite hard to recover statically. In that
situation, one can simply take the best of the two worlds and use a compromise
between static and dynamic analysis, sometimes referred to as concolic execution.

Basically that means you debug the target and catch (break at) every call to
the VM; within the callback, you switch from dynamic to static analysis and
proceed to the following actions:

1. Dump target’s memory.

2. Initialize the symbolic analysis context with the memory dump. Actually,
a kind of lazy loading can be used. All access to the uninitialized context
will be solved and cached using the memory dump.

3. Compute the VM’s symbolic execution.

Using concolic execution, it becomes quite easy to follow the execution flow
of the VM (i.e., a succession of handlers). The process of handler analysis and
tracing is fully automated.

Here is an example of output of the tool for one handler. The extensive use of
the turning key (consisting of key_a, key_b, and key_c) clearly appears; in this
situation, the key is used to obfuscate access to the VM’s context:

[+] disasm handler 2be at 42c2cdh

[+] analyzing handler at 0x42c2cd

[+] considering code from 0x42c2cd to 0x42c3b3
[+] cached handler binding

dword ptr [dword ptr [esp+4*(dword ptr [4*key_b+436000h] *
(dword ptr [4*key_c+436000h] *dword ptr [4*key_ a+436000h]))+140h]] =>
dword ptr [dword ptr [esp+4*(dword ptr [4*key_b+436004h] *
(dword ptr [4*key_c+436004h] *dword ptr [4*key_ a+436004h] ))+140h] ]

key_c => key_c+5
key_b => key_b+5
key_a => key_a+5

nHandler => (dword ptr [4*key_b+43600ch] *
(dword ptr [4*key_c+43600ch]“dword ptr [4*key_a+43600ch] ))+
(((dword ptr [4*key_c+436010h] *(dword ptr [4*key_b+436010h] *
dword ptr [4*key_a+436010h]))* (byte ptr [dword ptr [esp+4*

---

**Page 224**

334

Chapter 5 = Obfuscation

A

(dword ptr [4*key_b+436008h] * (dword ptr [4*key_ c+436008h]
dword ptr [4*key_a+436008h] ))+140h]] &0ffh) ) GOffLLLEELh)

[+] symbolic binding

dword ptr [esp+0a8h] => dword ptr [esp+0ach]

key_c => Od6h

key_b => 1f6h

key_a => 126ah

nHandler => ((2leh* (flag4&0ffh) ) <OffLLLLELH) +O0ac6h

[+] solved binding

dword ptr [esp+0a8h] => 4f3de0b9h
key_c => O0d6h

key_b => 1f£6h

key_a => 126ah n

Handler => Oac6h

Solving the Challenge

What we have designed so far is equivalent to a VM's level-tracing tool. Handling
branching statements—(un)conditional jumps, calls—would be required to get
a disassembling-oriented tool. We could build a more complex tool, a sort of
compiler, based on a bytecode disassembler and be able to regenerate native
code. Using a previous example, the tool would process the input:

dword ptr [ESP+0a8h] => dword ptr [ESP+0ach]

to a C-like source:

vm_ctx.reg 2ah = vm_ctx.reg 2bh;

For this sample, we will rely on the tracing feature only. The strategy is
straightforward. We have a good idea of the algorithm implemented by the VM,
so we will use black-box/differential analysis to identify divergence between a
standard Mersenne twister (MT) algorithm and the VM’s. When a divergence
is identified, we will check the trace output.

Let’s again take an example to illustrate this: state initialization of the MT
algorithm. The initialization is implemented by function func2. We will only
look at its inputs/outputs. The state is an array of 624 dwords. Using standard
implementations and the same seed used by the program for a name of six
characters, (3961821h), we get the following:

m Standard implementation—state[1] = 0x968bff6d
m VM’s implementation—state[1] = 0x968e4c84
We look for these values in the trace:

[+] disasm handler 2c2 at 41f056h
[+] analyzing handler at 0x41f056
[+] considering code from 0x41f056 to 0x41f165

---

**Page 225**

Chapter 5= Obfuscation 335

[+] cached handler binding

byte ptr [esp+0dh] => byte ptr [dword ptr [esp+4*(dword ptr
[4*key_b+43600ch] *(dword ptr [4*key_c+43600ch] “dword ptr
[4*key_a+43600ch] ))+140h]] &0ffh
dword ptr [dword ptr [esp+4*(dword ptr [4*key_b+436000h] *(dword ptr
[4*key_c+436000h] *dword ptr [4*key_a+436000h]))+140h]] => dword ptr [dword
ptr
[esp+4* (dword ptr [4*key_b+436004h] * (dword ptr [4*key_c+436004h] *dword ptr
[4*key_ a+436004h] ))+140h]]*dword ptr [dword ptr [esp+4*(dword ptr
[4*key_b+436008h] *(dword ptr [4*key_c+436008h] “dword ptr
[4*key_a+436008h] ))+140h] ]
key_c => key_c+6
key_a => key_a+6
key_b => key _b+6
nHandler => (dword ptr [4*key_b+436010h]*(dword ptr [4*key_c+436010h] *dword
ptr
[4*key_a+436010h] ))+(((dword ptr [4*key_c+436014h] * (dword ptr
[4*key_b+436014h] *dword ptr [4*key_a+436014h]))*(byte ptr [dword ptr
[esp+4* (dword ptr [4*key_b+43600ch] * (dword ptr [4*key_c+43600ch] *dword ptr
[4*key_a+43600ch] ))+140h]]&0ffh) ) <OffLLLELELh)

[+] symbolic binding

byte ptr [esp+0dh] => flag2&0ffh

dword ptr [esp+100h] => dword ptr [esp+9ch]“dword ptr [esp+10ch]
key_c => 10e2h

key_a => 12b3h

key_b => Oc8ah

nHandler => ((164h* (flag2&0ffh) ) <OffLLLLELH) +0a53h

[+] solved binding

byte ptr [esp+0dh] => 1

dword ptr [esp+100h] => 968e4c84h
key_c => 10e2h

key_a => 12b3h

key_b => Oc8ah

We have a xor operation between dword ptr [ESP+9ch] and dword ptr
[ESP+10ch]. We can check from the context their values:

[+] context dump

[...]

dword ptr [esp+9ch] => 968bff6dh
dword ptr [esp+10ch] => 5b3e9h
[...]

This handler has a xor-like semantics and is included within one of the loops
previously identified (one with 624 iterations, the size of the MT state). There
are a few more steps to recover the full transformation, but this approach is
sufficient. Its pseudo-code would be as follows:

scramble = 0x5b3e9h
for i in (N-1)

state[i+1] *= scramble

---

**Page 226**

336

Chapter 5 = Obfuscation

scramble = lcg rand(scramble)

with Nn being the size of the state: 624. 1cg_rand is a linear congruential generator
Xn41 = (ax, + c) (mod m), with a, c, and m respectively equal to 0x159b, 0x13e8b,
and oxffffffFe.

The rest of the Mersenne twister algorithm is also lightly modified; each of
these tweaks involves the first letter of the username and a simple operation
apD/suB/xoR. We will not say more about these tweaks; please refer to the fol-
lowing “Exercises” section.

1”

m Username—” Hell yeah, we have tools
m Serial number—”117538a51905ddf6”

Final Thoughts

That sample is a great playground, nicely crafted by its author. We have used an
interesting combination of dynamic and static analysis to work through it. The
protection implements code-flattening, code virtualization, and data encoding,
concepts that can be found in most professional-grade protection systems, and
yet it is still accessible. It provides a useful template for sharpening tools and
experimenting with new ideas and/or algorithms. The simplicity of the protection
scheme and the algorithm enabled us to take many shortcuts for this section.

Exercises

The first exercise we propose to you is to keygen this chapter's case study binary.
This is a great starting point:

m The binary is unique, relatively small, and easy to analyze, disassemble,
and instrument. Thus, this is an accessible challenge even for beginners.

m Most of the important implemented techniques have been described in the
case study. Look for them and ensure that you understand their internals.

After reading this chapter, getting your own hands on the challenge would
be an invaluable experience. Your task is as follows:

1. Based on the proposed methodology (or one you come up with), build
your own tool to analyze the VM’s bytecode.

2. Contact your favorite demo division and package a stunning keygen for
this fine crackme.

To familiarize yourself with Metasm, you'll find two exercise scripts with the
material shipped with the book: symbolic-execution-lvl1l.rb and symbolic-
execution-lv1l2.rb. Answering the questions will lead you to a journey in

---

**Page 227**

Chapter 5 = Obfuscation

337

Metasm internals. You can find the scripts at www.wiley.com/go/practical-

reverseengineering.com.

Notes

10.

. Bansal, Sorav and Aiken, Alex. “Automatic Generation of Peephole

Superoptimizers,” 2006, http: //theory.stanford.edu/~sbansal/pubs/
asplos06.pdf.

Barak, Boaz et al., “On the (Im)possibility of Obfuscating Programs.”
Technical report, Electronic Colloquium on Computational Complexity,
2001. http//www.eccc.uni-trier.de/eccc.

Beckman, Lennart et al., “A Partial Evaluator, and Its Use as a Programming
Tool,” Artificial Intelligence, Volume 7, Issue 4, pp. 319-357, 1976.

Bellard, Fabrice. “QEMU, a Fast and Portable Dynamic Translator.” Paper
presented at the Proceedings of the USENIX Annual Technical Conference,
FREENIX Track, 41-46, 2005.

Billet, Olivier, Gilbert, Henri, and Ech-Chatbi, Charaf. “Cryptanalysis of a
White Box AES Implementation.” In Selected Areas in Cryptography, edited
by Helena Handschuh and M. Anwar Hasan, 227-240. Springer, 2004.

Boyer, R. S., Elspas, B., and Levitt, K. N. SELECT - A Formal System for
Testing and Debugging Programs by Symbolic Execution. SIGPLAN Not.,
10:234—245, 1975.

Chipounov, V. and Candea, G. “Enabling Sophisticated Analyses of x86
Binaries with RevGen.” Paper presented at the Dependable Systems
and Networks Workshops (DSN-W), 2011 IEEE/IFIP 41st International
Conference, 211-216, 2011.

Chipounov, V., Kuznetsov, V. and Candea, G. “S2e: A Platform for In-vivo
Multi-path Analysis of Software Systems,” ACM SIGARCH Computer
Architecture News, vol. 39, no. 1, 265-278, 2011.

Chow, S., Eisen, P. A., Johnson, H., and van Oorschot, P. C. A White-Box
DES Implementation for DRM Applications. In Security and Privacy in
Digital Rights Management, ACM CCS-9 Workshop, DRM 2002, Washington,
DC, USA, November 18, 2002, Revised Papers, volume 2696 of Lecture
Notes in Computer Science, 1-15. Springer, 2002.

Chow, S., Eisen, P. A., Johnson, H., and van Oorschot, P. C. White-Box
Cryptography and an AES Implementation. In Selected Areas in Cryptography,
volume 2595 of Lecture Notes in Computer Science, 250-270. Springer,
2002.

---

**Page 228**

338

Chapter 5 = Obfuscation

11

12.

13.

14.

15.

16.

17.

18.

19.
20.

21.

22.

23.

Chow, Stanley T., Johnson, Harold J., and Gu, Yuan. Tamper Resistant
Software Encoding, 2003.

Collberg, Christian, Thomborson, Clark, and Low, Douglas. A Taxonomy
of Obfuscating Transformations. Technical report, 1997.

Collberg, Christian S., Thomborson, Clark D., and Low, Douglas.
“Manufacturing Cheap, Resilient, and Stealthy Opaque Constructs.” In
POPL, 184-196, 1998.

Cousot, P. and Cousot, R. “Abstract Interpretation: A Unified Lattice
Model for Static Analysis of Programs by Construction or Approximation
of Fixpoints.” In Conference Record of the 4th ACM Symp. on Principles
of Programming Languages (POPL ’77), 238-252. ACM Press, New York,
1977.

Cousot, P. and Cousot, R. “Systematic Design of Program Transformation
Frameworks by Abstract Interpretation. In Conference Record of the
Twenty-Ninth Annual ACM SIGPLAN-SIGACT Symposium on Principles
of Programming Languages, 178-190. New York, 2002. ACM Press.

Cousot, P. “Constructive Design of a Hierarchy of Semantics of a Transition
System by Abstract Interpretation. ENTCS, 6, 1997.

Dalla Preda, Mila. “Code Obfuscation and Malware Detection by Abstract
Interpretation,” (PhD diss.), http: //profs.sci.univr.it/~dallapre/
MilaDallaPreda_PhD.pdf.

Dalla Preda, Mila. and Giacobazzi, Roberto. “Control Code Obfuscation by
Abstract Interpretation.” In Third IEEE International Conference on Software
Engineering and Formal Methods, 301-310, 2005.

Deroko. Nanomites.w32. http: //deroko.phearless.org/nanomites. zip.

Ernst, Michael D. Static and Dynamic Analysis: Synergy and Duality.”
In Proceedings of WODA 2003: Workshop on Dynamic Analysis, Portland,
Oregon, 24-27, May 2003.

Futamura, Yoshihiko. “Partial Evaluation of Computation Process - An
Approach to a Compiler-Compiler,” 1999. http: //cs.au.dk/~hosc/local/
HOSC-12-4-pp381-391.pdf.

Gazet, Alexandre and Guillot, Yoann. “Defeating Software Protection with
Metasm. In HITB Malaysia, Kuala Lumpur, 2009. http: //metasm.cr0.org/
docs/2009-guillot-gazet-hitb-deprotection.pdf.

Godefroid, P., Klarlund, N., and Sen, K. “DART: Directed Automated
Random Testing.” In PLDI ’05, June 2005.

---

**Page 229**

Chapter 5 = Obfuscation

339

24.

25.

26.

27.

28.

29.

30.

31.

32.

33.

34.

35.

36.

37.

Goubin, L., Masereel, J. M., and Quisquater, M. “Cryptanalysis of White
Box DES Implementations.” Cryptology ePrint Archive, Report 2007/035,
2007.

Jacob, Matthias et al. “The Superdiversifier: Peephole Individualization
for Software Protection.” 2008. http: //research.microsoft.com/apps/
pubs/default.aspx?id=77265.

Jakubowski, Marius H. et al. “Iterated Transformations and Quantitatives
Metrics for Software Protection,” 2009. http: //research.microsoft .com/
apps/pubs/default.aspx?id=81560.

Josse, S. “Secure and Advanced Unpacking using Computer Emulation.”
In Proceedings of the AVAR 2006 Conference, Auckland, New Zealand,
December 3-5, 174-190, 2006.

Josse, S. “Rootkit Detection from Outside the Matrix.” Journal in Computer
Virology, vol. 3, 113-123. Springer, 2007.

Josse, S. “Dynamic Malware Recompilation.” In IEEE Proceedings of the
47th HICSS Conference, 2014.

Kinder, Johannes, Zuleger, Florian, and Veith, Helmut. “An Abstract
Interpretation-Based Framework for Control Flow Reconstruction from
Binaries.” 2009. http: //pure.rhul.ac.uk/portal/files/17558147/
vmcai09.pdf.

Lattner, C. and Adve, V. “LLVM: A Compilation Framework for Lifelong
Program Analysis & Transformation.” In International Symposium on
Code Generation and Optimization, 75-86, 2004.

Maximus. “Reversing a Simple Virtual Machine.” 2006. http: //tuts4you.
com/ download.php?view.210.

Maximus. “Virtual Machines Re-building.” 2006. http: //tuts4you.com/
download. php?view.1229.

Rolles, Rolf. “Finding Bugs in VMs with a Theorem Prover,
Round 1.” http://www.openrce.org/blog/view/1963/
Finding Bugs in VMs with_a_heorem Prover, Round_l.
Rolles, Rolf. “Defeating HyperUnpackMe2 With an IDA Processor Module,”
2006. http: //www.openrce.org/articles/full_view/28.

Scheller, T. “Llvm-qemu, Backend for QEMU using LLVM Components,”
Google Summer of Code 2007. http: //code.google.com/p/11lvm-gemu/.

Sen, K., Marinov, D., and Agha, G. “CUTE: A Concolic Unit Testing Engine
for C.” In ESEC/FSE ’05, Sep 2005.

---

**Page 230**

340

Chapter 5 = Obfuscation

38.

39.

40.

41.

42.

43.

44.

Smaragdakis, Yannis and Csallner, Christoph. “Combining Static and
Dynamic Reasoning for Bug Detection.” In Proceedings of International
Conference on Tests and Proofs (TAP), LNCS vol. 4454, 1-16, Springer,
2007.

Smithson, Matt et al. “A Compiler-level Intermediate Representation Based
Binary Analysis and Rewriting System.” In MALWARE, 47-54, 2010.

Song, Dawn et al. “BitBlaze: A New Approach to Computer Security via
Binary Analysis.” In Proceedings of the 4th International Conference on
Information Systems Security, Hyderabad, India, 2008.

Thakur, A. et al. “Directed Proof Generation for Machine Code.” 2010.

http://research.cs.wisc.edu/wpis/papers/cavl10-mceveto.pdf.

Weiser, M., “Program Slices: Formal, Psychological, and Practical
Investigations of an Automatic Program Abstraction Method (PhD diss.,
University of Michigan, Ann Arbor, 1979).

Zhao, J. et al, “Formalizing the LLVM Intermediate Representation for
Verified Program Transformations.” In Proceedings of the 39th Annual
ACM SIGPLAN-SIGACT Symposium on Principles of Programming
Languages, 427-440, 2012.

Zhu, William and Thomborson, Clark. “A Provable Scheme for Homomorphic
Obfuscation in Software Security.” In CNIS, 208-212. ACTA Press, 2005.
