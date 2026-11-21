import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM
BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
def u16s(va, m=140):
    o = va - BASE; s = []
    for k in range(0, m*2, 2):
        c = B[o+k] | (B[o+k+1] << 8)
        if c == 0 or c > 0x7e or c < 0x20: break
        s.append(chr(c))
    return ''.join(s) if s else None
def u8s(va, m=140):
    o = va - BASE
    if B[o:o+2] == b'\x00\x00': return None
    s = []
    for k in range(m):
        c = B[o+k]
        if c == 0 or c > 0x7e or c < 0x20: break
        s.append(chr(c))
    return ''.join(s) if s else None
f = open(r'out\_regfn.txt', 'w', encoding='utf-8')
def dis(a, b, lab):
    f.write('==== %s %x-%x\n' % (lab, a, b))
    for ins in md.disasm(B[a-BASE:b-BASE], a):
        note = ''
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                note += '   ; %x %r %r' % (t, u16s(t), u8s(t))
            elif op.type == X86_OP_IMM and BASE <= op.imm < BASE + N:
                s = u16s(op.imm) or u8s(op.imm)
                if s: note += '   ; %x %r' % (op.imm, s)
        f.write('%x %-8s %-44s%s\n' % (ins.address, ins.mnemonic, ins.op_str, note))
dis(0x1400d8c00, 0x1400d9269, 'DoRegister?')
f.close()
print('ok')
