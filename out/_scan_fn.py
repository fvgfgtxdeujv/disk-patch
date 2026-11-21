import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
N = len(B)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def u16s(va, maxlen=80):
    off = va - BASE
    if off < 0 or off + 1 >= N:
        return None
    o = []
    for k in range(0, maxlen * 2, 2):
        if off + k + 1 >= N:
            break
        c = B[off + k] | (B[off + k + 1] << 8)
        if c == 0:
            break
        if c < 0x20 or c > 0x7e:
            return None
        o.append(chr(c))
    return ''.join(o) if o else None

def scan(va, end, label):
    print('#### %s %x-%x' % (label, va, end))
    for ins in md.disasm(B[va - BASE: end - BASE], va):
        line = None
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                s = u16s(t)
                line = '%x lea/mem %s -> %x %r' % (ins.address, ins.op_str, t, s)
        if ins.mnemonic == 'call':
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                line = '%x call %x' % (ins.address, op.imm)
            else:
                line = '%x call %s' % (ins.address, ins.op_str)
        if ins.mnemonic in ('cmp', 'test') and ins.operands and ins.operands[-1].type == X86_OP_IMM:
            line = '%x %s %s' % (ins.address, ins.mnemonic, ins.op_str)
        if ins.mnemonic.startswith('j') and ins.mnemonic != 'jmp':
            line = line or '%x %s %s' % (ins.address, ins.mnemonic, ins.op_str)
        if line:
            print(line)

scan(0x1400d6a50, 0x1400d7209, 'lic_cfg_a')
scan(0x140113c80, 0x140113ccc, 'small1')
scan(0x140159cfc, 0x140159e84, 'small2')
scan(0x1400d8168, 0x1400d85b7, 'skey_fn')
scan(0x1400d85b8, 0x1400d8983, 'dat_fn')
