import re, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
print('size', len(B))

# 1) strings in pool
lo, hi = 0x6a0000, 0x6c0000
pat = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
for m in pat.finditer(B[lo:hi]):
    s = m.group().decode('utf-16-le')
    if any(k in s.lower() for k in ('license', 'reg', 'appname', 'options', 'verify', 'key', 'user', 'email', 'check', 'skey', 'encryption', 'mid')):
        print('U16', hex(BASE + lo + m.start()), repr(s))
apat = re.compile(rb'[\x20-\x7e]{4,}')
for m in apat.finditer(B[lo:hi]):
    s = m.group().decode('latin1')
    if any(k in s.lower() for k in ('license', 'appname', 'options', 'regver', 'skey', 'encryption')):
        print('ASC', hex(BASE + lo + m.start()), repr(s))

# 2) rip-relative xrefs to a set of targets
targets = {}
for m in pat.finditer(B[lo:hi]):
    s = m.group().decode('utf-16-le')
    if any(k in s for k in ('license', 'LicenseInfo', 'Options.ini', 'regver', 'appname=', '&skey', 'encryption=', 'VerifyDate', 'Remind')):
        targets[BASE + lo + m.start()] = s
print('targets', {hex(k): v for k, v in targets.items()})

md = Cs(CS_ARCH_X86, CS_MODE_64)
code_sections = [(0x1000, 0x2e2400), (0x62f000, 0x73c00), (0x7be000, 0x88e00), (0x9a3000, 0x353000)]

hits = []
for off, size in code_sections:
    blob = B[off:off + size]
    for i in range(len(blob) - 8):
        if (blob[i] & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from('<i', blob, i + 1)[0]
        tgt = BASE + off + i + 5 + disp
        if tgt not in targets:
            continue
        for back in range(1, 5):
            s = i - back
            if s < 0:
                continue
            va = BASE + off + s
            ins = next(md.disasm(blob[s:s + 12], va, 1), None)
            if not ins or ins.size != back + 5:
                continue
            if 'rip' in ins.op_str and (('%x' % tgt) in ins.op_str):
                hits.append((va, ins.mnemonic + ' ' + ins.op_str, targets[tgt]))
                break
for h in sorted(set(hits)):
    print('XREF %x  %-50s -> %r' % (h[0], h[1], h[2]))
print('total', len(set(hits)))
