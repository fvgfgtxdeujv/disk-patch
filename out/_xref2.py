import numpy as np, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x140000000
B = open(r'out\moddump_140000000.bin', 'rb').read()
arr = np.frombuffer(B, dtype=np.uint8)
N = len(arr)
md = Cs(CS_ARCH_X86, CS_MODE_64)

TARGETS = {
    0x1406a1328: 'Options.ini',
    0x1406b3590: 'Remind',
    0x1406b35a0: 'LicenseInfo',
    0x1406b35d8: 'VerifyDate',
    0x1406b35f0: 'license',
    0x1406b3660: 'appname',
    0x1406b3670: 'user',
    0x1406b3680: 'email',
    0x1406b3690: 'regcode',
    0x1406b36a0: 'regver',
    0x1406b37b8: '&check=',
    0x1406b3898: '&skey=',
    0x1406b38a8: 'OfflineReg.dat',
}

idx = np.arange(N - 8, dtype=np.int64)
modrm_ok = (arr[idx] & 0xC7) == 0x05
pos = idx[modrm_ok]
print('candidate modrm positions', len(pos))

for T, name in TARGETS.items():
    exp = np.uint32((T - BASE - 5 - pos.astype(np.int64)) & 0xffffffff)
    d = (arr[pos + 1].astype(np.uint32) | (arr[pos + 2].astype(np.uint32) << 8)
         | (arr[pos + 3].astype(np.uint32) << 16) | (arr[pos + 4].astype(np.uint32) << 24))
    cand = pos[d == exp]
    out = []
    for i in cand:
        for back in range(1, 5):
            s = int(i) - back
            if s < 0:
                continue
            va = BASE + s
            ins = next(md.disasm(B[s:s + 12], va, 1), None)
            if ins and ins.size == back + 5 and 'rip' in ins.op_str and ('%x' % T) in ins.op_str:
                out.append((va, ins.mnemonic + ' ' + ins.op_str))
                break
    if out:
        print('==', name, hex(T))
        for va, txt in sorted(set(out)):
            print('  %x  %s' % (va, txt))
