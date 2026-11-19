# -*- coding: utf-8 -*-
"""在第一层解压基础上继续模拟，记录：写入区间分布、崩溃点 RIP、RIP 轨迹尾部。
   目的：找到「谁解密 0x62F000 数据段」以及解压完成后跳到哪。
"""
import struct, collections
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RDX, UC_X86_REG_RIP,
                               UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX)

IB = 0x140000000
EXE = '/workspace/dgwork/dgpkg/DiskGenius/DiskGenius.exe'
pe = open(EXE, 'rb').read()

pe_off = struct.unpack_from('<I', pe, 0x3c)[0]
nsec = struct.unpack_from('<H', pe, pe_off + 6)[0]
opt = pe_off + 24
ep = struct.unpack_from('<I', pe, opt + 16)[0]
ib = struct.unpack_from('<Q', pe, opt + 24)[0]
tbl = opt + struct.unpack_from('<H', pe, pe_off + 20)[0]
secs = []
for i in range(nsec):
    s = tbl + i * 40
    name = pe[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
    vs, va, rs, rp = struct.unpack_from('<IIII', pe, s + 8)
    secs.append(dict(name=name, va=va, vs=vs, rs=rs, rp=rp))

size_of_image = max(s['va'] + max(s['vs'], s['rs']) for s in secs)
size_of_image = (size_of_image + 0xFFF) & ~0xFFF
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(ib, (size_of_image + 0xFFFFF) & ~0xFFFFF)
for s in secs:
    if s['rs']:
        mu.mem_write(ib + s['va'], pe[s['rp']:s['rp'] + s['rs']])

STACK = 0x40000000
mu.mem_map(STACK, 0x400000)
rsp = STACK + 0x200000
# 返回地址：一个可执行哨兵，落到就停
SENT = 0x1000
mu.mem_map(SENT, 0x3000)
mu.mem_write(SENT, b'\xcc' * 0x1000)
mu.mem_write(rsp, struct.pack('<Q', SENT))
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.reg_write(UC_X86_REG_RDX, 0)

writes = collections.Counter()
rip_tail = collections.deque(maxlen=40)
n_code = [0]
last_rip = [0]


def hw(mu, access, addr, size, value, user):
    writes[(addr - ib) >> 16] += size


def hc(mu, addr, size, user):
    n_code[0] += 1
    last_rip[0] = addr
    if len(rip_tail) == 0 or addr != rip_tail[-1]:
        rip_tail.append(addr)


mu.hook_add(UC_HOOK_MEM_WRITE, hw)
mu.hook_add(UC_HOOK_CODE, hc)

print('[*] 开始模拟 EP=%#x' % (ib + ep))
err = None
try:
    mu.emu_start(ib + ep, SENT, count=200_000_000)
    print('[*] 正常到达哨兵')
except UcError as e:
    err = e
    print('[!] 中断: %s' % e)

rip = mu.reg_read(UC_X86_REG_RIP)
print('[i] 执行指令数 %d' % n_code[0])
print('[i] 崩溃/停止处 RIP = %#x (RVA %#x)' % (rip, rip - ib))
print('[i] 最后 20 条 RIP:')
for a in list(rip_tail)[-20:]:
    print('     %#x  RVA %#x' % (a, a - ib))

print('\n[i] 写入区间（64KB 粒度，跳过 .vmp 主区）：')
vmp_lo, vmp_hi = 0x19D4000 >> 16, (0x19D4000 + 0xDAC000) >> 16
for k, v in writes.most_common(30):
    tag = ' [.vmp]' if vmp_lo <= k <= vmp_hi else ''
    print('   RVA ~%#09x : %d 字节%s' % (k << 16, v, tag))
