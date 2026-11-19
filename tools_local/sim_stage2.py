# -*- coding: utf-8 -*-
"""第二阶段模拟：伪造 TEB/PEB + 把 IAT 全接成 RET 桩，看能不能跑到「解密数据段」。
   产出：写入区间统计（重点看 0x62F000 / 0x7BE000 / 0x9A3000 三段）、崩溃点、RIP 轨迹。
"""
import struct, collections
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_MEM_WRITE,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED)
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_GS_BASE

IB = 0x140000000
EXE = '/workspace/dgwork/dgpkg/DiskGenius/DiskGenius.exe'
pe = open(EXE, 'rb').read()

pe_off = struct.unpack_from('<I', pe, 0x3c)[0]
nsec = struct.unpack_from('<H', pe, pe_off + 6)[0]
opt = pe_off + 24
ep = struct.unpack_from('<I', pe, opt + 16)[0]
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
mu.mem_map(IB, (size_of_image + 0xFFFFF) & ~0xFFFFF)
for s in secs:
    if s['rs']:
        mu.mem_write(IB + s['va'], pe[s['rp']:s['rp'] + s['rs']])

# ---- 假 TEB / PEB ----
TEB, PEB, GS = 0x50000000, 0x50001000, 0x50002000
mu.mem_map(0x50000000, 0x10000)
mu.mem_write(TEB + 0x30, struct.pack('<Q', PEB))       # TEB->PEB
mu.mem_write(PEB + 0x02, b'\x00')                       # BeingDebugged = 0
mu.mem_write(PEB + 0xBC, struct.pack('<I', 0))          # NtGlobalFlag = 0
mu.mem_write(PEB + 0x08, struct.pack('<Q', IB))         # ImageBaseAddress
mu.mem_write(TEB + 0x08, struct.pack('<Q', 0x40000000 + 0x200000))  # StackBase
mu.mem_write(TEB + 0x10, struct.pack('<Q', 0x40000000))             # StackLimit
mu.mem_write(TEB + 0x40, struct.pack('<I', 0x1234))     # ClientId.ProcessId
mu.mem_write(TEB + 0x48, struct.pack('<I', 0x1234))     # ClientId.ThreadId

# ---- IAT 全部接成 RET 桩 ----
FAKE = 0x60000000
mu.mem_map(FAKE, 0x20000)
mu.mem_write(FAKE, b'\x31\xc0\xc3' * 0x100)             # xor eax,eax; ret
mu.mem_write(FAKE + 0x10000, b'\xb8\x01\x00\x00\x00\xc3' * 0x100)

# 解析导入表
imp_rva = struct.unpack_from('<I', pe, opt + 0x78)[0]   # DataDirectory[1] = Import


def rva2off(rva):
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
            return s['rp'] + (rva - s['va'])
    return None


n_iat = 0
if imp_rva:
    o = rva2off(imp_rva)
    stub = FAKE
    while o and o + 20 <= len(pe):
        ilt, ts, fc, name_rva, iat = struct.unpack_from('<IIIII', pe, o)
        if not (ilt or name_rva or iat):
            break
        if iat:
            k = 0
            while True:
                v = struct.unpack_from('<Q', pe, rva2off(iat) + k * 8)[0]
                if v == 0:
                    break
                mu.mem_write(IB + iat + k * 8, struct.pack('<Q', stub))
                n_iat += 1
                k += 1
        o += 20
print('[*] 已重定向 IAT 项 %d 个' % n_iat)

# ---- 栈 ----
STACK = 0x40000000
mu.mem_map(STACK, 0x400000)
rsp = STACK + 0x200000
SENT = 0x1000
mu.mem_map(SENT, 0x2000)
mu.mem_write(SENT, b'\xf4' * 0x1000)                    # hlt
mu.mem_write(rsp, struct.pack('<Q', SENT))
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.reg_write(UC_X86_REG_GS_BASE, GS)
mu.mem_write(GS, struct.pack('<Q', TEB))                # gs:0 -> TEB

writes = collections.Counter()
rip_tail = collections.deque(maxlen=60)
n_code = [0]
fault = []


def hw(mu, access, addr, size, value, user):
    writes[(addr - IB) >> 16] += size


def hc(mu, addr, size, user):
    n_code[0] += 1
    rip_tail.append(addr)


def hru(mu, access, addr, size, value, user):
    fault.append(('R', addr))
    return False


def hwu(mu, access, addr, size, value, user):
    fault.append(('W', addr))
    return False


mu.hook_add(UC_HOOK_MEM_WRITE, hw)
mu.hook_add(UC_HOOK_CODE, hc)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hru)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hwu)

print('[*] 开始模拟')
try:
    mu.emu_start(IB + ep, SENT, count=300_000_000, timeout=600 * 1000 * 1000)
    print('[*] 正常结束')
except UcError as e:
    print('[!] 中断: %s' % e)

rip = mu.reg_read(UC_X86_REG_RIP)
print('[i] 指令数 %d   RIP %#x (RVA %#x)' % (n_code[0], rip, rip - IB))
print('[i] 最后 15 条 RIP:')
for a in list(rip_tail)[-15:]:
    print('     %#x  RVA %#x' % (a, a - IB))
if fault:
    print('[i] 未映射访问前 5 条:', fault[:5])
print('\n[i] 写入区间 Top20：')
vmp_lo, vmp_hi = 0x19D4000 >> 16, 0x2780000 >> 16
for k, v in writes.most_common(20):
    tag = ''
    rva = k << 16
    if 0x62F000 <= rva < 0x7BE000: tag = ' [seg2 0x62F000]'
    elif 0x7BE000 <= rva < 0x9A3000: tag = ' [seg3 0x7BE000]'
    elif 0x9A3000 <= rva < 0x199F000: tag = ' [seg4 0x9A3000]'
    elif vmp_lo <= k <= vmp_hi: tag = ' [.vmp]'
    elif 0x2780000 <= rva < 0x2FF2000: tag = ' [.boot]'
    print('   RVA ~%#09x : %d 字节%s' % (rva, v, tag))
