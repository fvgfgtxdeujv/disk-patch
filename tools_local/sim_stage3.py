# -*- coding: utf-8 -*-
"""第三阶段：按函数名模拟 Win32 API，让 VM 真正启动。
   关键观测：
     * 数据段（0x62F000/0x7BE000/0x9A3000）是否被读写 —— 说明第二层解密发生
     * `movzx rX, word [rY]` 的 rY 轨迹 —— 那就是 VM 字节流指针
     * 写出的完整内存镜像（可直接用 IDA 加载）
"""
import struct, collections, sys
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_MEM_WRITE,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED)
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_GS_BASE,
                               UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSI)

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


def rva2off(rva):
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
            return s['rp'] + (rva - s['va'])
    return None


mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(IB, (size_of_image + 0xFFFFF) & ~0xFFFFF)
for s in secs:
    if s['rs']:
        mu.mem_write(IB + s['va'], pe[s['rp']:s['rp'] + s['rs']])

# 假 TEB / PEB
TEB, PEB, GS = 0x50000000, 0x50001000, 0x50002000
mu.mem_map(0x50000000, 0x10000)
mu.mem_write(TEB + 0x30, struct.pack('<Q', PEB))
mu.mem_write(TEB + 0x08, struct.pack('<Q', 0x40000000 + 0x300000))
mu.mem_write(TEB + 0x10, struct.pack('<Q', 0x40000000))
mu.mem_write(TEB + 0x40, struct.pack('<I', 0x1234))
mu.mem_write(TEB + 0x48, struct.pack('<I', 0x1234))
mu.mem_write(TEB + 0x60, struct.pack('<I', 0))          # LastErrorValue
mu.mem_write(PEB + 0x02, b'\x00')
mu.mem_write(PEB + 0xBC, struct.pack('<I', 0))
mu.mem_write(PEB + 0x08, struct.pack('<Q', IB))
mu.mem_write(GS, struct.pack('<Q', TEB))

# 每个导入一个独立 stub
STUB_BASE = 0x60000000
mu.mem_map(STUB_BASE, 0x40000)
STUB = {}
name2stub = {}

imp_rva = struct.unpack_from('<I', pe, opt + 0x78)[0]
o = rva2off(imp_rva)
idx = 0
while o and o + 20 <= len(pe):
    ilt, ts, fc, name_rva, iat = struct.unpack_from('<IIIII', pe, o)
    if not (ilt or name_rva or iat):
        break
    if iat:
        thunk = ilt or iat
        k = 0
        while True:
            v = struct.unpack_from('<Q', pe, rva2off(thunk) + k * 8)[0]
            if v == 0:
                break
            if not (v >> 63):
                no = rva2off(v)
                nm = pe[no + 2:pe.index(b'\0', no + 2)].decode('latin1')
            else:
                nm = 'ord_%d' % (v & 0xFFFF)
            stub = STUB_BASE + idx * 16
            idx += 1
            mu.mem_write(stub, b'\xc3' + b'\x00' * 15)
            STUB[stub] = nm
            name2stub.setdefault(nm, stub)
            mu.mem_write(IB + iat + k * 8, struct.pack('<Q', stub))
            k += 1
    o += 20

print('[*] 导入函数 %d 个：%s' % (len(STUB), ', '.join(sorted(set(STUB.values()))[:40])))

# 通用返回桩（GetProcAddress 的返回目标）
GEN = STUB_BASE + 0x30000
mu.mem_write(GEN, b'\x31\xc0\xc3' + b'\x00' * 13)

heap_top = [0x20000000]
reads_seg = collections.Counter()
ip_samples = []


def seg_name(rva):
    if 0x62F000 <= rva < 0x7BE000: return 'seg2_62F000'
    if 0x7BE000 <= rva < 0x9A3000: return 'seg3_7BE000'
    if 0x9A3000 <= rva < 0x199F000: return 'seg4_9A3000'
    if 0x19D4000 <= rva < 0x2780000: return '.vmp'
    if 0x2780000 <= rva < 0x2FF2000: return '.boot'
    return None


def api(name, mu):
    n = name.lower()
    if 'virtualalloc' in n or 'heapalloc' in n or n in ('malloc',) or 'new' == n:
        a = heap_top[0]
        try:
            mu.mem_map(a, 0x100000)
        except Exception:
            pass
        heap_top[0] += 0x100000
        return a
    if 'getmodulehandle' in n or 'loadlibrary' in n or 'getmodulefilename' in n:
        return IB
    if 'getprocaddress' in n:
        return GEN
    if 'virtualprotect' in n or 'flushinstructioncache' in n or 'closehandle' in n:
        return 1
    if 'getcurrentprocess' in n:
        return 0xFFFFFFFFFFFFFFFF
    if 'createthread' in n or 'createmutex' in n or 'createevent' in n:
        return 0x1000
    if 'queryperformancecounter' in n or 'gettickcount' in n:
        return 0x10000
    return 1


writes = collections.Counter()
n_code = [0]
calls = collections.Counter()


def hcode(mu, addr, size, user):
    n_code[0] += 1
    if addr in STUB:
        nm = STUB[addr]
        calls[nm] += 1
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret)
        mu.reg_write(UC_X86_REG_RAX, api(nm, mu))
        return
    # 记录「读 opcode」的形态：movzx rX, word [rY]
    rva = addr - IB
    if 0x19D4000 <= rva < 0x2FF2000:
        try:
            b = mu.mem_read(addr, 4)
        except Exception:
            return
        if len(b) >= 3 and b[0] == 0x0F and b[1] == 0xB7:
            try:
                ptr = mu.reg_read(UC_X86_REG_RSI)
            except Exception:
                ptr = 0
            if len(ip_samples) < 40:
                ip_samples.append((addr, ptr))


def hw(mu, access, addr, size, value, user):
    writes[(addr - IB) >> 16] += size


def hru(mu, access, addr, size, value, user):
    rva = addr - IB
    s = seg_name(rva) if rva >= 0 else None
    if s:
        reads_seg[s] += 1
    return False


mu.hook_add(UC_HOOK_CODE, hcode)
mu.hook_add(UC_HOOK_MEM_WRITE, hw)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hru)

STACK = 0x40000000
mu.mem_map(STACK, 0x400000)
rsp = STACK + 0x300000
SENT = 0x1000
mu.mem_map(SENT, 0x2000)
mu.mem_write(SENT, b'\xf4' * 0x1000)
mu.mem_write(rsp, struct.pack('<Q', SENT))
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.reg_write(UC_X86_REG_GS_BASE, GS)

print('[*] 开始模拟')
try:
    mu.emu_start(IB + ep, SENT, count=400_000_000, timeout=1500 * 1000 * 1000)
    print('[*] 正常结束')
except UcError as e:
    print('[!] 中断: %s' % e)

rip = mu.reg_read(UC_X86_REG_RIP)
print('[i] 指令数 %d  RIP RVA %#x' % (n_code[0], rip - IB))
print('[i] API 调用 Top15:', calls.most_common(15))
print('[i] 数据段读命中:', dict(reads_seg))
print('[i] opcode 读样本（前 10）：')
for a, p in ip_samples[:10]:
    print('     %#x  rsi=%#x  -> %s' % (a, p, seg_name(p - IB) if IB <= p < IB + size_of_image else 'oob'))

print('\n[i] 写入区间 Top12：')
for k, v in writes.most_common(12):
    print('   RVA ~%#09x : %d%s' % (k << 16, v, ' [%s]' % seg_name(k << 16) if seg_name(k << 16) else ''))

# 落盘镜像
img = bytes(mu.mem_read(IB, size_of_image))
open('/workspace/dgwork/stage2_image.bin', 'wb').write(img)
print('\n[+] 已写 stage2_image.bin (%d 字节)' % len(img))
