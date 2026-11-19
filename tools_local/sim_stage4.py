# -*- coding: utf-8 -*-
"""第四阶段：构造可被壳「自解析」的假 kernel32/ntdll（PEB->Ldr 链 + 导出表），
   让壳能自己找到 LoadLibraryA / GetProcAddress / VirtualAlloc，从而跑过初始化。
"""
import struct, collections
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_MEM_WRITE,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED)
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_GS_BASE,
                               UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSI, UC_X86_REG_RDI)

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

# ---------- API 桩 ----------
STUB_BASE = 0x60000000
mu.mem_map(STUB_BASE, 0x100000)
STUB = {}
name2stub = {}
GEN = STUB_BASE + 0xF0000
mu.mem_write(GEN, b'\x31\xc0\xc3')

EXPORTS = ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'GetProcAddress',
           'GetModuleHandleA', 'GetModuleHandleW', 'VirtualAlloc', 'VirtualFree',
           'VirtualProtect', 'GetModuleFileNameA', 'GetModuleFileNameW',
           'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThreadId',
           'GetSystemTimeAsFileTime', 'QueryPerformanceCounter', 'GetTickCount',
           'Sleep', 'ExitProcess', 'HeapAlloc', 'HeapCreate', 'HeapFree',
           'GetLastError', 'SetLastError', 'InitializeCriticalSection',
           'EnterCriticalSection', 'LeaveCriticalSection',
           'DeleteCriticalSection', 'CloseHandle', 'CreateFileW', 'ReadFile',
           'WriteFile', 'GetFileSize', 'SetFilePointer']

for i, nm in enumerate(EXPORTS):
    st = STUB_BASE + i * 16
    mu.mem_write(st, b'\x31\xc0\xc3' + b'\x00' * 13)
    STUB[st] = nm
    name2stub[nm] = st


# ---- 把导入表接到桩上（ilt 常为 0，用 iat 当 thunk）----
imp_rva = struct.unpack_from('<I', pe, opt + 0x78)[0]
o = rva2off(imp_rva)
n_iat = 0
while o and o + 20 <= len(pe):
    ilt, ts, fc, nr, iat = struct.unpack_from('<IIIII', pe, o)
    if not (ilt or nr or iat):
        break
    if iat:
        thunk = ilt or iat
        k = 0
        while True:
            v = struct.unpack_from('<Q', pe, rva2off(thunk) + k * 8)[0]
            if v == 0:
                break
            if v >> 63:
                nm = 'ord_%d' % (v & 0xFFFF)
            else:
                no = rva2off(v)
                nm = pe[no + 2:pe.index(b'\0', no + 2)].decode('latin1')
            mu.mem_write(IB + iat + k * 8, struct.pack('<Q', name2stub.get(nm, GEN)))
            n_iat += 1
            k += 1
    o += 20
print('[*] IAT 重定向 %d 项' % n_iat)


def build_fake_dll(base, dllname, exports):
    """构造最小可用 PE：DOS+NT 头 + 一个 .text + 导出目录（按名字排序）。"""
    PAGE = 0x10000
    mu.mem_map(base, PAGE)
    blob = bytearray(PAGE)
    e_lfanew = 0x80
    struct.pack_into('<H', blob, 0, 0x5A4D)
    struct.pack_into('<I', blob, 0x3C, e_lfanew)
    struct.pack_into('<I', blob, e_lfanew, 0x00004550)
    cof = e_lfanew + 4
    struct.pack_into('<HHIIIHH', blob, cof, 0x8664, 1, 0, 0, 0, 0xE0, 0x2022)
    o = cof + 20
    struct.pack_into('<H', blob, o, 0x20B)
    struct.pack_into('<Q', blob, o + 24, base)         # ImageBase
    struct.pack_into('<I', blob, o + 16, 0x1000)       # AddressOfEntryPoint
    struct.pack_into('<I', blob, o + 32, 0x1000)       # SectionAlignment
    struct.pack_into('<I', blob, o + 36, 0x1000)       # FileAlignment
    struct.pack_into('<I', blob, o + 56, 0x2000)       # SizeOfImage
    struct.pack_into('<I', blob, o + 60, 0x400)        # SizeOfHeaders
    struct.pack_into('<I', blob, o + 108, 16)          # NumberOfRvaAndSizes
    exp_rva = 0x1000
    struct.pack_into('<II', blob, o + 112, exp_rva, 0x200)   # DataDirectory[0]

    names = sorted(exports)
    n = len(names)
    # 布局：导出目录 0x1000，EAT 0x1040，ENT 0x1040+4n，EOT 0x1040+8n，字符串 0x1100
    eat = 0x1040
    ent = eat + 4 * n
    eot = ent + 4 * n
    strbase = 0x1200
    struct.pack_into('<IIHHIIIIIII', blob, exp_rva, 0, 0, 0, 0, 0, 1, n, n,
                     eat, ent, eot)
    stroff = strbase
    for i, nm in enumerate(names):
        st = name2stub.get(nm)
        if st is None:
            st = STUB_BASE + len(STUB) * 16
            mu.mem_write(st, b'\x31\xc0\xc3' + b'\x00' * 13)
            STUB[st] = nm
            name2stub[nm] = st
        struct.pack_into('<I', blob, eat + 4 * i, (st - base) if st >= base else st)
        struct.pack_into('<I', blob, ent + 4 * i, stroff)
        struct.pack_into('<H', blob, eot + 2 * i, i)
        b = nm.encode() + b'\0'
        blob[stroff:stroff + len(b)] = b
        stroff += len(b)
    # 名字写 UNICODE_STRING
    return bytes(blob), names


K32_BASE = 0x70000000
NTD_BASE = 0x70100000
k32, k32names = build_fake_dll(K32_BASE, 'kernel32.dll', EXPORTS)
ntd, ntdnames = build_fake_dll(NTD_BASE, 'ntdll.dll', ['NtQueryInformationProcess', 'RtlGetVersion'])
mu.mem_write(K32_BASE, k32)
mu.mem_write(NTD_BASE, ntd)

# ---------- PEB / Ldr ----------
TEB, PEB, GS = 0x50000000, 0x50001000, 0x50002000
LDR = 0x50010000
ENT1, ENT2 = 0x50011000, 0x50012000      # ntdll, kernel32
mu.mem_map(0x50000000, 0x20000)
mu.mem_write(TEB + 0x30, struct.pack('<Q', PEB))
mu.mem_write(TEB + 0x08, struct.pack('<Q', 0x40000000 + 0x300000))
mu.mem_write(TEB + 0x10, struct.pack('<Q', 0x40000000))
mu.mem_write(TEB + 0x40, struct.pack('<I', 0x1234))
mu.mem_write(TEB + 0x48, struct.pack('<I', 0x1234))
mu.mem_write(PEB + 0x02, b'\x00')
mu.mem_write(PEB + 0xBC, struct.pack('<I', 0))
mu.mem_write(PEB + 0x08, struct.pack('<Q', IB))
mu.mem_write(PEB + 0x18, struct.pack('<Q', LDR))
mu.mem_write(GS, struct.pack('<Q', TEB))

mu.mem_write(LDR, struct.pack('<I', 0x100))
# InLoadOrderModuleList 在 +0x10，InMemoryOrder +0x20，InInit +0x30
off_ildr, off_imem, off_iini = 0x10, 0x20, 0x30


def name_us(addr, s):
    b = s.encode('utf-16-le')
    mu.mem_write(addr, struct.pack('<HHI', len(b), len(b) + 2, 0))
    BUF = addr + 0x100
    mu.mem_write(BUF, b + b'\0\0')
    mu.mem_write(addr + 8, struct.pack('<Q', BUF))


# 条目字段：DllBase +0x30, EntryPoint +0x38, SizeOfImage +0x40, FullDllName +0x48, BaseDllName +0x58
for ent, base, nm, sz in ((ENT1, NTD_BASE, 'ntdll.dll', 0x2000),
                          (ENT2, K32_BASE, 'kernel32.dll', 0x2000)):
    mu.mem_write(ent + 0x30, struct.pack('<Q', base))
    mu.mem_write(ent + 0x38, struct.pack('<Q', base + 0x1000))
    mu.mem_write(ent + 0x40, struct.pack('<I', sz))
    name_us(ent + 0x48, nm)
    name_us(ent + 0x58, nm)

# 双向链表：LDR.head <-> ENT1 <-> ENT2 <-> LDR.head
def link(a, a_off, b, b_off):
    mu.mem_write(a + a_off, struct.pack('<Q', b + b_off))
    mu.mem_write(a + a_off + 8, struct.pack('<Q', b + b_off))


for o_ in (off_ildr, off_imem, off_iini):
    link(LDR, o_, ENT1, o_)
    link(ENT1, o_, ENT2, o_)
    link(ENT2, o_, LDR, o_)

heap_top = [0x20000000]
calls = collections.Counter()
seg_reads = collections.Counter()
writes = collections.Counter()
n_code = [0]
malloc_map = {}


def api(name, mu):
    n = name.lower()
    if 'virtualalloc' in n or 'heapalloc' in n or n == 'malloc':
        a = heap_top[0]
        try:
            mu.mem_map(a, 0x200000)
        except Exception:
            pass
        heap_top[0] += 0x200000
        return a
    if 'getmodulehandle' in n or 'loadlibrary' in n:
        # 读参数判断要哪个 DLL
        try:
            p = mu.reg_read(UC_X86_REG_RCX)
            raw = bytes(mu.mem_read(p, 64))
            if raw[0] == 0 and len(raw) > 1 and raw[1] != 0:
                s = raw.decode('utf-16-le', 'ignore').split('\0')[0].lower()
            else:
                s = raw.split(b'\0')[0].decode('latin1', 'ignore').lower()
        except Exception:
            s = ''
        if 'ntdll' in s:
            return NTD_BASE
        if 'kernel32' in s:
            return K32_BASE
        if s in ('', 'diskgenius.exe'):
            return IB
        return K32_BASE
    if 'getprocaddress' in n:
        try:
            p = mu.reg_read(UC_X86_REG_RDX)
            s = bytes(mu.mem_read(p, 48)).split(b'\0')[0].decode('latin1', 'ignore')
        except Exception:
            s = ''
        return name2stub.get(s, GEN)
    if 'getmodulefilename' in n:
        p = mu.reg_read(UC_X86_REG_RCX)
        mu.mem_write(p, 'C:\\DG\\DiskGenius.exe\0'.encode('utf-16-le') if 'w' in n else b'C:\\DG\\DiskGenius.exe\0')
        return 22
    if 'virtualprotect' in n or 'closehandle' in n or 'flushinstructioncache' in n:
        return 1
    if 'getcurrentprocess' in n:
        return 0xFFFFFFFFFFFFFFFF
    if 'getcurrentprocessid' in n:
        return 0x1234
    if 'getcurrentthreadid' in n:
        return 0x1238
    if 'queryperformancecounter' in n:
        p = mu.reg_read(UC_X86_REG_RCX)
        try:
            mu.mem_write(p, struct.pack('<Q', 0x100000))
        except Exception:
            pass
        return 1
    if 'gettickcount' in n:
        return 0x10000
    if 'exitprocess' in n:
        return 0
    return 1


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


def hw(mu, access, addr, size, value, user):
    writes[(addr - IB) >> 16] += size


def hru(mu, access, addr, size, value, user):
    rva = addr - IB
    if 0x62F000 <= rva < 0x199F000:
        seg_reads[(rva >> 16) << 16] += 1
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

print('[*] 假 DLL: kernel32@%#x (%d 导出) ntdll@%#x' % (K32_BASE, len(k32names), NTD_BASE))
print('[*] 开始模拟')
try:
    mu.emu_start(IB + ep, SENT, count=500_000_000, timeout=1800 * 1000 * 1000)
    print('[*] 正常结束')
except UcError as e:
    print('[!] 中断: %s' % e)

print('[i] 指令数 %d  RIP RVA %#x' % (n_code[0], mu.reg_read(UC_X86_REG_RIP) - IB))
print('[i] API 调用:', calls.most_common(20))
print('[i] 数据段读命中:', {hex(k): v for k, v in seg_reads.most_common(8)})
print('\n[i] 写入 Top12:')
for k, v in writes.most_common(12):
    rva = k << 16
    print('   RVA ~%#09x : %d' % (rva, v))

img = bytes(mu.mem_read(IB, size_of_image))
open('/workspace/dgwork/stage4_image.bin', 'wb').write(img)
print('[+] 已写 stage4_image.bin')
