# -*- coding: utf-8 -*-
"""
v6 产物分析：对运行期各段 dump 做三件事
  1. 与静态基准（exe 文件原节 / vmp_unpacked）diff，定位解密区
  2. 非对齐全量扫 VM 表（连续 qword 落保护段）
  3. 全量扫 [u16 op][i32 len] 字节流（放宽 op 上界）
用法:
  python analyze_v6.py <artifact_dir> <exe_path>
"""
import struct, sys, os

def pe_sections(exe_path):
    exe = open(exe_path, 'rb').read()
    e = struct.unpack_from('<I', exe, 0x3C)[0]
    nsec = struct.unpack_from('<H', exe, e+6)[0]
    opt_size = struct.unpack_from('<H', exe, e+20)[0]
    opt = e+24
    base = struct.unpack_from('<Q', exe, opt+0x18)[0]
    so = opt+opt_size
    secs = []
    for i in range(nsec):
        o = so+i*40
        name = exe[o:o+8].rstrip(b'\0').decode('latin1','replace')
        vs, va = struct.unpack_from('<II', exe, o+8)
        secs.append((name, base+va, vs))
    return exe, base, secs

RANGES = [(0x140001000,0x14062e2f8),(0x1419d4000,0x142780000),
          (0x142780000,0x142ff2000)]
def in_rng(v):
    for lo,hi in RANGES:
        if lo<=v<hi: return True
    return False

def scan_tables(data, base, name, minrun=24):
    n = len(data)
    for phase in range(8):
        i = phase
        while i+8*minrun <= n:
            j = i; cnt = 0
            while j+8 <= n:
                v = struct.unpack_from('<Q', data, j)[0]
                if in_rng(v): j += 8; cnt += 1
                else: break
            if cnt >= minrun:
                print(f'  [表 {name}] @VA {hex(base+i)} 连续 {cnt} 项 (phase {phase})')
                i = j
            else:
                i += 8

def walk(data, off, max_steps=64, max_op=0x10000, max_len=0x800):
    steps = 0; ops = []; o = off; n = len(data)
    while steps < max_steps and o+6 <= n:
        op = data[o] | (data[o+1]<<8)
        ln = struct.unpack_from('<i', data, o+2)[0]
        if not (0 < op < max_op) or not (6 <= ln <= max_len): break
        ops.append(op); o += ln; steps += 1
    return steps, ops

def scan_streams(data, base, name, min_steps=40):
    n = len(data); i = 0; found = 0
    while i+6 <= n:
        op = data[i] | (data[i+1]<<8)
        if 0 < op < 0x10000:
            ln = struct.unpack_from('<i', data, i+2)[0]
            if 6 <= ln <= 0x800:
                s, ops = walk(data, i)
                if s >= min_steps:
                    found += 1
                    print(f'  [流 {name}] @VA {hex(base+i)} 步数 {s} '
                          f'前10op {ops[:10]}')
                    if found > 20: return
                i += 6
                continue
        i += 1

def diff(a, b, base, name, top=8):
    import numpy as np
    n = min(len(a), len(b)) & ~7
    A = np.frombuffer(a[:n], dtype=np.uint64)
    B = np.frombuffer(b[:n], dtype=np.uint64)
    neq = np.nonzero(A != B)[0]
    if len(neq) == 0:
        print(f'  [diff {name}] 无差异'); return []
    regions = []; prev = None
    for idx in neq:
        off = idx*8
        if prev is not None and off-prev[1] < 256: prev[1] = off+8
        else:
            if prev: regions.append(tuple(prev))
            prev = [off, off+8]
    if prev: regions.append(tuple(prev))
    tot = sum(hi-lo for lo,hi in regions)
    print(f'  [diff {name}] {len(regions)} 区 / {tot} 字节')
    for lo,hi in sorted(regions, key=lambda x:-(x[1]-x[0]))[:top]:
        print(f'    VA {hex(base+lo)} len {hi-lo}')
    return regions

def main():
    adir, exe_path = sys.argv[1], sys.argv[2]
    exe, base, secs = pe_sections(exe_path)
    print('== PE 段 ==')
    for name, va, vs in secs:
        print(f'  {name:10s} VA {hex(va)} vsize {hex(vs)}')
    for f in sorted(os.listdir(adir)):
        if not f.startswith('prot_'): continue
        path = os.path.join(adir, f)
        data = open(path,'rb').read()
        tag, vastr = f[5:-4].split('_',1)
        va = int(vastr, 16)
        print(f'== {f} ({hex(len(data))}) ==')
        # 找对应静态节
        sec = next((s for s in secs if s[1] == va), None)
        if sec:
            rva = sec[1]-base
            # 用 exe 里的文件内容做基准（.vmp rawsz=0 时用 vmp_unpacked）
            e = struct.unpack_from('<I', exe, 0x3C)[0]
            nsec = struct.unpack_from('<H', exe, e+6)[0]
            opt_size = struct.unpack_from('<H', exe, e+20)[0]
            raw_idx = [struct.unpack_from('<II', exe, e+24+opt_size+i*40+16)
                       for i in range(nsec)]
            si = next(i for i,s in enumerate(secs) if s[1]==va)
            raw_off, raw_sz = raw_idx[si]
            if raw_sz:
                diff(exe[raw_off:raw_off+raw_sz][:len(data)], data, va,
                     f'{f} vs exe原文')
            else:
                up = '/workspace/dgwork/out/vmp_unpacked_6201829.bin'
                if os.path.exists(up) and va == 0x1419D4000:
                    diff(open(up,'rb').read(), data, va, f'{f} vs vmp_unpacked')
        scan_tables(data, va, f)
        scan_streams(data, va, f)

if __name__ == '__main__':
    main()
