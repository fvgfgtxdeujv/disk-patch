# -*- coding: utf-8 -*-
"""
memimage.py —— 进程内存镜像容器 + 离线扫描

为什么要有这个：
  WinLicense/Themida 这类壳会防调试、防 dump、防注入。在线扫一遍没命中时，
  把「当前可读内存」原样存成一个文件，之后离线反复扫 —— 同一份数据可以
  反复试参数、可以当证据、不会因为进程退出而丢掉。

容器格式（小端）：
    magic  8B   b'ZAKAMEM1'
    hlen   4B   头部 JSON 字节数
    nreg   4B   区域数
    header hlen  [{"va":..,"size":..,"off":..}, ...]   off 相对 payload 起点
    payload ... 各区域原始字节

这个模块不依赖 Windows，Linux 上可以单测（local_selftest.py 里有往返用例）。
"""
import json
import os
import struct

MAGIC = b'ZAKAMEM1'
CHUNK = 32 << 20


# ------------------------------------------------------------
# 读写容器
# ------------------------------------------------------------
def write_image(path, regions):
    """
    regions: [(va, data: bytes), ...]
    头部先算好（off 由各区域长度前缀和得出），再写头、再写数据。
    """
    regions = [(va, d) for va, d in regions if d]
    header = []
    off = 0
    for va, d in regions:
        header.append({'va': va, 'size': len(d), 'off': off})
        off += len(d)
    hj = json.dumps(header).encode('utf-8')
    with open(path, 'wb') as f:
        f.write(MAGIC)
        f.write(struct.pack('<I', len(hj)))
        f.write(struct.pack('<I', len(regions)))
        f.write(hj)
        for _, d in regions:
            f.write(d)
    return len(regions)


class Image(object):
    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        head = self.f.read(8)
        if head != MAGIC:
            raise ValueError('%s 不是 memimage（magic=%r）' % (path, head))
        hlen = struct.unpack('<I', self.f.read(4))[0]
        self.nreg = struct.unpack('<I', self.f.read(4))[0]
        self.header = json.loads(self.f.read(hlen).decode('utf-8'))
        self.payload_off = 8 + 4 + 4 + hlen
        self.regions = [(r['va'], r['size'], r['off']) for r in self.header]

    def read(self, va, n):
        for rva, size, off in self.regions:
            if rva <= va and va + n <= rva + size:
                self.f.seek(self.payload_off + off + (va - rva))
                return self.f.read(n)
        return None

    def iter_region(self, rva, size, off, chunk=CHUNK):
        done = 0
        while done < size:
            n = min(chunk, size - done)
            n -= n % 8
            if n <= 0:
                break
            self.f.seek(self.payload_off + off + done)
            data = self.f.read(n)
            if not data:
                break
            yield rva + done, data
            done += len(data)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


def read_image(path):
    return Image(path)


# ------------------------------------------------------------
# 从活的进程里存
# ------------------------------------------------------------
def save_process(h, path, regions, max_total=3 << 30):
    """regions: enum_regions() 的输出 [(base, size, prot)]"""
    import ctypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    out = []
    total = 0
    for base, size, prot in regions:
        if total >= max_total:
            break
        n = min(size, CHUNK)
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, n, ctypes.byref(got))
        if got.value:
            out.append((base, buf.raw[:got.value]))
            total += got.value
    return write_image(path, out)


# ------------------------------------------------------------
# 离线扫描（复用 dump_ctx 的核心算法）
# ------------------------------------------------------------
def _reader_for(img):
    def rd64(addr):
        b = img.read(addr, 8)
        return struct.unpack('<Q', b)[0] if b and len(b) == 8 else None

    def rd16(addr):
        b = img.read(addr, 2)
        return struct.unpack('<H', b)[0] if b and len(b) == 2 else None

    return rd64, rd16


def scan_image(path, code_lo, code_hi, min_score=4, min_table_len=16,
               max_tables=256, chunk=CHUNK):
    """对整个镜像逐区域扫，返回候选列表（按分数降序）"""
    import dump_ctx as D
    img = Image(path)
    hits = []
    try:
        for rva, size, off in img.regions:
            for va, data in img.iter_region(rva, size, off, chunk):
                pref = D.prefilter_ctx_candidates(data, va, code_lo, code_hi,
                                                  min_table_len, max_tables)
                if not pref:
                    continue
                rd64, rd16 = _reader_for(img)
                for ctx_va in list(pref)[:200]:
                    sc, det, tables = D.score_ctx(rd64, rd16, ctx_va, code_lo, code_hi,
                                                  lambda a: True)
                    if sc >= min_score and tables:
                        hits.append({'va': ctx_va, 'score': sc, 'detail': det,
                                     'tables': {('0x%X' % k): ('0x%X' % v)
                                                for k, v in tables.items()}})
    finally:
        img.close()
    hits.sort(key=lambda x: -x['score'])
    return hits


def dump_tables(path, ctx_va, code_lo=0, code_hi=0, slots=None, maxn=65536):
    """按 ctx 槽把整张表读出来（离线版）"""
    import dump_ctx as D
    slots = slots or D.CTX_SLOTS
    img = Image(path)
    try:
        rd64, _ = _reader_for(img)
        out = {}
        for s in slots:
            t = rd64(ctx_va + s)
            if not t:
                continue
            items = []
            for i in range(maxn):
                v = rd64(t + i * 8)
                if not v:
                    break
                if code_lo and code_hi and not (code_lo <= v < code_hi):
                    break
                items.append(v)
            if items:
                out['0x%X' % s] = {'table_va': '0x%X' % t, 'entries': items}
        return out
    finally:
        img.close()


def main():
    import argparse
    import dump_ctx as D
    ap = argparse.ArgumentParser(description='离线扫 memimage，产出 tables.json')
    ap.add_argument('image')
    ap.add_argument('--out', default='tables.json')
    ap.add_argument('--code-lo', required=True)
    ap.add_argument('--code-hi', required=True)
    ap.add_argument('--min-score', type=int, default=4)
    ap.add_argument('--module-base', default=None)
    ap.add_argument('--source', default='memimage')
    a = ap.parse_args()

    D._utf8_console()
    lo = int(a.code_lo, 16) if isinstance(a.code_lo, str) else a.code_lo
    hi = int(a.code_hi, 16) if isinstance(a.code_hi, str) else a.code_hi
    hits = scan_image(a.image, lo, hi, a.min_score)
    if not hits:
        print('[!] 镜像里没找到候选')
        return 1
    best = hits[0]
    tables = dump_tables(a.image, best['va'], lo, hi)
    out = {'ctx_va': '0x%X' % best['va'], 'score': best['score'],
           'detail': best['detail'], 'tables': tables,
           'module_base': a.module_base or '0x%X' % lo,
           'source': a.source}
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print('[+] 已写入 %s（%d 张表）' % (a.out, len(tables)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
