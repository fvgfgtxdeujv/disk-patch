# -*- coding: utf-8 -*-
"""
local_selftest.py —— 跨平台自检（Linux / macOS / Windows 都能跑）

不需要 Windows、不需要真目标：
构造一块合成内存镜像（代码段 + handler 表 + VM 上下文 + 干扰结构），检查
  1) scan_buffer 能不能把真 ctx 排第一、且不把干扰结构当 ctx
  2) memimage 容器往返正确、离线扫结果与在线扫一致

CI 第一步就跑它 —— Windows runner 的控制台默认 cp1252，中文 print 会炸，
所以入口处统一把 stdout/stderr 切 UTF-8。
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dump_ctx as D
import memimage as M

D._utf8_console()

CODE_LO = 0x180000000
CODE_HI = 0x180100000
IMG_LO = 0x30000000
IMG_SIZE = 0x40000        # 256KB 合成镜像


def build_image():
    buf = bytearray(IMG_SIZE)

    def put64(addr, v):
        o = addr - IMG_LO
        struct.pack_into('<Q', buf, o, v)

    def put_bytes(addr, b):
        o = addr - IMG_LO
        buf[o:o + len(b)] = b

    # 两张 handler 表（各 32 项，全落在代码段）
    t1 = IMG_LO + 0x1000
    t2 = IMG_LO + 0x2000
    for i in range(32):
        put64(t1 + i * 8, CODE_LO + 0x100 + i * 0x40)
        put64(t2 + i * 8, CODE_LO + 0x900 + i * 0x40)

    # 真 ctx
    ctx = IMG_LO + 0x8000
    put64(ctx + 0x0, IMG_LO + 0x10000)      # 字节流指针
    put64(ctx + 0x8, t1)                    # 表指针 1（0x4 与 0x8 重叠，只取其一）
    put64(ctx + 0xF5, t2)                   # 表指针 2
    put64(ctx + 0x92, IMG_LO + 0x10000)     # IP
    put_bytes(IMG_LO + 0x10000, b'\x20\x10\x00\x00' + b'\x00' * 12)

    # 干扰 1：两个代码段指针但指向的不是表
    dec1 = IMG_LO + 0x9000
    put64(dec1 + 0x8, CODE_LO + 0x1234)
    put64(dec1 + 0xF5, CODE_LO + 0x5678)

    # 干扰 2：表项全是同一个地址（假表）
    ft = IMG_LO + 0x3000
    for i in range(32):
        put64(ft + i * 8, CODE_LO + 0x200)
    dec2 = IMG_LO + 0xA000
    put64(dec2 + 0x8, ft)

    # 干扰 3：全零结构
    dec3 = IMG_LO + 0xB000
    put64(dec3 + 0x8, 0)

    # 一张「静态 handler 表」：乱序、互不相同、跨度大 —— 静态策略应该认出来
    t3 = IMG_LO + 0x4000
    order = [(i * 37) % 32 for i in range(32)]
    for i, k in enumerate(order):
        put64(t3 + i * 8, CODE_LO + 0x2000 + k * 0x40)

    # 升序跳表（编译器 switch 表）—— 静态策略应该跳过
    t4 = IMG_LO + 0x5000
    for i in range(32):
        put64(t4 + i * 8, CODE_LO + 0x3000 + i * 0x40)

    return bytes(buf), ctx, t1, t2, (dec1, dec2, dec3), t3, t4


def main():
    buf, ctx, t1, t2, decoys, t3, t4 = build_image()
    hits = D.scan_buffer(buf, IMG_LO, CODE_LO, CODE_HI, min_score=4)

    ok = 0
    fail = 0

    def check(name, cond, extra=''):
        nonlocal ok, fail
        if cond:
            ok += 1
            print('   [PASS] %-34s %s' % (name, extra))
        else:
            fail += 1
            print('   [FAIL] %-34s %s' % (name, extra))

    print('[*] 合成镜像 %d KB，候选 %d 个' % (len(buf) // 1024, len(hits)))
    check('找到候选', len(hits) > 0, '%d 个' % len(hits))
    if not hits:
        print('\n[*] 结果: %d passed, %d failed' % (ok, fail))
        return 1

    top = hits[0]
    check('第一名就是真 ctx', top['va'] == ctx, '0x%X vs 期望 0x%X' % (top['va'], ctx))
    check('认出两张表', len(top['tables']) >= 2,
          'slots=%s' % ','.join(sorted(top['tables'])))
    if top['tables']:
        check('表地址正确(0x8)', top['tables'].get('0x8') == '0x%X' % t1,
              top['tables'].get('0x8', '?'))
        check('表地址正确(0xF5)', top['tables'].get('0xF5') == '0x%X' % t2,
              top['tables'].get('0xF5', '?'))

    va_set = {h['va'] for h in hits[:6]}
    check('干扰结构未被当 ctx', not (va_set & set(decoys)),
          'decoys=%s' % ','.join('0x%X' % d for d in decoys))

    # ---- 静态指针数组策略 ----
    arrs = D.collect_static_tables(buf, IMG_LO, CODE_LO, CODE_HI, min_len=8)
    arr_vas = [va for va, _ in arrs]
    check('静态策略认出 handler 表', t3 in arr_vas,
          '%d 张：%s' % (len(arrs), ','.join('0x%X' % v for v in arr_vas[:4])))
    check('静态策略跳过升序跳表', t4 not in arr_vas,
          '升序表 0x%X' % t4)

    # ---- memimage 往返 + 离线扫 ----
    tmp = tempfile.mkdtemp(prefix='dgselftest_')
    path = os.path.join(tmp, 'mem.bin')
    n = M.write_image(path, [(IMG_LO, buf)])
    check('镜像写入', n == 1 and os.path.getsize(path) >= len(buf),
          '%d 字节' % os.path.getsize(path))

    img = M.read_image(path)
    got = img.read(ctx + 0x8, 8)
    img.close()
    check('镜像往返读表指针', got is not None and struct.unpack('<Q', got)[0] == t1,
          '0x%X' % (struct.unpack('<Q', got)[0] if got else 0))

    off_hits = M.scan_image(path, CODE_LO, CODE_HI, min_score=4)
    check('离线扫找到候选', len(off_hits) > 0, '%d 个' % len(off_hits))
    if off_hits:
        check('离线扫第一名一致', off_hits[0]['va'] == top['va'],
              '0x%X' % off_hits[0]['va'])
        ot = M.dump_tables(path, off_hits[0]['va'], CODE_LO, CODE_HI)
        check('离线读表内容一致', ot.get('0x8', {}).get('table_va') == '0x%X' % t1 and
              len(ot.get('0x8', {}).get('entries', [])) == 32,
              '%s 项' % len(ot.get('0x8', {}).get('entries', [])))

    try:
        os.remove(path)
        os.rmdir(tmp)
    except Exception:
        pass

    print('\n[*] 结果: %d passed, %d failed' % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
