# -*- coding: utf-8 -*-
"""
4MB 混合载荷性能基准：代码段与随机数据交错。
复现 REPORT 里「59.3 秒」的场景，用来量优化前后的差距。

用法：
  python3 bench_4mb.py                 # 默认 4MB mixed
  python3 bench_4mb.py --size 4194304
  python3 bench_4mb.py --mode random   # 纯随机（最坏情况）
  python3 bench_4mb.py --mode code     # 纯代码
"""
import sys, os, time, random, argparse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x86il_dispatch as D

CODE_CB = 0x400000


def build_code_chunk():
    """一段真实可反汇编的代码（复用 test_mixed 的派发器 + handler 形态）"""
    src = r"""
    mov rax, [rbp+0x92]
    movzx r12d, byte ptr [rax]
    cmp r12b, 0x10
    je  lab_a
    cmp r12b, 0x11
    je  lab_b
    mov rax, [rbp+8]
    add rax, [rbp+0x10]
    mov [rbp+0x18], rax
    xor eax, eax
    shl rax, 3
    jmp lab_a
lab_b:
    mov rbx, [rbp+0x20]
    sub rbx, 7
    mov [rbp+0x28], rbx
    ret
lab_a:
    mov rcx, rdi
    imul rcx, rcx, 5
    jmp lab_b
"""
    return D._build(src, code_base=CODE_CB)


def build_payload(total, mode='mixed', seed=1234):
    rnd = random.Random(seed)
    code = build_code_chunk()
    out = bytearray()
    if mode == 'random':
        return bytes(rnd.getrandbits(8) for _ in range(total))
    if mode == 'code':
        while len(out) < total:
            out += code
        return bytes(out[:total])
    blk = 64 * 1024
    while len(out) < total:
        out += (code * (blk // len(code) + 1))[:blk]
        out += bytes(rnd.getrandbits(8) for _ in range(min(blk, total - len(out))))
    return bytes(out[:total])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--size', type=int, default=4 * 1024 * 1024)
    ap.add_argument('--mode', default='mixed', choices=('mixed', 'random', 'code'))
    ap.add_argument('--save', metavar='FILE')
    ap.add_argument('--max-insn', type=int, default=3_000_000)
    a = ap.parse_args()

    p = build_payload(a.size, a.mode)
    if a.save:
        open(a.save, 'wb').write(p)
    print("[*] 载荷 %.1f MB  mode=%s" % (len(p) / 1048576.0, a.mode))

    t0 = time.time()
    sc = D.Scanner(p, CODE_CB, max_insn=a.max_insn)
    r = sc.run()
    dt = time.time() - t0

    ent = r['entries']
    found = {e['opcode'] for e in ent if e['opcode'] is not None}
    via = collections.Counter(e['via'] for e in ent)
    print("[*] 耗时 %.3f s   指令 %d   条目 %d   opcode %d"
          % (dt, r['stats']['instructions'], len(ent), len(found)))
    print("[*] via 分布: %s" % dict(via))
    print("[*] 吞吐: %.0f KB/s" % (len(p) / 1024.0 / max(dt, 1e-9)))


if __name__ == '__main__':
    main()
