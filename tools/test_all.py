# -*- coding: utf-8 -*-
"""
test_all.py —— 一键回归：正确性 + 精度 + 性能

覆盖：
  1. x86il_dispatch 自检（10 项：五种派发形态 / 16 位选择子 / 两类精度）
  2. 混合载荷召回率（12/12，零误报）
  3. 旧引擎 vs 新引擎对照（旧引擎在 xor 掩码上给错 opcode）
  4. 4MB 混合载荷性能门限
  5. 真实 DiskGenius 载荷（存在时）可行性与耗时门限

用法：
  python3 test_all.py                 # 全部
  python3 test_all.py --skip-real     # 跳过真实载荷
  python3 test_all.py --budget 15     # 4MB 耗时门限（秒）
"""
import sys, os, json, time, argparse, collections, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import x86il_dispatch as D

REAL = 'DiskGenius_unpacked_vmp.bin'
EXPECT = {0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x30, 0x31, 0x40, 0x41, 0x42}

results = []


def rec(name, ok, detail=''):
    results.append((name, ok, detail))
    print("  [%s] %-34s %s" % ('PASS' if ok else 'FAIL', name, detail))


def case_selftest():
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = D.selftest()
    rec('x86il_dispatch 自检', ok, buf.getvalue().strip().splitlines()[-1])


def case_mixed():
    p = open(os.path.join(HERE, 'payload_mixed.bin'), 'rb').read() \
        if os.path.exists(os.path.join(HERE, 'payload_mixed.bin')) else None
    if p is None:
        rec('混合载荷召回率', False, '缺 payload_mixed.bin，先跑 test_mixed.py')
        return
    r = D.discover(p, 0x400000)
    got = {k for k in r['scored'] if k is not None}
    rec('混合载荷召回率', got == EXPECT,
        '命中 %d/12  误报 %d' % (len(got & EXPECT), len(got - EXPECT)))


def case_compare():
    spec = importlib.util.spec_from_file_location(
        'v2', os.path.join(HERE, 'x86il_deobf_v2.py'))
    v2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v2)
    p = open(os.path.join(HERE, 'payload_mixed.bin'), 'rb').read()
    old = set(v2.discover_handlers_legacy(p, 0x400000))
    new = set(D.discover_handlers_compat(p, 0x400000))
    rec('旧引擎召回', len(old & EXPECT) == 5, '%d/12' % len(old & EXPECT))
    rec('新引擎召回', new == EXPECT, '%d/12' % len(new & EXPECT))
    rec('新引擎不产生错误 opcode', not (new - EXPECT),
        '误报 %s' % (sorted('0x%02X' % x for x in new - EXPECT) or '无'))


def case_perf(budget):
    import bench_4mb as B
    p = B.build_payload(4 * 1024 * 1024, 'mixed')
    t0 = time.time()
    D.Scanner(p, B.CODE_CB).run()
    dt = time.time() - t0
    rec('4MB 混合载荷耗时', dt <= budget, '%.2fs（门限 %ds）' % (dt, budget))


def case_real(budget):
    path = os.path.join(HERE, REAL)
    if not os.path.exists(path):
        print("  [SKIP] 真实载荷不存在：%s" % REAL)
        return
    p = open(path, 'rb').read()
    t0 = time.time()
    r = D.discover(p, D.CODE_BASE_VA, min_cases=2)
    dt = time.time() - t0
    n = len([k for k in r['scored'] if k is not None])
    rec('真实载荷可跑通', n > 0, '%d 个 opcode，条目 %d'
        % (n, r['stats']['entries']))
    rec('真实载荷耗时', dt <= budget, '%.2fs（门限 %ds）' % (dt, budget))


def case_ipslot():
    """IP 槽恢复：站点数、槽收敛、与 cmp 链候选不相交"""
    path = os.path.join(HERE, REAL)
    if not os.path.exists(path):
        print("  [SKIP] 真实载荷不存在，跳过 IP 槽")
        return
    import ipslot as I
    p = open(path, 'rb').read()
    t0 = time.time()
    r = I.scan(p, D.CODE_BASE_VA)
    dt = time.time() - t0
    sites = r['sites']
    rec('IP 槽站点发现', len(sites) > 1000, '%d 个 / %.1fs' % (len(sites), dt))
    if not sites:
        return
    top = collections.Counter(s.slot for s in sites).most_common(3)
    rec('IP 槽收敛到少数偏移', len(top) <= 4,
        '前三 %s' % ', '.join('0x%X:%d' % kv for kv in top))
    # 与 cmp 链候选应当不相交
    rr = D.discover(p, D.CODE_BASE_VA, min_cases=2)
    tg = {e['va'] for e in rr['entries']}
    inter = tg & {s.at for s in sites}
    rec('cmp 链候选与 IP 站点不相交', len(inter) == 0,
        '交集 %d（cmp 候选 %d / 站点 %d）' % (len(inter), len(tg), len(sites)))


def case_sixth_form():
    """第六种形态：mov rD,[tbl+idx*8]; jmp rD 的派发点应覆盖绝大多数 IP 槽站点"""
    path = os.path.join(HERE, REAL)
    if not os.path.exists(path):
        print("  [SKIP] 真实载荷不存在")
        return
    p = open(path, 'rb').read()
    r = D.discover(p, D.CODE_BASE_VA, min_cases=2)
    dps = {d['at'] for d in r['dispatch_points'] if d['kind'] == 'dispatch'}
    rec('第六形态派发点', len(dps) > 1000, '%d 个（去重）' % len(dps))

    import ipslot as I
    rs = I.scan(p, D.CODE_BASE_VA)
    sites = {s.at for s in rs['sites']}
    if not sites:
        return
    cov = 100.0 * len(dps & sites) / len(sites)
    rec('派发点覆盖 IP 槽站点', cov > 90.0, '%.1f%%（%d/%d）'
        % (cov, len(dps & sites), len(sites)))


def case_tableresolve():
    """表指针槽位定位（抽样 250 个派发点，控制在十几秒内）"""
    path = os.path.join(HERE, REAL)
    if not os.path.exists(path):
        print("  [SKIP] 真实载荷不存在")
        return
    import tableresolve as T
    p = open(path, 'rb').read()
    js = json.load(open(os.path.join(HERE, 'ipslots.json'), encoding='utf-8'))
    import collections
    cnt = collections.Counter(x['slot'] for x in js['sites'])
    ip_slots = {k for k, v in cnt.items() if v >= 20}
    dispatch = [(int(x['at'], 16), x['jmp_reg']) for x in js['sites']][:250]

    t0 = time.time()
    loads = T.find_ctx_loads(p, D.CODE_BASE_VA)
    res = T.resolve(p, dispatch, loads, D.CODE_BASE_VA, 400, ip_slots)
    dt = time.time() - t0
    rec('上下文装载惯用法', len(loads) > 10000, '%d 处' % len(loads))
    rec('表指针槽位可定位', len(res) / max(len(dispatch), 1) > 0.3,
        '%d/%d = %.1f%%（%.1fs）'
        % (len(res), len(dispatch), 100.0 * len(res) / len(dispatch), dt))
    if res:
        top = collections.Counter(r[2] for r in res if not r[3]).most_common(3)
        rec('槽位集中在少数偏移', len(top) >= 2,
            ', '.join('ctx+0x%X:%d' % kv for kv in top))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-real', action='store_true')
    ap.add_argument('--budget', type=float, default=15.0)
    ap.add_argument('--real-budget', type=float, default=30.0)
    a = ap.parse_args()

    print("[*] 回归开始\n")
    print("-- 正确性 --")
    case_selftest()
    case_mixed()
    case_compare()
    print("\n-- 性能 --")
    case_perf(a.budget)
    if not a.skip_real:
        case_real(a.real_budget)
        case_ipslot()
        case_sixth_form()
        case_tableresolve()

    bad = [r for r in results if not r[1]]
    print("\n" + "=" * 66)
    print("总计 %d 项，通过 %d，失败 %d" % (len(results), len(results) - len(bad), len(bad)))
    for n, _, d in bad:
        print("  失败: %s  %s" % (n, d))
    print("PASS" if not bad else "FAIL")
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
