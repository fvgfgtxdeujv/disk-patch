#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""等待指定仓库最新的 dump-runtime run 结束，打印各步骤结论 + 末尾日志。"""
import json, sys, time, urllib.request, urllib.error

T = 'os.environ["GH_TOKEN"]'
REPO = 'fvgfgtxdeujv/disk-patch'
BASE = 'https://api.github.com/repos/' + REPO


def g(path, raw=False):
    r = urllib.request.Request(BASE + path, headers={
        'Authorization': 'Bearer ' + T, 'Accept': 'application/vnd.github+json',
        'User-Agent': 'x', 'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(r, timeout=90) as resp:
        b = resp.read()
        return b if raw else json.loads(b or b'{}')


def main():
    since = sys.argv[1] if len(sys.argv) > 1 else None
    runs = g('/actions/workflows/dump-runtime.yml/runs?per_page=5')['workflow_runs']
    if not runs:
        print('no runs'); return 1
    run = runs[0]
    if since and run['id'] < int(since):
        print('最新 run 早于期望，等待新 run 出现'); 
    rid = run['id']
    print('[*] run %s  head=%s  created=%s' % (rid, run['head_sha'][:10], run['created_at']))
    t0 = time.time()
    while True:
        run = g('/actions/runs/%d' % rid)
        st = (run['status'], run['conclusion'])
        el = int(time.time() - t0)
        if run['status'] == 'completed':
            print('[*] 结束 %s  用时 %ds' % (run['conclusion'], el))
            break
        if el > 1500:
            print('[!] 超时等待，当前', st); break
        print('    ... %s %ds' % (run['status'], el)); sys.stdout.flush()
        time.sleep(20)
    for j in g('/actions/runs/%d/jobs' % rid)['jobs']:
        print('== job %s : %s / %s' % (j['name'], j['status'], j['conclusion']))
        for s in j['steps']:
            print('   - %-42s %s/%s' % (s['name'], s['status'], s['conclusion']))
    # 末尾日志
    try:
        log = g('/actions/runs/%d/logs' % rid, raw=True)
        import io, zipfile
        z = zipfile.ZipFile(io.BytesIO(log))
        for n in z.namelist():
            if 'dump-runtime' in n or 'runtime' in n:
                txt = z.read(n).decode('utf-8', 'replace').splitlines()
                keep = [l for l in txt if any(k in l for k in
                        ('[trace]', 'hook', '[!]', '[LIC]', '[OK]', '采样', '轨迹', '解码',
                         '钩', '派发器', 'Error', 'error', 'Traceback', 'Fatal'))]
                print('---- %s (关键行 %d / 共 %d) ----' % (n, len(keep), len(txt)))
                for l in keep[-80:]:
                    print(l)
    except Exception as e:
        print('[!] 日志拉取失败', e)
    print('RUNID=%d' % rid)
    return 0


if __name__ == '__main__':
    sys.exit(main())
