#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""拉指定 run 的产物 zip，解到目标目录。"""
import io, json, os, sys, urllib.request, urllib.error, zipfile

T = 'os.environ["GH_TOKEN"]'
BASE = 'https://api.github.com/repos/fvgfgtxdeujv/disk-patch'


def api(path):
    r = urllib.request.Request(BASE + path, headers={
        'Authorization': 'Bearer ' + T, 'Accept': 'application/vnd.github+json',
        'User-Agent': 'x'})
    with urllib.request.urlopen(r, timeout=120) as resp:
        return resp.read()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dl(url):
    """产物 zip 会 302 到对象存储，跳转后必须去掉 Authorization 头，否则 401。"""
    op = urllib.request.build_opener(NoRedirect)
    try:
        return op.open(urllib.request.Request(url, headers={
            'Authorization': 'Bearer ' + T, 'User-Agent': 'x'}), timeout=120)
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            raise
        loc = e.headers['Location']
        with urllib.request.urlopen(urllib.request.Request(loc, headers={
                'User-Agent': 'x'}), timeout=180) as r:
            data = r.read()
        class R:
            def __init__(self, b): self._b = b
            def read(self): return self._b
        return R(data)


def main():
    rid = sys.argv[1]
    out = sys.argv[2]
    ar = json.loads(api('/actions/runs/%s/artifacts' % rid))
    if not ar['artifacts']:
        print('无产物'); return 1
    os.makedirs(out, exist_ok=True)
    for a in ar['artifacts']:
        print('[*] %s  %d B' % (a['name'], a['size_in_bytes']))
        z = zipfile.ZipFile(io.BytesIO(dl(BASE + '/actions/artifacts/%d/zip' % a['id']).read()))
        z.extractall(out)
    for root, _, fs in os.walk(out):
        for f in fs:
            p = os.path.join(root, f)
            print('    %-58s %10d' % (os.path.relpath(p, out), os.path.getsize(p)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
