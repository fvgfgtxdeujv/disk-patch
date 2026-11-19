"""命令行入口：python -m pyauth <子命令>"""

from __future__ import annotations

import argparse
import binascii
import datetime as _dt
import json
import os
import sys

from . import const
from . import license as lic
from . import protocol
from . import gate


def _cmd_query(args) -> int:
    print(protocol.build_status_query(
        ver=args.ver, mid=args.mid, appname=args.appname, iplan=args.iplan))
    return 0


def _cmd_mid(args) -> int:
    raw = protocol.decode_mid(args.value)
    print("编码串 : %r" % args.value)
    print("字节数 : %d" % len(raw))
    print("hex    : %s" % raw.hex(" "))
    print("回编码 : %s" % protocol.enc_mid(raw))
    print("还原一致: %s" % (protocol.enc_mid(raw) == args.value))
    return 0


def _cmd_code(args) -> int:
    print("原始   : %s" % args.value)
    print("规范   : %s" % lic.normalize_regcode(args.value))
    print("分组   : %s" % lic.format_regcode(args.value))
    print("形态ok : %s" % lic.regcode_syntax_ok(args.value))
    return 0


def _cmd_gate(args) -> int:
    rec = lic.LicenseRecord(appname=args.appname, user=args.user, email=args.email,
                            regcode=args.code, regver=args.regver,
                            verify_date=args.date)
    res = gate.evaluate(rec, check_expiry=args.check_expiry)
    print(json.dumps({"decision": res.decision.value, "licensed": res.licensed,
                      "detail": res.detail, "record": rec.as_dict()},
                     ensure_ascii=False, indent=2))
    return 0


def _cmd_show(args) -> int:
    if not os.path.exists(args.path):
        print("找不到 %s" % args.path)
        return 2
    section, others = lic.read_options_ini(args.path)
    print("[%s]" % const.INI_SECTION)
    for k, v in section.items():
        print("  %s = %r" % (k, v))
    if others:
        print("其它段: %s" % ", ".join(others))
    rec = lic.LicenseRecord.from_dict(section)
    print("解析结果: %s" % json.dumps(rec.as_dict(), ensure_ascii=False))
    return 0


def _cmd_decode_value(args) -> int:
    if os.path.exists(args.source):
        payload = open(args.source, "rb").read()
    else:
        payload = binascii.unhexlify(args.source.replace(" ", ""))
    print(json.dumps(lic.decode_license_value(payload), ensure_ascii=False, indent=2))
    return 0


def _cmd_offline_dat(args) -> int:
    from . import offline as off
    url = args.url
    plain = off.make_plain(url)
    dat = off.encode_dat(plain, bytes(off.DAT_KEY_SIZE))
    out = args.out or "OfflineReg.dat"
    with open(out, "wb") as fh:
        fh.write(dat)
    print("已写出 %s (%d 字节)" % (out, len(dat)))
    print("  URL        : %s" % url)
    print("  host:port  : %s (客户端固定 port=443 -> %s)" % (
        off.parse_endpoint(url).host, "TLS" if off.parse_endpoint(url).secure else "明文"))
    print("  POST body  : %s" % off.parse_endpoint(url).body)
    return 0


def _cmd_offline_ini(args) -> int:
    from . import offline as off
    resp = args.response
    if os.path.exists(resp):
        resp = open(resp, encoding="utf-8", errors="replace").read().strip()
    if not off.response_ok(resp):
        print("客户端会拒绝这个响应：第一个字段必须是 %r" % off.RESPONSE_PREFIX)
        return 1
    res = off.OfflineResult(regver=args.regver, key=resp, raw=resp)
    out = args.out or "Options.ini"
    off.write_options_ini(out, res)
    print("已写出 %s" % out)
    print(off.render_options_ini(res))
    return 0


def _cmd_offline_show(args) -> int:
    from . import offline as off
    fields, text = off.read_options_ini(args.path)
    if not fields:
        print("没有 [%s] 段" % off.INI_SECTION_ACTUAL)
        return 1
    for k in off.INI_ORDER:
        print("%-8s = %s" % (k, fields.get(k, "")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pyauth", description="DiskGenius 授权层 Python 还原工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("query", help="打印状态/校验请求串（默认用实测样本参数）")
    p.add_argument("--ver", default="6.2.0.1829_x64_pro_eng")
    p.add_argument("--mid", default=const.SAMPLE_MID)
    p.add_argument("--appname", default="DiskGenius")
    p.add_argument("--iplan", default="Y")
    p.set_defaults(func=_cmd_query)

    p = sub.add_parser("mid", help="解码 mid 参数")
    p.add_argument("value")
    p.set_defaults(func=_cmd_mid)

    p = sub.add_parser("code", help="注册码规范化 / 形态检查")
    p.add_argument("value")
    p.set_defaults(func=_cmd_code)

    p = sub.add_parser("gate", help="按授权门模型判定")
    p.add_argument("--appname", default="DiskGenius")
    p.add_argument("--user", default="")
    p.add_argument("--email", default="")
    p.add_argument("--code", default="")
    p.add_argument("--regver", default="6")
    p.add_argument("--date", default="")
    p.add_argument("--check-expiry", action="store_true", help="附加过期检查（推断项）")
    p.set_defaults(func=_cmd_gate)

    p = sub.add_parser("show", help="解析 Options.ini 的 [LicenseInfo] 段")
    p.add_argument("path")
    p.set_defaults(func=_cmd_show)

    p = sub.add_parser("decode-value", help="解析注册表 license 值的字节（文件或 hex）")
    p.add_argument("source")
    p.set_defaults(func=_cmd_decode_value)

    p = sub.add_parser("offline-dat", help="生成 OfflineReg.dat（2048 字节，可指到自己的服务器）")
    p.add_argument("url", help="明文里的 URL，query 会原样成为 POST body")
    p.add_argument("--out", default="")
    p.set_defaults(func=_cmd_offline_dat)

    p = sub.add_parser("offline-ini", help="用服务端响应文本生成 Options.ini")
    p.add_argument("response", help="响应原文，或含响应原文的文件")
    p.add_argument("--regver", default="6.2.0.1829_x64_pro_eng")
    p.add_argument("--out", default="")
    p.set_defaults(func=_cmd_offline_ini)

    p = sub.add_parser("offline-show", help="解析 Options.ini 的 [license] 段")
    p.add_argument("path")
    p.set_defaults(func=_cmd_offline_show)

    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
