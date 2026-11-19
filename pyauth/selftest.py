"""自测：所有能字节级对齐的结论都做断言，跑 `python -m pyauth.selftest`。"""

from __future__ import annotations

import datetime as _dt
import os
import tempfile

from . import const
from . import protocol, license as lic, gate


def _eq(name, got, want):
    if got != want:
        raise AssertionError("%s\n  got : %r\n  want: %r" % (name, got, want))
    print("  ok  %s" % name)


def main() -> int:
    print("[1] 请求串逐字节复现")
    q = protocol.build_status_query()
    _eq("build_status_query() == 运行期实测串", q, const.SAMPLE_QUERY)

    print("[2] mid 编解码")
    raw = protocol.decode_mid(const.SAMPLE_MID)
    _eq("decode_mid 字节数", len(raw), 26)
    _eq("decode_mid 首字节", raw[0], 0x6B)      # 'k'
    _eq("decode_mid 第3字节", raw[2], 0x02)
    _eq("enc_mid(decode_mid(x)) == x", protocol.enc_mid(raw), const.SAMPLE_MID)

    print("[3] 普通参数编码")
    _eq("enc_query 点号", protocol.enc_query("10.0.19043.sp0.0.00000000"),
        "10%2e0%2e19043%2esp0%2e0%2e00000000")
    _eq("enc_query 字母数字不动", protocol.enc_query("ver6_2"), "ver6%5f2")

    print("[4] 注册码形态")
    code = "QK7X-M2PV-ZLHD-W8CT-RBNQ"
    _eq("normalize", lic.normalize_regcode(code), "QK7XM2PVZLHDW8CTRBNQ")
    _eq("format 往返", lic.format_regcode(lic.normalize_regcode(code)), code)
    _eq("语法检查", lic.regcode_syntax_ok(code), True)
    _eq("长度不对", lic.regcode_syntax_ok("QK7X-M2PV"), False)

    print("[5] VerifyDate")
    d = lic.parse_verify_date("20991231")
    _eq("parse", d, _dt.date(2099, 12, 31))
    _eq("format", lic.format_verify_date(d), "20991231")
    _eq("非法日期", lic.parse_verify_date("2099123"), None)

    print("[6] Options.ini 往返")
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, const.INI_NAME)
    rec = lic.LicenseRecord(user="probe", email="probe@probe.test",
                            regcode=code, regver="6", verify_date="20991231")
    lic.write_options_ini(path, rec, extra_license_keys={"Show": "6.2.0.1829"})
    section, others = lic.read_options_ini(path)
    _eq("读回 user", section.get(const.FIELD_USER), "probe")
    _eq("读回 regcode", section.get(const.FIELD_REGCODE), code)
    _eq("读回 VerifyDate", section.get(const.FIELD_VERIFYDATE), "20991231")
    _eq("Show 键保留", section.get(const.INI_SHOW_KEY), "6.2.0.1829")
    _eq("文件是 UTF-16 BOM", open(path, "rb").read(2), b"\xff\xfe")

    print("[7] license 值编解码")
    payload = lic.encode_license_value(rec, "kv_lines")
    back = lic.decode_license_value(payload)
    _eq("kv_lines 往返 user", back.get(const.FIELD_USER), "probe")
    _eq("kv_lines 往返 code", back.get(const.FIELD_REGCODE), code)

    print("[8] 授权门")
    _eq("无授权", gate.evaluate(lic.LicenseRecord()).decision, gate.Decision.NO_LICENSE)
    _eq("有授权", gate.evaluate(rec).decision, gate.Decision.HAS_LICENSE)
    expired = lic.LicenseRecord(user="a", email="b", regcode=code, verify_date="20200101")
    _eq("过期(可选检查)", gate.evaluate(expired, check_expiry=True).decision,
        gate.Decision.EXPIRED)
    _eq("过期但默认不查", gate.evaluate(expired).decision, gate.Decision.HAS_LICENSE)
    bad = lic.LicenseRecord(user="a", email="b", regcode="QK7X-M2PV")
    _eq("形态不对", gate.evaluate(bad).decision, gate.Decision.BAD_SYNTAX)

    print("[9] 注册请求体")
    body = protocol.build_register_body("6.2.0.1829_x64_pro_eng", code, "probe",
                                        "probe@probe.test", const.SAMPLE_MID,
                                        appname="DiskGenius")
    _eq("参数顺序前缀", body.split("&")[:2],
        ["ver=6.2.0.1829_x64_pro_eng", "code=" + code])
    _eq("带 appname", body.endswith("&appname=DiskGenius"), True)
    _eq("percent 模式可用", protocol.build_register_body("6.2", code, "a b", "e@x", const.SAMPLE_MID, percent=True).split("&")[1], "code=QK7X%2dM2PV%2dZLHD%2dW8CT%2dRBNQ")

    print("[10] 离线注册（OfflineReg.dat / Options.ini）")
    from . import offline as off

    plain = off.make_plain("https://test.example.com/reg?appname=DiskGenius&license=SIG")
    dat = off.encode_dat(plain)
    _eq("dat 固定 2048 字节", len(dat), off.DAT_SIZE)
    _eq("dat 往返", off.decode_dat(dat)[off.URL_OFFSET:off.URL_OFFSET + 20],
        b"https://test.example")
    _eq("read_url", off.read_url(off.decode_dat(dat)),
        "https://test.example.com/reg?appname=DiskGenius&license=SIG")
    try:
        off.decode_dat(dat[:-1])
        raise AssertionError("短 dat 应该报错")
    except ValueError:
        print("  ok  dat 长度校验")

    ep = off.parse_endpoint("https://test.example.com/reg?appname=DiskGenius&license=SIG")
    _eq("443 走 TLS", ep.secure, True)
    _eq("query 原样当 body", ep.body, "appname=DiskGenius&license=SIG")

    _eq("响应判定(通过)", off.response_ok("appname=DiskGenius&license=SIG&user=a"), True)
    _eq("响应判定(license 打头被拒)", off.response_ok("license=SIG&appname=DiskGenius"), False)

    res = off.OfflineResult(regver="6.2.0.1829_x64_pro_eng",
                            key="appname=DiskGenius&license=TEST123&user=ZakaTest&email=zaka@example.com")
    text = off.render_options_ini(res)
    _eq("段名是 [license]", text.splitlines()[0], "[license]")
    _eq("key 原样保存", 'key = "%s"' % res.key in text, True)
    tmp2 = os.path.join(tmp, "Options_offline.ini")
    off.write_options_ini(tmp2, res)
    _eq("写出是 UTF-16 BOM", open(tmp2, "rb").read(2), b"\xff\xfe")
    fields, _ = off.read_options_ini(tmp2)
    _eq("读回 regver", fields.get("regver"), "6.2.0.1829_x64_pro_eng")
    _eq("读回 key", fields.get("key"), res.key)
    _eq("默认 user 为空", fields.get("user"), "")
    _eq("默认 email", fields.get("email"), "license@eassos.com")

    print("\nALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
