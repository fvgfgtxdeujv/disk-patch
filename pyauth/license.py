"""授权记录（LicenseRecord）与两种落地位置：Options.ini 的 [LicenseInfo] 段 / 注册表值。

实测事实：
  * Options.ini 里程序自己写的形态是 BOM + `[LicenseInfo]` + `Show = "6.2.0.1829"`
  * 启动时注册表只查了一个值：HKCU\\Software\\Eassos\\DiskGenius\\Reg\\license
  * 字段名（池里连续排列）：appname / user / email / regcode / regver / VerifyDate
  * VerifyDate 的格式串是 %04d%02d%02d（即 YYYYMMDD 的十进制串）

未确定的：`license` 这个值里到底怎么把上面几个字段串起来（明文 k=v、分隔符、还是被变换过）。
本模块把"能确定的部分"做成严格实现，把"未确定的部分"做成可替换的 codec，
这样拿到一条真授权后只要试 codec 就能定案。
"""

from __future__ import annotations

import datetime as _dt
import os
import re
from dataclasses import dataclass, asdict
from typing import Iterable, Iterator, List, Optional, Tuple

from . import const


# ---------------------------------------------------------------- 注册码形态
def normalize_regcode(code: str) -> str:
    """去掉分隔符/空白，统一大写。空串原样返回。"""
    if not code:
        return ""
    return re.sub(r"[^0-9A-Za-z]", "", code).upper()


def format_regcode(code: str) -> str:
    """按 5 组 × 4 位的分组重新加分隔符（长度不匹配时原样返回去分隔符的结果）。"""
    raw = normalize_regcode(code)
    n = const.REGCODE_GROUPS * const.REGCODE_GROUP_LEN
    if len(raw) != n:
        return raw
    return const.REGCODE_SEP.join(
        raw[i:i + const.REGCODE_GROUP_LEN]
        for i in range(0, n, const.REGCODE_GROUP_LEN)
    )


def regcode_syntax_ok(code: str, alphabet: str = const.REGCODE_ALPHABET_LOOSE) -> bool:
    """只校验形态：20 位、出现在观测字符集里。

    注意：这不是"授权是否有效"的判定——真正判定在程序内的 VM 里（见 reports/REPORT_auth_python.md）。
    """
    raw = normalize_regcode(code)
    if len(raw) != const.REGCODE_GROUPS * const.REGCODE_GROUP_LEN:
        return False
    return all(c in alphabet for c in raw)


# ---------------------------------------------------------------- 日期
def parse_verify_date(value: str) -> Optional[_dt.date]:
    """%04d%02d%02d -> date；解析不了返回 None。"""
    v = (value or "").strip()
    if not re.fullmatch(r"\d{8}", v):
        return None
    try:
        return _dt.date(int(v[0:4]), int(v[4:6]), int(v[6:8]))
    except ValueError:
        return None


def format_verify_date(d: _dt.date) -> str:
    return "%04d%02d%02d" % (d.year, d.month, d.day)


# ---------------------------------------------------------------- 记录
@dataclass
class LicenseRecord:
    appname: str = "DiskGenius"
    user: str = ""
    email: str = ""
    regcode: str = ""
    regver: str = ""
    verify_date: str = ""

    # -- 派生 ------------------------------------------------------------
    @property
    def has_data(self) -> bool:
        """授权数据是否存在（VM 授权门看到的"有没有"就是这个）。"""
        return bool(self.regcode.strip())

    @property
    def verify_date_obj(self) -> Optional[_dt.date]:
        return parse_verify_date(self.verify_date)

    def is_expired(self, today: Optional[_dt.date] = None) -> bool:
        d = self.verify_date_obj
        if d is None:
            return False
        return d < (today or _dt.date.today())

    def as_dict(self) -> dict:
        return asdict(self)

    # -- INI 段 ----------------------------------------------------------
    def to_ini_section(self) -> List[str]:
        lines = ["[%s]" % const.INI_SECTION]
        for key, value in (
            (const.FIELD_APPNAME, self.appname),
            (const.FIELD_USER, self.user),
            (const.FIELD_EMAIL, self.email),
            (const.FIELD_REGCODE, self.regcode),
            (const.FIELD_REGVER, self.regver),
            (const.FIELD_VERIFYDATE, self.verify_date),
        ):
            if value:
                lines.append('%s = "%s"' % (key, value))
        return lines

    @classmethod
    def from_dict(cls, data: dict) -> "LicenseRecord":
        norm = {str(k).lower(): v for k, v in data.items()}
        return cls(
            appname=norm.get(const.FIELD_APPNAME.lower(), "DiskGenius"),
            user=norm.get(const.FIELD_USER.lower(), ""),
            email=norm.get(const.FIELD_EMAIL.lower(), ""),
            regcode=norm.get(const.FIELD_REGCODE.lower(), ""),
            regver=norm.get(const.FIELD_REGVER.lower(), ""),
            verify_date=norm.get(const.FIELD_VERIFYDATE.lower(), ""),
        )


# ---------------------------------------------------------------- INI 读写
def read_options_ini(path: str) -> Tuple[dict, dict]:
    """返回 (LicenseInfo 段, 其余全部段)。兼容 UTF-16(带 BOM) 与 UTF-8。"""
    if not os.path.exists(path):
        return {}, {}
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8", "replace")
    else:
        text = raw.decode("utf-8", "replace")

    sections: dict = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, {})
            continue
        if "=" in line and current is not None:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            sections[current][k.strip()] = v
    lic = sections.pop(const.INI_SECTION, {})
    return lic, sections


def write_options_ini(path: str, record: LicenseRecord,
                      extra_license_keys: Optional[dict] = None,
                      encoding: str = "utf-16") -> None:
    """写回 Options.ini。

    实测：程序自己把 `Show = "6.2.0.1829"` 和授权字段放在同一个 [LicenseInfo] 段里，
    所以额外键（Show 等）通过 extra_license_keys 一起写进该段，不另开段。
    """
    lic_section, others = read_options_ini(path)
    lic_section.update(extra_license_keys or {})

    lines: List[str] = []
    for section, values in others.items():
        lines.append("[%s]" % section)
        for k, v in values.items():
            lines.append('%s = "%s"' % (k, v))
        lines.append("")

    lines.append("[%s]" % const.INI_SECTION)
    for key, value in lic_section.items():
        if value:
            lines.append('%s = "%s"' % (key, value))
    # 记录字段覆盖同名键
    for key, value in (
        (const.FIELD_APPNAME, record.appname),
        (const.FIELD_USER, record.user),
        (const.FIELD_EMAIL, record.email),
        (const.FIELD_REGCODE, record.regcode),
        (const.FIELD_REGVER, record.regver),
        (const.FIELD_VERIFYDATE, record.verify_date),
    ):
        if not value:
            continue
        for i, line in enumerate(lines):
            if line.split("=")[0].strip() == key:
                lines[i] = '%s = "%s"' % (key, value)
                break
        else:
            lines.append('%s = "%s"' % (key, value))
    lines.append("")

    data = "\r\n".join(lines)
    with open(path, "wb") as fh:
        if encoding == "utf-16":
            fh.write(b"\xff\xfe" + data.encode("utf-16-le"))
        else:
            fh.write(data.encode("utf-8"))


# ---------------------------------------------------------------- 注册表
def read_reg_license(key_path: str = const.REG_KEY) -> Optional[bytes]:
    """读 HKCU\\<key_path>\\license 的原始字节（Windows / Wine 上可用）。"""
    import winreg  # noqa: WPS433 — 只在 Windows 环境导入

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _type = winreg.QueryValueEx(key, const.REG_VALUE_LICENSE)
    except OSError:
        return None
    if isinstance(value, str):
        return value.encode("utf-16-le")
    return bytes(value)


def write_reg_license(payload: bytes, key_path: str = const.REG_KEY) -> None:
    """把授权负载写进 HKCU\\<key_path>\\license（REG_BINARY）。"""
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, const.REG_VALUE_LICENSE, 0, winreg.REG_BINARY, payload)


# ---------------------------------------------------------------- license 值编解码（可替换）
def encode_license_value(record: LicenseRecord, style: str = "kv_lines") -> bytes:
    """把记录编成 `license` 注册表值的字节。

    style 是"待验证假设"的集合，实测只确定了字段名，没有确定串接方式：
      kv_lines   —— "appname=...\\r\\nuser=...\\r\\n..."（UTF-16LE）
      kv_amp     —— "appname=...&user=...&..."（UTF-16LE）
      pipe       —— "appname|user|email|regcode|regver|VerifyDate"（UTF-16LE）
    """
    items = [
        (const.FIELD_APPNAME, record.appname),
        (const.FIELD_USER, record.user),
        (const.FIELD_EMAIL, record.email),
        (const.FIELD_REGCODE, record.regcode),
        (const.FIELD_REGVER, record.regver),
        (const.FIELD_VERIFYDATE, record.verify_date),
    ]
    items = [(k, v) for k, v in items if v]
    if style == "kv_lines":
        text = "\r\n".join("%s=%s" % (k, v) for k, v in items)
    elif style == "kv_amp":
        text = "&".join("%s=%s" % (k, v) for k, v in items)
    elif style == "pipe":
        text = "|".join(v for _k, v in items)
    else:
        raise ValueError("未知 style: %s" % style)
    return text.encode("utf-16-le")


def decode_license_value(payload: bytes) -> dict:
    """尽力解析 `license` 值：先当 UTF-16，再当 latin1；支持 = & | 三种分隔。"""
    if payload[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = payload.decode("utf-16")
    else:
        try:
            text = payload.decode("utf-16-le")
        except UnicodeDecodeError:
            text = payload.decode("latin1")
    text = text.replace("\x00", "")
    out: dict = {}
    for chunk in re.split(r"[\r\n&|]+", text):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------- 便利函数
def iter_fields(record: LicenseRecord) -> Iterator[Tuple[str, str]]:
    yield const.FIELD_APPNAME, record.appname
    yield const.FIELD_USER, record.user
    yield const.FIELD_EMAIL, record.email
    yield const.FIELD_REGCODE, record.regcode
    yield const.FIELD_REGVER, record.regver
    yield const.FIELD_VERIFYDATE, record.verify_date


def fields_present(record: LicenseRecord, required: Iterable[str] = (
        const.FIELD_USER, const.FIELD_EMAIL, const.FIELD_REGCODE)) -> bool:
    data = dict(iter_fields(record))
    return all((data.get(k) or "").strip() for k in required)
