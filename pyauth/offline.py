"""OfflineReg.dat / 离线注册流量 —— 全部基于本机 Wine 实测（2026-11-19）。

实测链路（可复现）：
    DiskGenius --(Offline Register)--> OfflineReg.dat
    OfflineReg.exe --(读 dat)--> 显示 name/email/code --(POST)--> 服务器
    服务器 --(响应)--> Options.ini 的 [license] 段

实测到的硬事实：
  1. OfflineReg.dat 固定 2048 字节：前 64 字节是 key，其余 1984 字节是
     cipher[i] ^= key[i % 64] 的循环 XOR。读不满 2048 字节直接判失败。
  2. 明文 +0x80 处是完整 URL（含 query）。程序从中解析 host/port/path，
     query 部分原样作为 POST body 发出去。
  3. 端口 443 → WinHTTP 加 WINHTTP_FLAG_SECURE（TLS）；非 443 → 明文 HTTP。
     （反汇编 0x40b4ee..0x40b500：cmp si,0x1bb; cmove eax,0x800100）
  4. 请求头固定：User-Agent: Eassos Net App/1.0
                Content-type: application/x-www-form-urlencoded
                Authorization: Basic（无内容）
  5. 响应判定：必须包含子串 "appname=DiskGenius"（且位于开头第一个字段），
     否则显示 "Sorry, registering failed."；响应含 "<html" 时走 301 重定向分支，
     从 "href=" 取新地址重试。
  6. 成功时写 Options.ini（UTF-16LE + BOM，CRLF），段名 **[license]**：
        [license]
        appname = "DiskGenius"
        user = ""
        email = "license@eassos.com"
        regcode = ""
        regver = "6.2.0.1829_x64_pro_eng"
        key = "<服务端响应原文，逐字节保存>"

  7. 主程序启动时会 CreateFileW(Options.ini, GENERIC_READ) 读它，但把
     伪造的 key 静默丢弃（不写 HKCU\\...\\Reg\\license）—— 说明 key 是服务端签名，
     客户端只做验证。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple
from urllib.parse import urlsplit, parse_qsl, quote

# ---------------------------------------------------------------- dat 容器
DAT_SIZE = 2048
DAT_KEY_SIZE = 64
DAT_BODY_SIZE = DAT_SIZE - DAT_KEY_SIZE

#: 明文里 URL 的起始偏移（相对明文区，即文件偏移 0xC0）
URL_OFFSET = 0x80


def decode_dat(raw: bytes) -> bytes:
    """2048 字节 dat -> 明文（1984 字节）。长度不对直接抛错（实测客户端就是这样判的）。"""
    if len(raw) != DAT_SIZE:
        raise ValueError("OfflineReg.dat must be exactly %d bytes, got %d" % (DAT_SIZE, len(raw)))
    key = raw[:DAT_KEY_SIZE]
    body = bytearray(raw[DAT_KEY_SIZE:])
    for i in range(len(body)):
        body[i] ^= key[i % DAT_KEY_SIZE]
    return bytes(body)


def encode_dat(plain: bytes, key: bytes = b"\x00" * DAT_KEY_SIZE) -> bytes:
    """明文 -> 2048 字节 dat。key 必须是 64 字节。"""
    if len(key) != DAT_KEY_SIZE:
        raise ValueError("key must be %d bytes" % DAT_KEY_SIZE)
    if len(plain) > DAT_BODY_SIZE:
        raise ValueError("plain too long: %d > %d" % (len(plain), DAT_BODY_SIZE))
    body = bytearray(DAT_BODY_SIZE)
    body[: len(plain)] = plain
    for i in range(len(body)):
        body[i] ^= key[i % DAT_KEY_SIZE]
    return key + bytes(body)


def read_url(plain: bytes) -> str:
    """取明文里的 URL（0x80 起，到第一个 NUL）。"""
    tail = plain[URL_OFFSET:]
    end = tail.find(b"\x00")
    if end >= 0:
        tail = tail[:end]
    return tail.decode("latin1")


def make_plain(url: str) -> bytes:
    """造一个只含 URL 的明文区（够复现客户端行为）。"""
    if len(url) > DAT_BODY_SIZE - URL_OFFSET:
        raise ValueError("url too long")
    plain = bytearray(DAT_BODY_SIZE)
    plain[URL_OFFSET : URL_OFFSET + len(url)] = url.encode("latin1")
    return bytes(plain)


# ---------------------------------------------------------------- 请求
DEFAULT_UA = "Eassos Net App/1.0"
CONTENT_TYPE = "application/x-www-form-urlencoded"


@dataclass
class Endpoint:
    scheme: str
    host: str
    port: int
    path: str
    query: str

    @property
    def secure(self) -> bool:
        return self.port == 443

    @property
    def body(self) -> str:
        """实测：query 原样作为 POST body。"""
        return self.query


def parse_endpoint(url: str) -> Endpoint:
    """按客户端的行为解析 URL。

    注意：客户端不拆 host 里的端口（实测 "http://127.0.0.1:8899/reg" 会连 host
    "127.0.0.1:8899"、port 443），所以这里保留原文，只按 443 判是否 TLS。
    """
    sp = urlsplit(url if "://" in url else "https://" + url)
    host = sp.netloc
    scheme = sp.scheme or "https"
    return Endpoint(scheme=scheme, host=host, port=443, path=sp.path or "/", query=sp.query)


def request_headers(host: str) -> dict:
    return {
        "User-Agent": DEFAULT_UA,
        "Content-type": CONTENT_TYPE,
        "Authorization": "Basic",
        "Host": host,
        "Connection": "Keep-Alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }


# ---------------------------------------------------------------- 响应
RESPONSE_PREFIX = "appname=DiskGenius"

#: 实测：失败提示（UTF-16 资源串）
FAIL_TEXT = "Sorry, registering failed. Please check the internet connection and try again."


def response_ok(text: str) -> bool:
    """实测判定：第一个字段必须是 appname=DiskGenius。"""
    return text.startswith(RESPONSE_PREFIX)


def parse_response(text: str) -> dict:
    """key=value & 分隔 -> dict。未做 URL 解码（实测客户端也是原文保存）。"""
    out = {}
    for pair in text.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
        else:
            out[pair] = ""
    return out


@dataclass
class OfflineResult:
    """一次离线注册的结果，字段对应 Options.ini [license] 段。"""

    appname: str = "DiskGenius"
    user: str = ""
    email: str = "license@eassos.com"
    regcode: str = ""
    regver: str = ""
    key: str = ""
    raw: str = field(default="", repr=False)

    @classmethod
    def from_response(cls, text: str, regver: str = "") -> "OfflineResult":
        if not response_ok(text):
            raise ValueError("response rejected by client rule: %r" % text[:40])
        return cls(regver=regver, key=text, raw=text)


# ---------------------------------------------------------------- Options.ini
INI_SECTION_ACTUAL = "license"          # 实测段名（不是先前报告里写的 LicenseInfo）
INI_ORDER = ("appname", "user", "email", "regcode", "regver", "key")
INI_DEFAULTS = {
    "appname": "DiskGenius",
    "user": "",
    "email": "license@eassos.com",
    "regcode": "",
}


def render_options_ini(result: OfflineResult) -> str:
    """按实测格式生成 Options.ini 文本（未含 BOM）。行尾 CRLF，值带双引号。"""
    vals = dict(INI_DEFAULTS)
    vals.update(appname=result.appname, user=result.user, email=result.email,
                regcode=result.regcode, regver=result.regver, key=result.key)
    lines = ["[%s]" % INI_SECTION_ACTUAL]
    for k in INI_ORDER:
        lines.append('%s = "%s"' % (k, vals.get(k, "")))
    return "\r\n".join(lines) + "\r\n\r\n"


def write_options_ini(path: str, result: OfflineResult) -> None:
    """UTF-16LE + BOM 写出（实测就是这个编码）。"""
    with open(path, "wb") as fh:
        fh.write(b"\xff\xfe")
        fh.write(render_options_ini(result).encode("utf-16-le"))


def read_options_ini(path: str) -> Tuple[dict, str]:
    """读回：返回 ([license] 段字段, 原始全文)。兼容 UTF-16/UTF-8。"""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8", "replace")
    fields, cur = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            continue
        if cur == INI_SECTION_ACTUAL and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            fields[k.strip()] = v
    return fields, text
