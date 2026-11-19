"""授权协议层：把字符串池里的格式串落成可复现的 Python 构造器。

两条编码规则都是逐字节对齐实测样本推出来的，selftest 会验证到字节级：

  1) 普通查询参数（ver / winver / ...）：非字母数字一律 percent 编码，十六进制小写
     "10.0.19043.sp0.0.00000000" -> "10%2e0%2e19043%2esp0%2e0%2e00000000"
  2) mid 参数：只把 0x10..0x1F 区间编码成 %XX（大写），其余字节原样
     b"\\x02OD\\x03Ikgn\\x1b\\x1d\\x12HLHLL\\x1a\\x1aH\\x1a\\x1aL\\x18\\x1b"
       -> "\\x02OD\\x03Ikgn%1B%1D%12HLHLL%1A%1AH%1A%1AL%18%1B"

第二条看起来像编码器的实现细节（只处理了高半字节 1 的控制字符），但它能被实测样本
完整复现，所以按它实现；换版本后必须重新用新样本回归。
"""

from __future__ import annotations

from typing import Dict, Optional

from . import const

_HEX = "0123456789abcdef"


def enc_query(value: str) -> str:
    """普通查询参数编码：非字母数字 -> %xx（小写十六进制）。"""
    out = []
    for ch in value:
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        else:
            code = ord(ch)
            if code > 0xFF:
                raise ValueError("enc_query 只接受单字节字符: %r" % ch)
            out.append("%%%02x" % code)
    return "".join(out)


def enc_mid(data: bytes) -> str:
    """mid 参数编码：仅 0x10..0x1F 转 %XX（大写），其余原样。"""
    out = []
    for b in data:
        if 0x10 <= b <= 0x1F:
            out.append("%%%02X" % b)
        else:
            out.append(chr(b))
    return "".join(out)


def decode_mid(param: str) -> bytes:
    """把 mid 参数还原成原始字节（%XX 解码，其余按 latin1 取字节）。"""
    out = bytearray()
    i = 0
    while i < len(param):
        ch = param[i]
        if ch == "%" and i + 2 < len(param):
            out.append(int(param[i + 1:i + 3], 16))
            i += 3
            continue
        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


def build_status_query(
    ver: str = "6.2.0.1829_x64_pro_eng",
    winver: str = "10.0.19043.sp0.0.00000000",
    winbits: int = 64,
    reslang: str = "eng",
    syslang: str = "eng",
    cpu: int = 64,
    mid: str = const.SAMPLE_MID,
    lid: str = "",
    otherinfo: str = "",
    iplan: str = "Y",
    appname: str = "DiskGenius",
    appcs: int = 0,
) -> str:
    """重建运行期实测的那条状态/校验请求（参数顺序与编码都对到字节）。"""
    # 逐字段编码是实测出来的：实测串里 ver=6.2.0.1829_x64_pro_eng 是原文（点/下划线不转），
    # 而 winver 里的点被转成 %2e。所以不能对一个整体串做统一编码。
    parts = [
        "ver=" + ver,                      # 实测：原文
        "winver=" + enc_query(winver),     # 实测：%xx
        "winbits=%d" % winbits,
        "reslang=" + reslang,              # 实测：原文
        "syslang=" + syslang,              # 实测：原文
        "cpu=%d" % cpu,
        "mid=" + mid,                      # 实测：专用编码（enc_mid）
        "lid=" + lid,
        "otherinfo=" + otherinfo,
        "iplan=" + iplan,
        "appname=" + appname,
        "appcs=%d" % appcs,
    ]
    return "&".join(parts)


def build_register_body(
    ver: str,
    code: str,
    name: str,
    email: str,
    mid: str,
    applang: str = "eng",
    appname: Optional[str] = None,
    check: Optional[str] = None,
    skey: Optional[str] = None,
    percent: bool = False,
) -> str:
    """按 POOL 里的两条格式串构造注册请求体。

    池里两条形态：
      ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s%s             (可接 &check=)
      %s%cver=%s&code=%s&name=%s&email=%s&mid=%s&appname=%s&applang=%s (可接 &skey=)

    编码策略是未证实项：实测只确认了状态请求里 winver 被 %xx 编码、ver 是原文，
    没有抓到真实的注册请求体，所以这里默认原文（percent=False），需要时再打开。
    """
    enc = enc_query if percent else (lambda s: s)
    body = (
        "ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s"
        % (enc(ver), enc(code), enc(name), enc(email), mid, enc(applang))
    )
    if appname:
        body += "&appname=" + enc(appname)
    if check:
        body += "&check=" + enc(check)
    if skey:
        body += "&skey=" + enc(skey)
    return body


def build_diskinfo(disk_index: int, value: str) -> str:
    """POOL: "&diskinfo%ld=%s" —— 按盘号附带的磁盘信息参数。"""
    return "&diskinfo%d=%s" % (disk_index, enc_query(value))


def parse_params(query: str) -> Dict[str, str]:
    """把 query / body 拆成 dict（保留原始编码值，不二次解码）。"""
    out: Dict[str, str] = {}
    for chunk in query.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        else:
            k, v = chunk, ""
        out[k] = v
    return out
