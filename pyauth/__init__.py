"""DiskGenius 授权层 Python 还原包（基于 6.2.0.1829 x64 实测）。

模块分工：
  const     实测常量与来源标注
  protocol  请求串 / mid 编码 / 离线注册体构造
  license   授权记录、Options.ini、注册表 license 值
  gate      授权门判定模型（实证 / 推断分开）
"""

from .const import SAMPLE_QUERY, SAMPLE_MID, REG_KEY
from .license import (LicenseRecord, normalize_regcode, format_regcode,
                      regcode_syntax_ok, parse_verify_date, format_verify_date,
                      read_options_ini, write_options_ini,
                      encode_license_value, decode_license_value)
from .protocol import (enc_query, enc_mid, decode_mid, build_status_query,
                       build_register_body, build_diskinfo, parse_params)
from .gate import Decision, GateResult, evaluate, is_licensed

__all__ = [
    "SAMPLE_QUERY", "SAMPLE_MID", "REG_KEY",
    "LicenseRecord", "normalize_regcode", "format_regcode", "regcode_syntax_ok",
    "parse_verify_date", "format_verify_date",
    "read_options_ini", "write_options_ini",
    "encode_license_value", "decode_license_value",
    "enc_query", "enc_mid", "decode_mid", "build_status_query",
    "build_register_body", "build_diskinfo", "parse_params",
    "Decision", "GateResult", "evaluate", "is_licensed",
]
__version__ = "0.1.0"
