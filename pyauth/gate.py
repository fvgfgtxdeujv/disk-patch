"""授权门（gate）模型。

只写"有证据"的判定，推断的部分单独标注，别把推断当事实用。

实证（reports/REPORT_table_dbi.md §13，双 run 差分）：
  * 无授权 vs 假授权的 VM 轨迹在 op 77..897 完全一致，假授权那次只在 op 897..905
    多执行了 9 个 op：tags 547,297,406,446,545,263,446,545,430 —— 一个完整条件块。
  * 该块往参数区写的是指针（0x1d0000 / 0x1d7000 系堆地址）+ 一个异常状态值
    0xc0000004（STATUS_INFO_LENGTH_MISMATCH），随后在 op 906 与无授权路径汇合。
  * 结论：门只判"有没有授权数据"；拿到数据后的处理在主程序里（同一个 2504 op 的
    VM 程序，两条路径 op 序列一致、数据不同）。
  * 授权明文在进程内存里不驻留（marker 全进程扫描 0 命中）。

推断（未证实，别当结论）：
  * VerifyDate 过期是否会让门判否 —— 没有样本，没法证实。
  * regcode 是否被本地做签名/校验和验证 —— 目前的证据反而倾向于"不验证或验证在
    VM 内"，因为离线注册程序 OfflineReg.exe 完全没有加密 API 导入。
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from . import const
from .license import LicenseRecord, regcode_syntax_ok


class Decision(str, Enum):
    NO_LICENSE = "no_license"        # 授权门："没有授权数据"分支
    HAS_LICENSE = "has_license"      # 授权门："有授权数据"分支（9-op 块）
    EXPIRED = "expired"              # 推断项：日期已过
    BAD_SYNTAX = "bad_regcode_syntax"  # 形态不对（本地可判，与 VM 无关）


@dataclass
class GateResult:
    decision: Decision
    detail: str

    @property
    def licensed(self) -> bool:
        return self.decision in (Decision.HAS_LICENSE,)


def evaluate(record: LicenseRecord, today: Optional[_dt.date] = None,
             check_syntax: bool = True, check_expiry: bool = False) -> GateResult:
    """按实证的门语义给判定。

    默认只做实证部分（有无授权数据）；check_expiry / check_syntax 打开后才会附带
    那两项推断/辅助检查，方便做实验时区分"门的判断"和"我们的附加判断"。
    """
    if not record.has_data:
        return GateResult(Decision.NO_LICENSE, "regcode 为空 -> 走无授权分支")

    if check_syntax and not regcode_syntax_ok(record.regcode):
        return GateResult(Decision.BAD_SYNTAX,
                          "regcode 形态不符合 %d×%d 分组/字符集"
                          % (const.REGCODE_GROUPS, const.REGCODE_GROUP_LEN))

    if check_expiry and record.is_expired(today):
        return GateResult(Decision.EXPIRED,
                          "VerifyDate=%s 已过期（推断项，未在真机证实）" % record.verify_date)

    return GateResult(Decision.HAS_LICENSE,
                      "有授权数据 -> 走 9-op 授权门块（op897..905）")


def is_licensed(record: LicenseRecord, **kwargs) -> bool:
    return evaluate(record, **kwargs).licensed
