"""从 DiskGenius 6.2.0.1829 x64 实测提取的授权层常量。

每一条都标了来源，避免"猜出来的常量"混进实现里。
source:
  POOL   = 运行期解密段 0x1406B3xxx 的 UTF-16 字符串池（本机 Wine 进程内存实测）
  REG    = WINEDEBUG=+reg 启动追踪（HKCU\\Software\\Eassos\\DiskGenius\\Reg\\ 被打开，值 license/Improveplan/ShowLicense 被查询）
  INI    = 程序自己写出的 Options.ini 实测内容
  REQ    = 运行期堆上拼好的请求串（本机 Wine 进程内存实测，见 SAMPLE_QUERY）
"""

# ---- 注册表（source: REG）------------------------------------------------
REG_KEY = r"Software\Eassos\DiskGenius\Reg"
REG_VALUE_LICENSE = "license"
REG_VALUE_IMPROVEPLAN = "Improveplan"
REG_VALUE_SHOWLICENSE = "ShowLicense"

# ---- Options.ini（source: INI）------------------------------------------
INI_NAME = "Options.ini"
INI_SECTION = "LicenseInfo"
INI_SHOW_KEY = "Show"

# ---- 授权记录字段（source: POOL 里连续排列的字段名）----------------------
FIELD_APPNAME = "appname"
FIELD_USER = "user"
FIELD_EMAIL = "email"
FIELD_REGCODE = "regcode"
FIELD_REGVER = "regver"
FIELD_VERIFYDATE = "VerifyDate"
LICENSE_FIELDS = (
    FIELD_APPNAME,
    FIELD_USER,
    FIELD_EMAIL,
    FIELD_REGCODE,
    FIELD_REGVER,
    FIELD_VERIFYDATE,
)

VERIFY_DATE_FORMAT = "%04d%02d%02d"

# ---- 字符串池里与授权/联网有关的格式串（source: POOL）--------------------
POOL_STRINGS = (
    "Remind",
    "LicenseInfo",
    "OfflineReg.exe",
    "VerifyDate",
    "license",
    "%04d%02d%02d",
    "appname",
    "user",
    "email",
    "regcode",
    "regver",
    "eassos@eassos.cn",
    "&diskinfo%ld=%s",
    "%04X",
    "&otherinfo=%s&tmp=%s",
    "ver=%s&code=%s&name=%s&email=%s&mid=%s&applang=%s%s",
    "&check=",
    "%s%cencryption=%s&appname=%s",
    "%s%cver=%s&code=%s&name=%s&email=%s&mid=%s&appname=%s&applang=%s",
    "&skey=",
    "OfflineReg.dat",
    "\\OfflineReg.exe",
    "Options.ini",
    "Error:CanTempRegister",
)

# ---- 运行期实测请求串（source: REQ）--------------------------------------
# ver / winver / winbits / reslang / syslang / cpu / mid / lid / otherinfo / iplan / appname / appcs
SAMPLE_QUERY = (
    "ver=6.2.0.1829_x64_pro_eng"
    "&winver=10%2e0%2e19043%2esp0%2e0%2e00000000"
    "&winbits=64&reslang=eng&syslang=eng&cpu=64"
    "&mid=k_\x02OD\x03Ikgn%1B%1D%12HLHLL%1A%1AH%1A%1AL%18%1B"
    "&lid=&otherinfo=&iplan=Y&appname=DiskGenius&appcs=0"
)

# 同一条请求里 mid 参数的原文（不含前缀 key，便于逐字节核对编码规则）
SAMPLE_MID = "k_\x02OD\x03Ikgn%1B%1D%12HLHLL%1A%1AH%1A%1AL%18%1B"

# ---- 注册码形态（source: 假授权实测值 + 界面输入框）----------------------
REGCODE_GROUPS = 5
REGCODE_GROUP_LEN = 4
REGCODE_SEP = "-"
# 观测样本 QK7X-M2PV-ZLHD-W8CT-RBNQ 用到的字符集；字母数字，无 I/O/1/0 的证据不足，
# 因此这里只把"观测到出现过的"作为确定集，其余用宽松集合，校验时可切换严格度。
REGCODE_ALPHABET_OBSERVED = "A2BCDHKLMNPVQRWXZ4J7Y"
REGCODE_ALPHABET_LOOSE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# ---- OfflineReg.exe 的导入表结论（source: PE 导入表实测）----------------
# 只有 WINHTTP / KERNEL32 / USER32 / ...，没有 crypt32、bcrypt、advapi32 的加密 API。
OFFLINEREG_CRYPTO_IMPORTS = ()
