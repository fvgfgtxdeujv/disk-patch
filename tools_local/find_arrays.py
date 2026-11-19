# -*- coding: utf-8 -*-
"""在完整镜像里找「连续 8 字节指针、全部落在 .vmp 范围内」的数组。
   运行期报告称：32 张数组 / 593 项 / 每项落点以 E9 开头（逻辑地址 RVA 0x62F000 起）。
"""
import struct, collections

IMG = open('/workspace/dgwork/unpack6201829/DiskGenius_image.bin', 'rb').read()
IB = 0x140000000
VMP_RVA, VMP_SIZE = 0x19D4000, 0x00DAC000
VMP_LO, VMP_HI = IB + VMP_RVA, IB + VMP_RVA + VMP_SIZE
CODE_END = IB + len(IMG)


def at(rva, n):
    return IMG[rva:rva + n]


runs = []
i = 0x62F000
end = 0x800000
cur = []
while i + 8 <= end:
    v = struct.unpack_from('<Q', IMG, i)[0]
    if VMP_LO <= v < VMP_HI:
        cur.append((i, v))
        i += 8
        continue
    if len(cur) >= 3:
        runs.append(cur)
    cur = []
    i += 8
if len(cur) >= 3:
    runs.append(cur)

print('找到连续指针段 %d 个，总项数 %d' % (len(runs), sum(len(r) for r in runs)))
runs.sort(key=len, reverse=True)
tot = 0
for r in runs[:40]:
    rva0 = r[0][0]
    # 落点首字节
    lead = collections.Counter()
    for _, v in r:
        off = v - VMP_LO
        if 0 <= off < VMP_SIZE:
            lead[open('/workspace/dgwork/unpack6201829/DiskGenius_unpacked_vmp.bin', 'rb').read(1)] += 0
    tot += len(r)
    print('  RVA %#09x  VA %#x  项数 %4d  首项 %#x  末项 %#x' %
          (rva0, IB + rva0, len(r), r[0][1], r[-1][1]))
print('前 40 段合计 %d 项' % tot)
