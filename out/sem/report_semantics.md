# handler 语义提取（unicorn ctx-diff，实测）

约定：ctx 槽位=rbp+off；IP%+#x=相对初始 IP 的字节码偏移；tab[i]=派发表；初始 IP=BC+0x100，派发表 512 项全指向哨兵。


## op 101

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000111'] | 事件数(seed1..3): [23] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x9be41a468e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5997aab4c1c6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb04521606
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x55a7f07
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x15400c02
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x4c1c
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x2     size=2 val=0x3423
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x4521606
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x9be41a46
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x7aab
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0x11b  size=2 val=0x1119
- 反汇编 96 条，覆盖 0x1b8 字节 → disasm_101.txt

## op 197

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x1000010b'] | 事件数(seed1..3): [19] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x64b548c18e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5998b901d6a6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbef7b7944
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xef7b7944
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x3d6ffdeb
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x8b90
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=2 val=0x1201
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x64b548c1
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x1d6a
  - R ctx+0x11b  size=2 val=0x1119
  - R ctx+0x119  size=2 val=0xa5be
- 反汇编 122 条，覆盖 0x232 字节 → disasm_197.txt

## op 210

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000053'] | 事件数(seed1..3): [5] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb57aef1f2
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xf5   size=8 val=0x40000000
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x2     size=2 val=0x3423
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x57aef1f2
- 反汇编 162 条，覆盖 0x2bc 字节 → disasm_210.txt

## op 256

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x100000a6'] | 事件数(seed1..3): [14] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x859cc2f38e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c599111915ea6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbef7befdd
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x6     size=2 val=0x7867
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xef7befdd
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x859cc2f3
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x15ea
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x4     size=2 val=0x5645
- 反汇编 324 条，覆盖 0x5fd 字节 → disasm_256.txt

## op 263

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x1000002f'] | 事件数(seed1..3): [3] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x35641deb8e000fb5
- 事件流水 (seed1, 前 60 条):
  - W ctx+0xa2   size=1 val=0x0
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
- 反汇编 303 条，覆盖 0x583 字节 → disasm_263.txt

## op 297

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x100000f9'] | 事件数(seed1..3): [21] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x04601c2b8e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5991119c3516d
  - ctx+0x138: 0xd1ce86b4b642758d -> 0xb633fd3c4f42758d
  - ctx+0x140: 0xcc90c21d9d69a355 -> 0xcc90c21d9df32a2d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb7ffefbef
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x6     size=4 val=0x9a897867
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x75f29baa
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x4601c2b
  - R ctx+0x13f  size=4 val=0x69a355d1
  - W ctx+0x13f  size=4 val=0xf32a2db6
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - W ctx+0x13b  size=4 val=0x33fd3c4f
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x4     size=2 val=0x5645
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x7ffefbef
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0xc351
  - R ctx+0x13f  size=4 val=0x69a355d1
  - R ctx+0x119  size=2 val=0xa5be
- 反汇编 305 条，覆盖 0x600 字节 → disasm_297.txt

## op 395

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000110'] | 事件数(seed1..3): [25] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x021510948e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5991119651c6d
  - ctx+0x138: 0xd1ce86b4b642758d -> 0x8e2234027342758d
  - ctx+0x140: 0xcc90c21d9d69a355 -> 0xcc90c21d9dbd50a3
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb7fef7f8f
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x2     size=4 val=0x56453423
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0xa4   size=4 val=0x35641deb
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x4329418d
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0xd3f53cf5
  - R ctx+0x13f  size=4 val=0x69a355d1
  - W ctx+0x13f  size=4 val=0xbd50a38e
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - W ctx+0x13b  size=4 val=0x22340273
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=2 val=0x1201
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x7fef7f8f
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x2151094
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x651c
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0x13f  size=4 val=0x69a355d1
- 反汇编 171 条，覆盖 0x2f7 字节 → disasm_395.txt

## op 407

- 终止: ['other_mem:0x50008000'] | 事件数(seed1..3): [9] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c59911199b3e6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbea2269d8
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xea2269d8
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x9b3e
  - R ctx+0x119  size=2 val=0xa5be
- 反汇编 307 条，覆盖 0x5ff 字节 → disasm_407.txt

## op 409

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000105'] | 事件数(seed1..3): [21] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x72feee568e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c599111990e96d
  - ctx+0x138: 0xd1ce86b4b642758d -> 0x09efa7bdfe42758d
  - ctx+0x140: 0xcc90c21d9d69a355 -> 0xcc90c21d9d06822c
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbef7befdf
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x2     size=4 val=0x56453423
  - R ctx+0xa4   size=4 val=0x35641deb
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x62d26652
  - R ctx+0x13f  size=4 val=0x69a355d1
  - W ctx+0x13f  size=4 val=0x6822c09
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - W ctx+0x13b  size=4 val=0xefa7bdfe
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0xd     size=2 val=0xefde
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xef7befdf
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x72feee56
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x90e9
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0x13f  size=4 val=0x69a355d1
- 反汇编 337 条，覆盖 0x5ff 字节 → disasm_409.txt

## op 418

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000055'] | 事件数(seed1..3): [6] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb80f92e3b
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R ctx+0xf5   size=8 val=0x40000000
  - R IP+0x6     size=2 val=0x7867
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x80f92e3b
- 反汇编 135 条，覆盖 0x255 字节 → disasm_418.txt

## op 424

- 终止: ['other_mem:0x50007ff8'] | 事件数(seed1..3): [11] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x004405298e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5991119dc0d6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbea226208
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xea226208
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x440529
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0xdc0d
- 反汇编 295 条，覆盖 0x5fe 字节 → disasm_424.txt

## op 430

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000031'] | 事件数(seed1..3): [3] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=2 val=0x1201
  - R ctx+0xf5   size=8 val=0x40000000
- 反汇编 56 条，覆盖 0xda 字节 → disasm_430.txt

## op 446

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000022'] | 事件数(seed1..3): [2] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x16    size=2 val=0x8877
- 反汇编 360 条，覆盖 0x600 字节 → disasm_446.txt

## op 478

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000108'] | 事件数(seed1..3): [18] | IP 槽被改: [True, True, True]
- ctx diff (seed1):
  - ctx+0x0: 0x9e3779b97f4a7c15 -> 0x9e3779b900000000
  - ctx+0x10: 0x93bbf08b4d98d7a5 -> 0x93bbf08b4d980000
  - ctx+0x68: 0x5a147e0d3c47cf3d -> 0x0000000d3c47cf3d
  - ctx+0x70: 0x54d6b976236efd05 -> 0x54d6b976236efd00
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x000000008e5a0fb5
  - ctx+0xb0: 0x2ae894bd5ca86b45 -> 0x2ae894bd00000000
  - ctx+0xb8: 0x3000010043cf990d -> 0x6423130143cf990d
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c599000000006d
  - ctx+0x120: 0xe187d47a00ccec35 -> 0xe187d47a00cc0035
  - ctx+0x138: 0xd1ce86b4b642758d -> 0x000000000042758d
  - ctx+0x140: 0xcc90c21d9d69a355 -> 0xcc90c21d9d000000
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb00000000
- 事件流水 (seed1, 前 60 条):
  - W ctx+0x6d   size=4 val=0x0
  - W ctx+0xb0   size=4 val=0x0
  - W ctx+0x178  size=4 val=0x0
  - W ctx+0x11b  size=2 val=0x0
  - W ctx+0x119  size=2 val=0x0
  - W ctx+0x0    size=4 val=0x0
  - W ctx+0x13f  size=4 val=0x0
  - W ctx+0x13b  size=4 val=0x0
  - W ctx+0x10   size=2 val=0x0
  - W ctx+0xa4   size=4 val=0x0
  - W ctx+0x121  size=1 val=0x0
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x4     size=2 val=0x5645
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=4 val=0x34231201
  - R ctx+0xbc   size=8 val=0x30000100
  - W ctx+0xbc   size=8 val=0x64231301
  - R ctx+0xf5   size=8 val=0x40000000
- 反汇编 64 条，覆盖 0x135 字节 → disasm_478.txt

## op 508

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000129'] | 事件数(seed1..3): [26] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0xf79b734f8e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5999a3922926d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb4b117ec6
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x6     size=2 val=0x7867
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x55a64e1
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0xe58b514c
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x2292
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=2 val=0x1201
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x55a76e1
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0xf79b734f
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x9a39
  - R ctx+0xf5   size=8 val=0x40000000
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x8     size=2 val=0x9a89
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x4b117ec6
- 反汇编 303 条，覆盖 0x5ff 字节 → disasm_508.txt

## op 545

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000024'] | 事件数(seed1..3): [2] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x2     size=2 val=0x3423
- 反汇编 364 条，覆盖 0x5ff 字节 → disasm_545.txt

## op 547

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x100000ac'] | 事件数(seed1..3): [14] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x9e42b7bf8e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c599e3fca5be6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fbefffffdd
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x6     size=2 val=0x7867
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xefffefdd
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x9e42b7bf
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0xe3fc
  - R ctx+0xf5   size=8 val=0x40000000
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x0     size=2 val=0x1201
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xefffffdd
- 反汇编 101 条，覆盖 0x1bd 字节 → disasm_547.txt

## op 649

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x100000f9'] | 事件数(seed1..3): [21] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x2d3cc0a88e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c599081f931b6d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb36d3c62e
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x5     size=2 val=0x6756
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x559ad28
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x6e57d4dc
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x931b
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0xb     size=2 val=0xcdbc
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x36d3c62e
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x2d3cc0a8
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x81f
  - R ctx+0x11b  size=2 val=0x1119
- 反汇编 145 条，覆盖 0x296 字节 → disasm_649.txt

## op 80

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000105'] | 事件数(seed1..3): [20] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x796978bb8e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5996f8a71e56d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb2179a18d
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x9     size=2 val=0xab9a
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x3de69deb
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0x71e5
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x4     size=2 val=0x5645
  - R ctx+0x13b  size=4 val=0xce86b4b6
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0x2179a18d
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x796978bb
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x6f8a
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0x11b  size=2 val=0x1119
- 反汇编 114 条，覆盖 0x202 字节 → disasm_80.txt

## op 90

- 终止: ['uc_error:Invalid memory read (UC_ERR_READ_UNMAPPED)@0x10000106'] | 事件数(seed1..3): [20] | IP 槽被改: [False, False, False]
- ctx diff (seed1):
  - ctx+0xa0: 0x35641deb8e5a0fb5 -> 0x757f5dff8e5a0fb5
  - ctx+0x118: 0xe6c5991119a5be6d -> 0xe6c5994f7aafe66d
  - ctx+0x178: 0xa7e061fbef7be3cd -> 0xa7e061fb0000b57c
- 事件流水 (seed1, 前 60 条):
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0x9     size=2 val=0xab9a
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x6d   size=4 val=0x55a147e
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xef7bf3dd
  - R ctx+0xa4   size=4 val=0x35641deb
  - W ctx+0xa4   size=4 val=0x757f5dff
  - R ctx+0x121  size=1 val=0xec
  - R ctx+0x119  size=2 val=0xa5be
  - W ctx+0x119  size=2 val=0xafe6
  - R ctx+0xbc   size=8 val=0x30000100
  - R IP+0xb     size=2 val=0xcdbc
  - R ctx+0x178  size=4 val=0xef7be3cd
  - R ctx+0x178  size=4 val=0xef7be3cd
  - W ctx+0x178  size=4 val=0xb57c
  - R ctx+0x11b  size=2 val=0x1119
  - W ctx+0x11b  size=2 val=0x4f7a
  - R ctx+0x119  size=2 val=0xa5be
  - R ctx+0x11b  size=2 val=0x1119
- 反汇编 310 条，覆盖 0x600 字节 → disasm_90.txt
