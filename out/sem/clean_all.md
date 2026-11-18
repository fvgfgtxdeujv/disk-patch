# handler 去噪核心（模板化符号分析）


## op 80（43 行核心）

  r13    = ctx[IP]
  r13    = IP+0x9
  addr(r13   ) = rbp+0x178
  [dword ptr [r11]] or= 0x9e29d2a
  addr(rcx   ) = rbp+0x121
  jbe 0x10000067
  [word ptr [r14]] sub= r9w
  rdx    = ctx[IP]
  rdx    = IP+0x4
  addr(r14   ) = rbp+0x178
  [dword ptr [rax]] and= r13d
  [dword ptr [r10]] xor= 0x448fe550
  [word ptr [r14]] sub= r13w
  r15    = [word ptr [r15]] u16
  r14    = [word ptr [r14]] u16
  r14    = [qword ptr [r14]] u64
  [byte ptr [r15]] add= r14b
  pushfq (保存标志)
  rsi    = ctx[IP]
  rsi    = IP+0x8
  je 0x10000160
  rsi    = ctx[IP]
  rsi    = IP+0xb
  pop r10
  jmp 0x10000162
  pop r10
  r10    = ctx[TBL]
  r15    = [qword ptr [r15]] u64
  r15    = [word ptr [r15]] u16
  [dword ptr [rdi]] and= r15d
  r14    = ctx[TBL] u64
  r8     = ctx[IP]
  r8     = IP+0x0
  [qword ptr [rdx]] add= r10
  jmp r14   <<< 间接跳（派发/计算跳转）
  je 0x1003aa09
  jmp 0x10475dd7
  je 0xfd6803e
  jmp 0x10485c34
  ret   <<< VM 退出
  jmp 0x1047dd6b
  ret   <<< VM 退出
  jmp 0x104751e1

## op 90（69 行核心）

  r13    = ctx[IP]
  r13    = IP+0x9
  [dword ptr [rcx]] or= r9d
  [dword ptr [r11]] or= 0x757b5575
  addr(rdi   ) = rbp+0x121
  jbe 0x1000006e
  [word ptr [r13]] sub= r9w
  r12    = ctx[IP]
  r12    = IP+0xb
  addr(rsi   ) = rbp+0x13b
  [dword ptr [r13]] sub= r8d
  addr(r13   ) = rbp+0xa4
  [word ptr [r12]] add= r8w
  rdx    = [word ptr [rdx]] u16
  r11    = [word ptr [r11]] u16
  r11    = [qword ptr [r11]] u64
  [dword ptr [rdx]] add= r11d
  pushfq (保存标志)
  r14    = ctx[IP]
  r14    = IP+0x0
  je 0x10000169
  r14    = ctx[IP]
  r14    = IP+0x5
  pop r15
  jmp 0x1000016b
  pop r15
  addr(rdi   ) = rbp+0xbc
  rcx    = [qword ptr [rcx]] u64
  rcx    = [word ptr [rcx]] u16
  rdi    = [qword ptr [rdi]] u64
  [dword ptr [rsi]] sub= ecx
  rsi    = [qword ptr [rdi]] u64
  rbx    = ctx[IP]
  rbx    = IP+0x1
  [qword ptr [rax]] add= rdi
  jmp rsi   <<< 间接跳（派发/计算跳转）
  push 0x6b5b59ca
  push rax
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  pop qword ptr [rsp + 0x18]
  jmp 0x1027fa27
  push 0x37f869ab
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  jmp 0x103fc66e
  push r13
  pop r13
  jmp 0xfe28746
  push 0x6f8f72b0
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  jmp 0x103affa0
  rax    = [qword ptr [rax]] u64
  cx     = [word ptr [rax]] u16
  [dword ptr [r8]] xor= ecx
  [dword ptr [r13]] and= 0x79aaab03
  [word ptr [r9]] add= cx
  [dword ptr [r9]] sub= edx
  addr(r10   ) = rbp+0x70
  r10    = [qword ptr [r10]] u64
  r9     = [word ptr [r10]] u16
  [dword ptr [rdx]] or= r9d
  [dword ptr [rdx]] sub= 0x6c04a42e
  addr(rdx   ) = rbp+0x800
  jbe 0x10000547
  [word ptr [rax]] xor= r9w
  r10    = [word ptr [r10]] u16
  rbx    = [word ptr [rbx]] u16

## op 101（29 行核心）

  r12    = ctx[IP]
  r12    = IP+0x8
  [dword ptr [r11]] sub= edx
  [dword ptr [r14]] and= 0x55c1cc16
  addr(r13   ) = rbp+0x121
  jbe 0x1000006f
  [word ptr [r11]] add= dx
  rdi    = ctx[IP]
  rdi    = IP+0x2
  [dword ptr [rsi]] and= eax
  [dword ptr [rsi]] sub= 0x795bf1bc
  [word ptr [r10]] sub= ax
  addr(r8    ) = rbp+0x119
  r8     = [word ptr [r8]] u16
  r12    = [word ptr [r12]] u16
  r12    = [qword ptr [r12]] u64
  [qword ptr [r8]] add= r12
  [byte ptr [rdi]] xor= r15b
  r13    = [qword ptr [r13]] u64
  r8     = [qword ptr [r8]] u64
  r8     = [word ptr [r8]] u16
  [dword ptr [rcx]] add= r8d
  r12    = [qword ptr [r13]] u64
  r15    = ctx[IP]
  r15    = IP+0x4
  [qword ptr [r14]] add= r13
  jmp r12   <<< 间接跳（派发/计算跳转）
  jmp 0xfe8b58a
  jmp 0x104bbc84

## op 197（41 行核心）

  rdx    = ctx[IP]
  rdx    = IP+0x8
  addr(r10   ) = rbp+0x178
  addr(r9    ) = rbp+0x13b
  [dword ptr [rdx]] xor= r11d
  [dword ptr [rbx]] or= 0x94be5c3
  [word ptr [rax]] xor= r11w
  r13    = ctx[IP]
  r13    = IP+0x0
  addr(r13   ) = rbp+0x178
  [dword ptr [r9]] xor= 0x59dab52a
  addr(r11   ) = rbp+0x121
  jbe 0x100000c5
  [word ptr [r12]] xor= cx
  r13    = [word ptr [r13]] u16
  r11    = [word ptr [r11]] u16
  r13    = [qword ptr [r13]] u64
  pushfq (保存标志)
  r10    = ctx[IP]
  r10    = IP+0xc
  je 0x10000162
  r10    = ctx[IP]
  r10    = IP+0xa
  pop rsi
  jmp 0x10000163
  pop rsi
  [byte ptr [rdi]] sub= r11b
  r14    = [qword ptr [r14]] u64
  r9     = [qword ptr [r9]] u64
  r9     = [word ptr [r9]] u16
  [dword ptr [r10]] sub= r9d
  r12    = ctx[IP]
  r12    = IP+0x2
  [qword ptr [rax]] add= r14
  jmp r8   <<< 间接跳（派发/计算跳转）
  jmp 0x1049c28c
  jmp 0x1049d9d0
  jmp 0xfe7d9db
  jmp 0x10486efc
  jmp 0xfb931e3
  jmp 0x102ba362

## op 210（65 行核心）

  r9     = [qword ptr [r9]] u64
  r12    = [qword ptr [r12]] u64
  r12    = [word ptr [r12]] u16
  [dword ptr [r11]] xor= r12d
  addr(r12   ) = rbp+0x8
  rcx    = ctx[IP]
  rcx    = IP+0x4
  addr(r8    ) = rbp+0x6d
  addr(rbx   ) = rbp+0x178
  addr(r13   ) = rbp+0xa4
  addr(r12   ) = rbp+0x121
  jbe 0x100000bf
  [word ptr [rbx]] add= ax
  rsi    = ctx[IP]
  rsi    = IP+0x0
  [dword ptr [rdi]] add= ebx
  [dword ptr [r11]] add= 0x532f1e40
  [word ptr [r12]] add= bx
  r8     = [word ptr [r8]] u16
  r9     = [word ptr [r9]] u16
  r9     = [qword ptr [r9]] u64
  [byte ptr [rbx]] or= sil
  r15    = ctx[IP]
  r15    = IP+0x6
  addr(rax   ) = rbp+0xbc
  [qword ptr [rax]] add= rdx
  rcx    = [qword ptr [r12]] u64
  push rcx
  pop rsi
  jmp rsi   <<< 间接跳（派发/计算跳转）
  [qword ptr [rsp]] add= 8
  jmp 0x100002a1
  push rbx
  [dword ptr [rsp]] sub= 0x6ffd9da6
  pop rbx
  push r10
  push rcx
  pop rcx
  push r14
  pop r14
  pop r10
  jmp 0x100001c2
  push rcx
  push r13
  [dword ptr [rsp + 8]] add= r13d
  r13    = [qword ptr [rsp]] u64
  push qword ptr [rsp]
  pop rdx
  jmp 0x100001d4
  push 0x7dbf037b
  [dword ptr [rsp]] add= 0x5fbf8a10
  pop rbx
  push r14
  push r8
  push rsi
  pop rsi
  pop r8
  pop r14
  jmp 0x100001c2
  jmp 0x1009fc48
  rax    = [qword ptr [rsp + 0x10]] u64
  jmp 0xfcad618
  jmp 0xf9d37ad
  jmp 0xfdf657d
  pop rdi

## op 256（88 行核心）

  r14    = ctx[IP]
  r14    = IP+0x6
  [dword ptr [rax]] or= ebx
  [dword ptr [r14]] add= 0x5038a508
  addr(rdi   ) = rbp+0x121
  jbe 0x10000060
  [word ptr [r11]] sub= bx
  r12    = [word ptr [r12]] u16
  r15    = ctx[IP]
  r15    = IP+0x4
  push qword ptr [r10]
  pushfq (保存标志)
  rsi    = ctx[IP]
  rsi    = IP+0x8
  je 0x1000010b
  rsi    = ctx[IP]
  rsi    = IP+0x4
  r10w   = *(IP+0x4) u16   <<< 字节码字段
  pop r14
  jmp 0x1000010d
  pop r14
  [byte ptr [rcx]] or= bl
  addr(rsi   ) = rbp+0xbc
  addr(r12   ) = rbp+0xf5
  rsi    = [qword ptr [rsi]] u64
  r12    = [qword ptr [r12]] u64
  rsi    = [word ptr [rsi]] u16
  [dword ptr [r9]] and= esi
  rax    = ctx[IP]
  rax    = IP+0x0
  [qword ptr [r13]] add= r12
  jmp rbx   <<< 间接跳（派发/计算跳转）
  [qword ptr [rsp]] add= 8
  push qword ptr [rsp]
  jmp 0x10000255
  push 0x7fdec402
  push rbx
  [dword ptr [rsp + 8]] sub= ebx
  pop rbx
  rax    = [qword ptr [rsp]] u64
  push r13
  pop r13
  jmp 0x100001f6
  push rsi
  pop rsi
  [dword ptr [rsp]] sub= 0x55ff040b
  push qword ptr [rsp]
  pop rax
  push rsi
  [dword ptr [rsp + 8]] add= esi
  pop rsi
  pop rax
  push 0x7ffba708
  pop r9
  jmp 0x100001ad
  jmp 0x100002b2
  push rcx
  [dword ptr [rsp]] add= 0x657915c8
  pop rdx
  push r13
  pop rbp
  r13    = [qword ptr [rsp]] u64
  jmp 0x100001ad
  jmp 0x10106544
  [byte ptr [rax]] add= al
  r12    = ctx[S0x70]
  r10    = ctx[S0x70]
  push qword ptr [r9]
  push qword ptr [r13]
  pop qword ptr [r9]
  pop qword ptr [r13]
  rdx    = ctx[S0x70]
  rdi    = ctx[S0x70]
  push qword ptr [rbx]
  push qword ptr [r11]
  pop qword ptr [rbx]
  pop qword ptr [r11]
  rsi    = [qword ptr [rsi]] u64
  r11    = [word ptr [rsi]] u16
  [dword ptr [r12]] xor= r11d
  r10b   = [byte ptr [r13]] u8
  jbe 0x10000471
  [word ptr [rdx]] add= r11w
  r8     = [qword ptr [r8]] u64
  [dword ptr [rax]] sub= r12d
  [dword ptr [r14]] add= 0x4d076aa8
  [dword ptr [rbx]] xor= r12d
  [dword ptr [r10]] and= r12d

## op 263（120 行核心）

  addr(rcx   ) = rbp+0xa2
  r8     = ctx[IP]
  r8     = IP+0x8
  r15    = ctx[IP]
  r15    = IP+0xa
  je 0x1000005f
  je 0x1000005f
  jmp 0x1000007b
  push rcx
  je 0x1000007a
  addr(r15   ) = rbp+0xa2
  pop rcx
  jne 0x1000009e
  jne 0x1000009e
  addr(r15   ) = rbp+0xa2
  jne 0x100000d1
  jne 0x100000d1
  jne 0x100000d1
  addr(r15   ) = rbp+0xa2
  jne 0x100000f4
  jne 0x100000f4
  addr(r15   ) = rbp+0xa2
  jne 0x10000117
  je 0x10000117
  addr(r15   ) = rbp+0xa2
  jne 0x10000158
  je 0x1000013d
  addr(r15   ) = rbp+0xa2
  je 0x10000158
  addr(r15   ) = rbp+0xa2
  jne 0x1000019f
  jne 0x1000019f
  jne 0x1000019f
  addr(r15   ) = rbp+0xa2
  jne 0x100001d6
  jne 0x100001d6
  addr(r15   ) = rbp+0xa2
  jne 0x1000020d
  je 0x1000020d
  addr(r15   ) = rbp+0xa2
  jne 0x10000262
  je 0x10000234
  addr(r15   ) = rbp+0xa2
  je 0x10000262
  addr(r15   ) = rbp+0xa2
  jne 0x10000285
  jne 0x10000285
  addr(r15   ) = rbp+0xa2
  jne 0x100002a8
  jne 0x100002a8
  addr(r15   ) = rbp+0xa2
  jne 0x100002cb
  jne 0x100002cb
  addr(r15   ) = rbp+0xa2
  jne 0x100002ee
  je 0x100002ee
  addr(r15   ) = rbp+0xa2
  jne 0x10000311
  je 0x10000311
  addr(r15   ) = rbp+0xa2
  jne 0x10000334
  je 0x10000334
  addr(r15   ) = rbp+0xa2
  rbx    = ctx[IP]
  rbx    = IP+0x0
  addr(r14   ) = rbp+0xf5
  r9     = ctx[IP]
  r9     = IP+0x4
  addr(r14   ) = rbp+0xa2
  je 0x100003de
  je 0x100003cf
  [qword ptr [r14]] sub= r9
  jmp 0x100003dc
  [qword ptr [r14]] add= r9
  jmp rdi   <<< 间接跳（派发/计算跳转）
  r14    = ctx[IP]
  r13    = [qword ptr [r13]] u64
  r14    = IP+0xb
  r14    = *(IP+0xb) u16   <<< 字节码字段
  [dword ptr [rdx]] and= r14d
  r9     = ctx[IP]
  r9     = IP+0xd
  [qword ptr [rbx]] add= r13
  jmp r11   <<< 间接跳（派发/计算跳转）
  jmp 0x10000499
  push r8
  push rsi
  pop rsi
  [dword ptr [rsp + 8]] xor= r8d
  pop r8
  jmp 0x1000050d
  [qword ptr [rsp]] add= 8
  jmp 0x10000540
  push rax
  push 0x7bbfb616
  [dword ptr [rsp + 8]] add= edi
  rdi    = [qword ptr [rsp]] u64
  rax    = [qword ptr [rsp]] u64
  [dword ptr [rsp + 8]] sub= r11d
  r11    = [qword ptr [rsp]] u64
  pop rax
  jmp 0x100004ab
  push 0x7dfedaee
  push rdx
  push rbx
  pop rbx
  [dword ptr [rsp + 8]] add= edx
  pop rdx
  rdx    = [qword ptr [rsp]] u64
  jmp 0x10000499
  jmp 0x100352f3
  je 0xff91de1
  jmp 0x102acb04
  je 0xfed5628
  jmp 0x102f7fde
  jmp 0x102dc97a
  jmp 0x102e33ae
  jmp 0xfe40046
  jmp 0xfc45b16
  jmp 0xff59261

## op 297（57 行核心）

  r14    = ctx[IP]
  r14    = IP+0x6
  addr(r9    ) = rbp+0x178
  addr(r12   ) = rbp+0xa4
  [dword ptr [rbx]] xor= r15d
  [dword ptr [rax]] and= 0x4e07c3b
  [dword ptr [rax]] xor= r15d
  [dword ptr [rax]] sub= r15d
  r12    = ctx[IP]
  r12    = IP+0x4
  rbx    = *(IP+0x4) u16   <<< 字节码字段
  [dword ptr [r9]] or= ebx
  addr(r13   ) = rbp+0xa4
  addr(rdi   ) = rbp+0x121
  jbe 0x100000c4
  [word ptr [r14]] sub= bx
  addr(rsi   ) = rbp+0x13f
  rsi    = [word ptr [rsi]] u16
  [qword ptr [rsi]] add= r11
  addr(r12   ) = rbp+0xbc
  rbx    = ctx[TBL]
  r12    = [qword ptr [r12]] u64
  r12    = [word ptr [r12]] u16
  [dword ptr [r8]] sub= r12d
  r11    = ctx[TBL] u64
  r15    = ctx[IP]
  r15    = IP+0x0
  [qword ptr [r13]] add= rbx
  jmp r11   <<< 间接跳（派发/计算跳转）
  jmp 0xfd58d22
  jmp 0x10328c10
  jmp 0x1033d57a
  jmp 0x10330787
  jmp 0x10346b52
  jmp 0xf9bd978
  [byte ptr [rax]] add= al
  rbx    = [qword ptr [rbx]] u64
  rdx    = [word ptr [rbx]] u16
  addr(r10   ) = rbp+0x3f
  addr(r11   ) = rbp+0x178
  [dword ptr [r11]] or= edx
  jbe 0x10000331
  [word ptr [r9]] add= dx
  addr(rdi   ) = rbp+0x178
  [dword ptr [rbx]] add= r8d
  r12    = [qword ptr [r12]] u64
  je 0x100003e8
  [dword ptr [rax]] sub= 0x78de4d01
  r8     = [qword ptr [r8]] u64
  rax    = [word ptr [r8]] u16
  r11    = [qword ptr [r11]] u64
  rax    = [qword ptr [rax]] u64
  [dword ptr [r10]] or= r15d
  [dword ptr [rsi]] xor= 0x6ae29cd7
  [word ptr [r11]] xor= r15w
  r9     = [word ptr [r9]] u16
  r11    = [word ptr [r11]] u16

## op 395（72 行核心）

  rdx    = ctx[IP]
  rdx    = IP+0x2
  [dword ptr [r12]] and= r13d
  [dword ptr [r10]] sub= 0x616ee0f6
  [dword ptr [r8]] add= r13d
  [dword ptr [r14]] add= r13d
  r9     = ctx[IP]
  r9     = IP+0x0
  [dword ptr [rsi]] or= ecx
  [dword ptr [rax]] and= 0xe1d1394
  addr(r14   ) = rbp+0x121
  jbe 0x100000d3
  [word ptr [r12]] add= cx
  addr(rsi   ) = rbp+0x119
  rsi    = [word ptr [rsi]] u16
  [dword ptr [rsi]] and= r15d
  pushfq (保存标志)
  rdx    = ctx[IP]
  rdx    = IP+0x8
  sil    = *(IP+0x8) u8   <<< 字节码字段
  je 0x1000016d
  rdx    = ctx[IP]
  rdx    = IP+0x6
  pop r10
  jmp 0x1000016f
  pop r10
  addr(r14   ) = rbp+0xbc
  r13    = [qword ptr [r13]] u64
  r14    = [qword ptr [r14]] u64
  r13    = [word ptr [r13]] u16
  [dword ptr [r10]] sub= r13d
  r9     = [qword ptr [r14]] u64
  r12    = ctx[IP]
  r12    = IP+0xb
  [qword ptr [rbx]] add= r14
  jmp r9   <<< 间接跳（派发/计算跳转）
  jmp 0x100002c0
  [qword ptr [rsp]] add= 8
  push qword ptr [rsp]
  jmp 0x100002d0
  jmp 0x10000215
  [dword ptr [rsp]] sub= 0x6ff308f
  rbx    = [qword ptr [rsp]] u64
  push rcx
  push r10
  pop r10
  pop rcx
  jmp 0x100002c0
  push rax
  pop qword ptr [rsp]
  [dword ptr [rsp]] sub= 0x56a7414d
  rax    = [qword ptr [rsp]] u64
  push rdi
  pop rdi
  push 0x7fed2c1a
  push 0x7d399295
  pop qword ptr [rsp]
  push r11
  [dword ptr [rsp + 8]] add= r11d
  pop r11
  pop rdx
  jmp 0x100001f6
  jmp 0x100001f6
  jmp 0x103d828c
  je 0xfc76246
  jmp 0x1061e189
  je 0x1004b81d
  jmp 0x1062d24e
  ret   <<< VM 退出
  jmp 0x1068fbe8
  ret   <<< VM 退出
  jmp 0x1068c39f

## op 407（65 行核心）

  rax    = ctx[IP]
  rax    = IP+0x8
  addr(r12   ) = rbp+0x178
  [dword ptr [r11]] add= ecx
  addr(r14   ) = rbp+0xa4
  addr(rdi   ) = rbp+0x121
  jbe 0x1000005f
  [word ptr [rdx]] add= cx
  pop r10
  rbx    = ctx[IP]
  rbx    = IP+0x4
  je 0x100000bb
  [qword ptr [rcx]] add= 8
  r10    = [qword ptr [r10]] u64
  rax    = [qword ptr [rax]] u64
  rax    = [word ptr [rax]] u16
  rbx    = [qword ptr [r10]] u64
  r13    = ctx[IP]
  r13    = IP+0x0
  [qword ptr [rdi]] add= r10
  jmp rbx   <<< 间接跳（派发/计算跳转）
  jmp 0x105f8b24
  jmp 0x105eb46a
  jmp 0x102979d8
  jmp 0x1064cb09
  jmp 0x106ef69c
  jmp 0x105974a7
  r12    = ctx[S0x73]
  r14    = ctx[S0x73] u16
  [dword ptr [rbx]] xor= r14d
  [dword ptr [r13]] add= 0x67c5ccb
  jbe 0x1000023c
  [word ptr [rdi]] sub= r14w
  rdx    = [word ptr [rdx]] u16
  rdx    = [qword ptr [rdx]] u64
  r12    = [qword ptr [r12]] u64
  push qword ptr [rbx]
  pushfq (保存标志)
  addr(r8    ) = rbp+0x73
  r14    = [qword ptr [r14]] u64
  r8     = [qword ptr [r8]] u64
  je 0x100003b4
  r14    = ctx[S0x73]
  pop rdi
  jmp 0x100003bc
  pop rdi
  r15    = [word ptr [r8]] u16
  r15    = [qword ptr [r15]] u64
  addr(r10   ) = rbp+0x107
  je 0x1000040b
  [dword ptr [r10]] xor= 0x59383ad2
  rsi    = [qword ptr [rsi]] u64
  r11    = [qword ptr [r11]] u64
  rsi    = [word ptr [rsi]] u16
  [dword ptr [rax]] and= esi
  rsi    = [qword ptr [r11]] u64
  rdx    = [qword ptr [rdx]] u64
  [qword ptr [r9]] add= r11
  jmp rsi   <<< 间接跳（派发/计算跳转）
  jmp 0x10614cdd
  jmp 0x1061122a
  jmp 0x1060daa7
  jmp 0x1045ef52
  [dword ptr [r9]] xor= r15d
  r14    = [qword ptr [r14]] u64

## op 409（126 行核心）

  r8     = ctx[IP]
  r8     = IP+0x2
  addr(rbx   ) = rbp+0x178
  addr(r9    ) = rbp+0x178
  [dword ptr [rbx]] xor= 0x57b67bb9
  [dword ptr [r8]] sub= r11d
  [dword ptr [r12]] or= r11d
  rbx    = ctx[IP]
  rbx    = IP+0xd
  r8     = *(IP+0xd) u16   <<< 字节码字段
  addr(r13   ) = rbp+0x6d
  [dword ptr [r12]] or= r8d
  [dword ptr [rbx]] or= 0x70beaa16
  addr(r10   ) = rbp+0x121
  jbe 0x100000ce
  [word ptr [rcx]] xor= r8w
  r8     = [word ptr [r8]] u16
  [qword ptr [r8]] add= r14
  pushfq (保存标志)
  rsi    = ctx[IP]
  rsi    = IP+0x6
  je 0x10000152
  rsi    = ctx[IP]
  rsi    = IP+0x0
  pop rsi
  jmp 0x10000153
  pop rsi
  r12    = ctx[TBL]
  rsi    = [qword ptr [rsi]] u64
  rsi    = [word ptr [rsi]] u16
  [dword ptr [rdx]] xor= esi
  r13    = ctx[TBL] u64
  rdx    = ctx[IP]
  rdx    = IP+0x9
  [qword ptr [rcx]] add= r12
  jmp r13   <<< 间接跳（派发/计算跳转）
  rdi    = [qword ptr [rdi]] u64
  rdx    = [qword ptr [rdx]] u64
  rdi    = [word ptr [rdi]] u16
  rdi    = [qword ptr [rdi]] u64
  rdx    = [word ptr [rdx]] u16
  rdx    = [qword ptr [rdx]] u64
  pushfq (保存标志)
  rcx    = ctx[IP]
  rcx    = IP+0x2
  addr(r15   ) = rbp+0xfd
  r10    = [qword ptr [r15]] u64
  addr(rdi   ) = rbp+0xbc
  rcx    = ctx[IP]
  rdi    = [qword ptr [rdi]] u64
  rcx    = IP+0xc
  rcx    = *(IP+0xc) u16   <<< 字节码字段
  rdi    = [word ptr [rdi]] u16
  je 0x100002af
  [qword ptr [rcx]] sub= 2
  [qword ptr [rdi]] sub= 2
  jmp 0x100002bd
  [qword ptr [rcx]] add= 2
  [qword ptr [rdi]] add= 2
  r13    = ctx[IP]
  r13    = IP+0xe
  sil    = *(IP+0xe) u8   <<< 字节码字段
  je 0x1000030e
  r13    = ctx[IP]
  r13    = IP+0x0
  pop r14
  jmp 0x10000310
  pop r14
  addr(r10   ) = rbp+0xbc
  rax    = ctx[TBL]
  r10    = [qword ptr [r10]] u64
  r10    = [word ptr [r10]] u16
  [dword ptr [r15]] add= r10d
  rbx    = ctx[TBL] u64
  r14    = ctx[IP]
  r14    = IP+0x4
  [qword ptr [r13]] add= rax
  jmp rbx   <<< 间接跳（派发/计算跳转）
  push qword ptr [rsp]
  push qword ptr [rsp]
  rbx    = [qword ptr [rsp]] u64
  jmp 0xff8712a
  push 0x7fd599b1
  push 0x7faecd82
  push 0x7bbf3bad
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  jmp 0xf939433
  r12    = ctx[IP]
  r12    = IP+0x6
  r8     = *(IP+0x6) u16   <<< 字节码字段
  [dword ptr [rdi]] xor= r8d
  [dword ptr [r10]] add= 0x342aff50
  addr(rdx   ) = rbp+0x121
  jbe 0x10000433
  [word ptr [rdx]] add= r8w
  r12    = ctx[IP]
  r12    = IP+0x4
  r10w   = *(IP+0x4) u16   <<< 字节码字段
  [dword ptr [rbx]] add= r10d
  [dword ptr [r8]] xor= 0x4e1285f0
  [word ptr [r14]] xor= r10w
  r10    = [word ptr [r10]] u16
  r8     = [word ptr [r8]] u16
  r10    = [qword ptr [r10]] u64
  r8     = [qword ptr [r8]] u64
  je 0x10000504
  jmp 0x10000526
  r9     = ctx[IP]
  r9     = IP+0x2
  [byte ptr [rsi]] add= bl
  r15    = ctx[IP]
  r15    = IP+0x0
  r15    = *(IP+0x0) u16   <<< 字节码字段
  r12    = ctx[TBL]
  [dword ptr [rbx]] xor= r15d
  rbx    = ctx[TBL] u64
  r10    = ctx[IP]
  r10    = IP+0x8
  [qword ptr [r13]] add= r12
  jmp rbx   <<< 间接跳（派发/计算跳转）
  rsi    = ctx[IP]
  rsi    = IP+0xd
  rdi    = *(IP+0xd) u16   <<< 字节码字段
  [dword ptr [r9]] sub= edi
  addr(r9    ) = rbp+0xa4

## op 418（44 行核心）

  r12    = ctx[IP]
  r12    = IP+0x6
  rcx    = [qword ptr [rcx]] u64
  r12    = *(IP+0x6) u16   <<< 字节码字段
  [dword ptr [rax]] sub= r12d
  addr(r8    ) = rbp+0x8
  rdi    = ctx[IP]
  rdi    = IP+0x8
  rax    = *(IP+0x8) u16   <<< 字节码字段
  [dword ptr [r8]] sub= eax
  [dword ptr [rcx]] and= 0x40352ed9
  addr(r9    ) = rbp+0x121
  jbe 0x100000ca
  [word ptr [r12]] sub= ax
  r12    = ctx[IP]
  r12    = IP+0x0
  addr(rax   ) = rbp+0x13b
  [dword ptr [r11]] sub= edx
  [dword ptr [r8]] xor= 0x42bc4adf
  [word ptr [r9]] sub= dx
  r11    = [word ptr [r11]] u16
  r10    = [word ptr [r10]] u16
  r11    = [qword ptr [r11]] u64
  addr(rbx   ) = rbp+0x8
  r10    = [qword ptr [rbx]] u64
  push r10
  r15    = [qword ptr [r15]] u64
  [qword ptr [rdx]] add= rdi
  pop r11
  jmp r11   <<< 间接跳（派发/计算跳转）
  push rdi
  push r8
  pop r8
  pop rdi
  push r15
  push r8
  pop r8
  pop r15
  jmp 0x1039a8c7
  jmp 0x101dbf15
  jmp 0x107b4880
  jmp 0x10288505
  jmp 0x1000024a
  pushfq (保存标志)

## op 424（61 行核心）

  rcx    = ctx[IP]
  rcx    = IP+0x8
  [dword ptr [r13]] and= r11d
  [dword ptr [rsi]] and= 0x4ad6e539
  addr(rsi   ) = rbp+0x121
  jbe 0x1000006c
  [word ptr [r10]] add= r11w
  push rdx
  push rdx
  pop rdx
  rdx    = [qword ptr [rdx]] u64
  push rdx
  r15    = ctx[IP]
  r15    = IP+0x0
  [qword ptr [rdi]] sub= 8
  addr(rax   ) = rbp+0xf5
  r13    = [qword ptr [r13]] u64
  rax    = [qword ptr [rax]] u64
  rax    = [word ptr [rax]] u16
  [dword ptr [rbx]] and= eax
  r10    = [qword ptr [r13]] u64
  rbx    = ctx[IP]
  rbx    = IP+0x4
  [qword ptr [r12]] add= r13
  jmp r10   <<< 间接跳（派发/计算跳转）
  rbx    = IP+0x7bffb456
  rbx    = IP+0xdff6d870
  push r14
  pop r14
  rbx    = IP+0x153f41ecd
  jmp 0x104e6d09
  jmp 0x1031e4f1
  jmp 0x1053b2a0
  jmp 0x100a91fd
  jmp 0x100001a0
  [byte ptr [rbp + 0x49c45fe0]] or= cl
  rcx    = IP+0xc
  r13    = [qword ptr [r13]] u64
  rdx    = [qword ptr [rdx]] u64
  rbx    = [word ptr [rdx]] u16
  rbx    = [qword ptr [rbx]] u64
  [dword ptr [r15]] xor= r8d
  [dword ptr [rdi]] add= 0x6eb78409
  jbe 0x10000399
  [word ptr [rdx]] xor= r8w
  [dword ptr [r14]] sub= r12d
  r13    = [qword ptr [r13]] u64
  [dword ptr [r12]] sub= r14d
  [dword ptr [r8]] sub= 0x30c4f0b7
  [word ptr [r8]] add= r14w
  r11    = ctx[S0x70]
  edx    = ctx[S0x70] u32
  [dword ptr [rsi]] and= edx
  rsi    = ctx[S0x70]
  addr(r14   ) = rbp+0x70
  rdx    = [qword ptr [rdx]] u64
  [dword ptr [r14]] or= r15d
  r8     = [word ptr [rdx]] u16
  r8     = [qword ptr [r8]] u64
  rsi    = [word ptr [rsi]] u16
  r9     = [word ptr [r9]] u16

## op 430（26 行核心）

  rax    = ctx[IP]
  rax    = IP+0x0
  addr(r14   ) = rbp+0xf5
  rbx    = ctx[IP]
  rbx    = IP+0x4
  je 0x10000082
  [qword ptr [rbx]] sub= r8
  jmp 0x1000008f
  [qword ptr [rbx]] add= r8
  jmp r9   <<< 间接跳（派发/计算跳转）
  *(IP+0x0) add= al <<< 写字节码
  *(IP+0x0) add= al <<< 写字节码
  [byte ptr [rax - 0x7f]] add= cl
  *(IP+0x0) or= al <<< 写字节码
  *(IP+0x0) add= al <<< 写字节码
  push 0x2ff343f2
  push rax
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  pop qword ptr [rbx]
  jmp 0x10056c35
  push rbx
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  jmp 0x10359cb0
  pop rcx

## op 446（146 行核心）

  rcx    = ctx[IP]
  rcx    = IP+0x16
  push qword ptr [r10]
  rcx    = ctx[IP]
  rcx    = IP+0xc
  push qword ptr [rbx]
  r14    = ctx[IP]
  r14    = IP+0x6
  bx     = *(IP+0x6) u16   <<< 字节码字段
  push qword ptr [rbx]
  rbx    = ctx[IP]
  rbx    = IP+0xa
  push qword ptr [r8]
  rbx    = ctx[IP]
  rbx    = IP+0x1a
  push qword ptr [r9]
  r9     = ctx[IP]
  r9     = IP+0x1e
  push qword ptr [rdx]
  rcx    = ctx[IP]
  rcx    = IP+0x10
  push qword ptr [rax]
  r8     = ctx[IP]
  r8     = IP+0xe
  push qword ptr [r15]
  r8     = ctx[IP]
  r8     = IP+0x20
  pop qword ptr [r13]
  r8     = ctx[IP]
  r8     = IP+0x8
  pop qword ptr [rcx]
  r9     = ctx[IP]
  r9     = IP+0x18
  r10w   = *(IP+0x18) u16   <<< 字节码字段
  pop qword ptr [r10]
  r12    = ctx[IP]
  r12    = IP+0x22
  dx     = *(IP+0x22) u16   <<< 字节码字段
  pop qword ptr [rdx]
  r13    = ctx[IP]
  r13    = IP+0x24
  cx     = *(IP+0x24) u16   <<< 字节码字段
  pop qword ptr [rcx]
  r12    = ctx[IP]
  r12    = IP+0x4
  r10w   = *(IP+0x4) u16   <<< 字节码字段
  pop qword ptr [r10]
  r10    = ctx[IP]
  r10    = IP+0x0
  pop qword ptr [r12]
  rax    = ctx[IP]
  rax    = IP+0x1c
  cx     = *(IP+0x1c) u16   <<< 字节码字段
  pop qword ptr [rcx]
  r9     = ctx[TBL]
  r13    = ctx[IP]
  r13    = IP+0x2
  r13    = *(IP+0x2) u16   <<< 字节码字段
  [dword ptr [rbx]] and= r13d
  r12    = ctx[TBL] u64
  rbx    = ctx[IP]
  rbx    = IP+0x12
  [qword ptr [rax]] add= r9
  jmp r12   <<< 间接跳（派发/计算跳转）
  push r9
  push r15
  r15    = [qword ptr [rsp]] u64
  push rdx
  pop rdx
  pop r9
  jmp 0xfd9d93d
  push rdi
  push rax
  jb 0x100003bb
  push 0x65
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rbp + 0x50]] add= dl
  push 0x6bed2a7e
  [qword ptr [rsp + 8]] add= rbx
  pop rbx
  pop rbp
  jmp 0xfba1f14
  pop di
  jae 0x10000409
  pop rbx
  *(IP+0x8) add= r8b <<< 写字节码
  [byte ptr [rax]] add= al
  [byte ptr [rax]] add= al
  [byte ptr [rax + 1]] add= al
  [byte ptr [rax]] add= al
  jmp 0x1038ecda
  push rsp
  r13    = ctx[IP]
  r13    = IP+0x0
  rax    = *(IP+0x0) u16   <<< 字节码字段
  [dword ptr [r9]] add= eax
  [dword ptr [r15]] xor= 0x400a64d5
  addr(r15   ) = rbp+0x121
  jbe 0x1000042a
  [word ptr [r12]] sub= ax
  rax    = ctx[IP]
  rax    = IP+0x8
  addr(r9    ) = rbp+0xa4
  [dword ptr [rbx]] xor= r11d
  addr(r9    ) = rbp+0xa4
  [dword ptr [r8]] add= r11d
  [dword ptr [rax]] and= r11d
  addr(r11   ) = rbp+0x119
  r11    = [word ptr [r11]] u16
  r11    = [qword ptr [r11]] u64
  r10    = ctx[IP]
  r10    = IP+0xa
  r13w   = *(IP+0xa) u16   <<< 字节码字段
  push qword ptr [r13]
  pushfq (保存标志)
  rdx    = ctx[IP]
  rdx    = IP+0x9
  je 0x10000542
  rdx    = ctx[IP]
  rdx    = IP+0xa
  pop rsi
  jmp 0x10000543
  pop rsi
  [byte ptr [rbx]] xor= r15b
  addr(r8    ) = rbp+0xf5
  r11    = ctx[IP]
  r11    = IP+0x2
  r8     = [qword ptr [r8]] u64
  r11    = *(IP+0x2) u16   <<< 字节码字段
  [dword ptr [rdx]] and= r11d
  r14    = [qword ptr [r8]] u64
  rdx    = ctx[IP]
  rdx    = IP+0x4
  [qword ptr [rcx]] add= r8
  jmp r14   <<< 间接跳（派发/计算跳转）
  r8     = ctx[IP]
  r8     = IP+0x0
  rdx    = *(IP+0x0) u16   <<< 字节码字段
  addr(rax   ) = rbp+0x178

## op 478（24 行核心）

  addr(r12   ) = rbp+0x6d
  addr(r11   ) = rbp+0xb0
  addr(rsi   ) = rbp+0x178
  addr(r13   ) = rbp+0x11b
  addr(r10   ) = rbp+0x119
  addr(rdi   ) = rbp+0x0
  addr(rbx   ) = rbp+0x13f
  addr(rax   ) = rbp+0x13b
  addr(rbx   ) = rbp+0x10
  addr(r8    ) = rbp+0xa4
  addr(r11   ) = rbp+0x121
  r8     = ctx[IP]
  r8     = IP+0x4
  r11    = ctx[IP]
  r11    = IP+0x0
  [qword ptr [r10]] add= r12
  addr(rsi   ) = rbp+0xf5
  r12    = [qword ptr [r15]] u64
  jmp r12   <<< 间接跳（派发/计算跳转）
  jmp 0x105597c4
  jmp 0x105af292
  jmp 0x101c66c3
  jmp 0x105aba1a
  pop rdi

## op 508（51 行核心）

  r14    = ctx[IP]
  r14    = IP+0x6
  [dword ptr [r11]] xor= edi
  [dword ptr [rcx]] sub= 0x4fd8cc9f
  addr(rbx   ) = rbp+0x121
  jbe 0x10000064
  [word ptr [rbx]] xor= di
  r11    = ctx[IP]
  r11    = IP+0x0
  addr(rbx   ) = rbp+0x13b
  [dword ptr [r8]] or= r10d
  [dword ptr [r13]] or= 0x5710324f
  [word ptr [r8]] sub= r10w
  addr(r10   ) = rbp+0xf5
  r12    = [qword ptr [r12]] u64
  r10    = [qword ptr [r10]] u64
  r10    = [word ptr [r10]] u16
  [dword ptr [rdx]] add= r10d
  addr(rax   ) = rbp+0x8
  r9     = [word ptr [r9]] u16
  r11    = [word ptr [r11]] u16
  r9     = [qword ptr [r9]] u64
  r12    = ctx[IP]
  r12    = IP+0x2
  r14    = [qword ptr [r10]] u64
  push r14
  [qword ptr [r15]] add= rax
  ret   <<< VM 退出
  ret   <<< VM 退出
  r12    = IP+0x22
  r13    = [qword ptr [r13]] u64
  r12    = IP+0x822
  rbx    = [word ptr [r13]] u16
  [dword ptr [rdx]] xor= ebx
  jbe 0x100002b9
  [word ptr [r14]] xor= bx
  r10    = [qword ptr [r10]] u64
  rdx    = [qword ptr [rdx]] u64
  r14    = [word ptr [rdx]] u16
  r14    = [qword ptr [r14]] u64
  [dword ptr [r10]] and= r15d
  [dword ptr [r13]] xor= 0x79a9b4d4
  [dword ptr [r10]] xor= r15d
  [dword ptr [rax]] add= r15d
  rcx    = [qword ptr [rcx]] u64
  r15d   = [dword ptr [r15]] u32
  rsi    = [word ptr [rsi]] u16
  r12    = [word ptr [rcx]] u16
  pushfq (保存标志)
  addr(r11   ) = rbp+0x70
  r11    = [qword ptr [r11]] u64

## op 545（157 行核心）

  r13    = ctx[IP]
  r13    = IP+0x2
  push qword ptr [rdi]
  rcx    = ctx[IP]
  rcx    = IP+0x12
  di     = *(IP+0x12) u16   <<< 字节码字段
  push qword ptr [rdi]
  rcx    = ctx[IP]
  rcx    = IP+0x1a
  push qword ptr [r13]
  rsi    = ctx[IP]
  rsi    = IP+0x8
  push qword ptr [r15]
  r8     = ctx[IP]
  r8     = IP+0x6
  r13w   = *(IP+0x6) u16   <<< 字节码字段
  push qword ptr [r13]
  rcx    = ctx[IP]
  rcx    = IP+0x0
  r13w   = *(IP+0x0) u16   <<< 字节码字段
  push qword ptr [r13]
  rbx    = ctx[IP]
  rbx    = IP+0x1c
  pop qword ptr [rcx]
  r14    = ctx[IP]
  r14    = IP+0x10
  pop qword ptr [rax]
  r12    = ctx[IP]
  r12    = IP+0xa
  pop qword ptr [r8]
  r8     = ctx[IP]
  r8     = IP+0xe
  r15w   = *(IP+0xe) u16   <<< 字节码字段
  pop qword ptr [r15]
  rbx    = ctx[IP]
  rbx    = IP+0xc
  pop qword ptr [rdx]
  r12    = ctx[IP]
  r12    = IP+0x18
  r15w   = *(IP+0x18) u16   <<< 字节码字段
  pop qword ptr [r15]
  [byte ptr [r12]] add= dl
  addr(rsi   ) = rbp+0xbc
  addr(r10   ) = rbp+0xf5
  rsi    = [qword ptr [rsi]] u64
  r10    = [qword ptr [r10]] u64
  rsi    = [word ptr [rsi]] u16
  [dword ptr [rax]] and= esi
  rax    = [qword ptr [r10]] u64
  rbx    = ctx[IP]
  rbx    = IP+0x14
  [qword ptr [rdi]] add= r10
  jmp rax   <<< 间接跳（派发/计算跳转）
  jmp 0x10222a6f
  jmp 0x10283e84
  jmp 0xf9338db
  jmp 0x1029bf6b
  jmp 0xf95ea42
  jmp 0xf95ea34
  pop rdi
  pushfq (保存标志)
  jg 0x100002f2
  jg 0x100002d7
  pop rdx
  push r14
  pop r14
  push 0x6f3966d3
  push 0x7f7fcc48
  push r8
  pop qword ptr [rsp + 8]
  pop r8
  push rax
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  push 0x357f7dfa
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  push qword ptr [rsp + 0x20]
  push qword ptr [rsp]
  rax    = [qword ptr [rsp]] u64
  push qword ptr [rsp + 0x10]
  push qword ptr [rsp]
  rbx    = [qword ptr [rsp]] u64
  push rbx
  push rax
  pop rbx
  push r13
  pop r13
  pop rbx
  pop qword ptr [rsp + 0x10]
  push r9
  pop qword ptr [rsp + 0x28]
  push qword ptr [rsp]
  pop r9
  push qword ptr [rsp]
  push qword ptr [rsp]
  rbx    = [qword ptr [rsp]] u64
  push qword ptr [rsp]
  rax    = [qword ptr [rsp]] u64
  push 0x7379e567
  push rdx
  pop qword ptr [rsp]
  push r9
  r9     = [qword ptr [rsp]] u64
  jmp 0x10014e1c
  dl     = [byte ptr [rsi]] u8
  jmp 0xfc54fef
  jmp 0xfe1b008
  jmp 0xffffffffccc18516
  [byte ptr [rax]] add= al
  [byte ptr [rbp - 0x75]] add= cl
  [dword ptr [rcx - 0x7f]] or= ecx
  [byte ptr [rax]] add= al
  r8     = [byte ptr [r9]] u8
  [dword ptr [rax]] add= r8d
  [dword ptr [rbx]] add= 0x52d2c99
  [dword ptr [rax]] sub= r8d
  addr(rcx   ) = rbp+0x13b
  r13    = ctx[IP]
  r13    = IP+0x1
  r11    = *(IP+0x1) u16   <<< 字节码字段
  [dword ptr [rax]] sub= r11d
  [dword ptr [rsi]] xor= 0x3f0da85c
  addr(r8    ) = rbp+0x121
  jbe 0x10000499
  [word ptr [r8]] xor= r11w
  addr(rsi   ) = rbp+0x13f
  r13    = [word ptr [r13]] u16
  r11    = ctx[IP]
  r11    = IP+0x3
  di     = *(IP+0x3) u16   <<< 字节码字段
  push qword ptr [rdi]
  pushfq (保存标志)
  r10    = ctx[IP]
  r10    = IP+0xb
  dl     = *(IP+0xb) u8   <<< 字节码字段
  je 0x1000054f
  r10    = ctx[IP]
  r10    = IP+0x3
  dx     = *(IP+0x3) u16   <<< 字节码字段
  pop r10
  jmp 0x10000551
  pop r10
  [byte ptr [rdi]] xor= r9b
  rbx    = ctx[IP]
  rbx    = IP+0x5
  rcx    = [qword ptr [rcx]] u64
  rbx    = *(IP+0x5) u16   <<< 字节码字段
  [dword ptr [r11]] or= ebx
  rsi    = [qword ptr [rcx]] u64
  r11    = ctx[IP]
  r11    = IP+0x7
  [qword ptr [r14]] add= rcx
  jmp rsi   <<< 间接跳（派发/计算跳转）
  r10    = ctx[IP]
  r10    = IP+0x2
  rax    = *(IP+0x2) u16   <<< 字节码字段

## op 547（34 行核心）

  rdx    = ctx[IP]
  rdx    = IP+0x6
  addr(rdi   ) = rbp+0x178
  [dword ptr [r14]] or= r15d
  [dword ptr [r14]] add= 0x68de99d4
  [word ptr [rax]] sub= r15w
  r14    = [qword ptr [r14]] u64
  r11    = [qword ptr [r11]] u64
  r11    = [word ptr [r11]] u16
  addr(rsi   ) = rbp+0x178
  [dword ptr [r12]] or= r11d
  rdi    = [qword ptr [r14]] u64
  addr(rcx   ) = rbp+0x8
  r11    = ctx[IP]
  r11    = IP+0x8
  rax    = *(IP+0x8) u16   <<< 字节码字段
  addr(r9    ) = rbp+0x178
  [dword ptr [rbx]] sub= eax
  addr(r10   ) = rbp+0xa4
  addr(rdi   ) = rbp+0x121
  jbe 0x1000011d
  [word ptr [rcx]] add= ax
  r14    = [word ptr [r14]] u16
  rax    = [word ptr [rax]] u16
  r14    = [qword ptr [r14]] u64
  addr(r10   ) = rbp+0x8
  rbx    = [qword ptr [rbx]] u64
  push r8
  [qword ptr [r10]] add= rsi
  pop rcx
  jmp rcx   <<< 间接跳（派发/计算跳转）
  [byte ptr [rax]] add= al
  jae 0x100001c4
  jb 0x10000148

## op 649（54 行核心）

  r14    = ctx[IP]
  r14    = IP+0x5
  [dword ptr [r13]] sub= esi
  [dword ptr [rdi]] xor= 0x5b33c937
  addr(r14   ) = rbp+0x121
  jbe 0x10000068
  [word ptr [r11]] xor= si
  rdi    = ctx[IP]
  rdi    = IP+0xb
  addr(rdi   ) = rbp+0x178
  [dword ptr [r12]] add= r10d
  [dword ptr [r11]] xor= 0x436b1474
  [word ptr [r12]] xor= r10w
  r13    = [word ptr [r13]] u16
  r13    = [qword ptr [r13]] u64
  r13    = [qword ptr [r13]] u64
  r12    = [word ptr [r12]] u16
  pushfq (保存标志)
  rdi    = ctx[IP]
  rdi    = IP+0x4
  je 0x10000163
  rdi    = ctx[IP]
  rdi    = IP+0x7
  pop r8
  jmp 0x10000165
  pop r8
  addr(rsi   ) = rbp+0xf5
  addr(r9    ) = rbp+0xbc
  rsi    = [qword ptr [rsi]] u64
  r9     = [qword ptr [r9]] u64
  r9     = [word ptr [r9]] u16
  r11    = [qword ptr [rsi]] u64
  r13    = ctx[IP]
  r13    = IP+0x0
  [qword ptr [r14]] add= rsi
  jmp r11   <<< 间接跳（派发/计算跳转）
  push qword ptr [rsp]
  push qword ptr [rsp]
  jmp 0xf92aba8
  push 0x73dc75e6
  push 0x5df3bf84
  push 0x7d9ffddc
  pop qword ptr [rsp]
  pop qword ptr [rsp]
  jmp 0x100f41ae
  jmp 0xfb9806f
  jmp 0xfe743a0
  push r10
  push 0x7df7070d
  pop rcx
  pop r10
  jmp 0xffdcbf0
  jmp 0x100dfdf5
  jmp 0x100dfe0b
