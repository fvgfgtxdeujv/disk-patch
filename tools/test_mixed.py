# -*- coding: utf-8 -*-
"""混合派发形态载荷：召回率 / 精度 / 耗时"""
import time, sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x86il_dispatch as D

CB = 0x400000          # 低基址，让 32 位跳表位移可编码

ASM = r"""
# ---------- 派发器 1：cmp 链，r12b 选择子 ----------
disp1:
    mov  rax, [rbp+0x92]
    movzx r12d, byte ptr [rax]
    cmp  r12b, 0x10
    je   h10
    cmp  r12b, 0x11
    je   h11
    cmp  r12b, 0x12
    je   h12
    cmp  r12b, 0x13
    je   h13
    jmp  vm_exit

# ---------- 派发器 2：递减测试链 ----------
disp2:
    mov  rax, [rbp+0x92]
    movzx ecx, byte ptr [rax+1]
    sub  ecx, 0x20
    jz   h20
    dec  ecx
    jz   h21
    dec  ecx
    jz   h22
    jmp  vm_exit

# ---------- 派发器 3：opcode 被 xor 混淆 ----------
disp3:
    mov  rax, [rbp+0x92]
    movzx edx, byte ptr [rax+2]
    xor  edx, 0x5A
    cmp  dl, 0x6A
    je   h30
    cmp  dl, 0x6B
    je   h31
    jmp  vm_exit

# ---------- 派发器 4：跳表 ----------
disp4:
    mov  rax, [rbp+0x92]
    movzx esi, byte ptr [rax+3]
    sub  esi, 0x40
    jmp  qword ptr [rsi*8 + tbl]

# ---------- handlers ----------
h10: mov rax,[rbp+0x0]
     mov [rbp+0x10],rax
     jmp disp1
h11: mov rax,[rbp+0x8]
     add rax,[rbp+0x0]
     mov [rbp+0x10],rax
     jmp disp1
h12: mov eax,dword ptr [rbp+0x0]
     xor eax,dword ptr [rbp+0x8]
     mov dword ptr [rbp+0x10],eax
     jmp disp1
h13: mov rax,[rbp+0x0]
     not rax
     mov [rbp+0x10],rax
     jmp disp1
h20: mov rax,[rbp+0x0]
     shl rax,3
     mov [rbp+0x10],rax
     jmp disp1
h21: mov rax,[rbp+0x0]
     shr rax,2
     mov [rbp+0x10],rax
     jmp disp1
h22: mov rax,[rbp+0x8]
     imul rax,rax,7
     mov [rbp+0x10],rax
     jmp disp1
h30: mov rax,[rbp+0x0]
     rol rax,5
     mov [rbp+0x10],rax
     jmp disp1
h31: mov rax,[rbp+0x0]
     ror rax,5
     mov [rbp+0x10],rax
     jmp disp1
h40: mov rax,[rbp+0x0]
     neg rax
     mov [rbp+0x10],rax
     jmp disp1
h41: mov rax,[rbp+0x0]
     bswap rax
     mov [rbp+0x10],rax
     jmp disp1
h42: mov rax,[rbp+0x8]
     sub rax,[rbp+0x0]
     mov [rbp+0x10],rax
     jmp disp1

# ---------- 干扰：普通函数里的 64 位比较，不应被认成派发 ----------
normal_fn:
    mov  rax, [rdi+0x8]
    cmp  rax, 0x5
    je   normal_a
    cmp  rax, 0x6
    je   normal_b
    ret
normal_a:
    ret
normal_b:
    ret

vm_exit:
    ret

.balign 8, 0x90
tbl:
    .quad h40, h41, h42
    .quad 0
"""

EXPECT = {0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x30, 0x31, 0x40, 0x41, 0x42}

payload = D._build(ASM, code_base=CB)
open('payload_mixed.bin', 'wb').write(payload)
print("[*] 载荷 %d 字节，期望 opcode %d 个" % (len(payload), len(EXPECT)))

t0 = time.time()
r = D.discover(payload, CB)
dt = time.time() - t0

found = {op for op in r['scored'] if op is not None}
print("[*] 发现 %d 个 opcode，耗时 %.3fs" % (len(found), dt))
print()
D.report(r, verbose=True)

hit = found & EXPECT
miss = EXPECT - found
extra = found - EXPECT
print()
print("=" * 70)
print("召回率: %d/%d = %.1f%%" % (len(hit), len(EXPECT), 100.0 * len(hit) / len(EXPECT)))
print("漏检  : %s" % (', '.join('0x%02X' % x for x in sorted(miss)) or '无'))
print("误报  : %s" % (', '.join('0x%02X' % x for x in sorted(extra)) or '无'))

# handler 目标是否互不相同且落在 handler 区
tg = {}
for op, d in r['scored'].items():
    if op is not None:
        tg.setdefault(d['best']['target'], []).append(op)
alias = {k: v for k, v in tg.items() if len(v) > 1}
print("别名  : %s" % (alias or '无（本载荷每个 opcode 独立）'))

# 每个 handler 应当被识别为「访问 VM 上下文 + 以 jmp 收尾」
bad_h = [hex(op) for op, d in r['scored'].items()
         if op is not None and (d['best']['ctx_refs'] == 0 or not d['best']['ends_jmp'])]
print("handler 特征不符: %s" % (bad_h or '无'))

ok = (not miss) and (not extra)
print("\n%s" % ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
