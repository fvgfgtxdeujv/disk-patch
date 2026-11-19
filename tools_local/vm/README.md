# tools_local/vm —— opcode 布局与语义提取

从**运行期镜像**（Wine dump 出来的解密态 50MB）提 VM 结构，不需要再跑目标。

```bash
export DG_IMG=/path/to/image_run.bin

python3 extract_handlers.py        # 661/49/1096 三张表 → 跟跳板 → 1806 个唯一 handler
python3 opsem3.py                  # 全部 661 个 op 的 packet 字段 + rel 偏移 → layouts.json
python3 opsem3.py 424 407 547      # 单看几个
python3 opsem2.py 424 --asm        # 带槽位追踪 + 反汇编
python3 lift.py 424                # unicorn 差分沙箱（ctx 哨兵法）
```

## 已知

- 表项是 `jmp rel32` 跳板，真 handler 多态生成、两两不重复 → 只能逐个提语义
- ctx：`+0xBC` = IP 指针，`+0xF5` = 表基址，`+0x6D`/`+0x178`/`+0xA4`... = 混淆累加器
- 派发尾：`op=u16@[IP+opoff]; IP += i32@[IP+reloff]; jmp table[op]`
- `reloff` 每个 op 不同，649/661 解出；`op=547` 的 `rel@+2` 已在 5 条真实轨迹上验证
- `lift.py` 能跑，但 handler 会解引用 ctx 内指针，**必须用真实 ctx 快照 + 单槽扰动**
