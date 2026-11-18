// 由 tableresolve.py 生成：把 VM 上下文里的 handler 表指针 dump 出来
// ctx 基址寄存器按实测是 rbp（若版本不同请改 CTX）
const CTX = "rbp";
const SLOTS = [0x4, 0x8, 0xF5, 0x110, 0x1F4];
const DISPATCH = [0x141D345C0, 0x141D356F4, 0x141D36731, 0x141D370B5, 0x141D3776A, 0x141D37932, 0x141D37C99, 0x141D381FB, 0x141D3AFC4, 0x141D3FE0F, 0x141D49269, 0x141D4B311, 0x141D4B9BF, 0x141D4C0A3, 0x141D4C70D, 0x141D4CA6A, 0x141D4D34E, 0x141D4DCCB, 0x141D4DEA2, 0x141D4E3FA, 0x141D4E7ED, 0x141D4F5ED, 0x141D50DD7, 0x141D51557, 0x141D51A22, 0x141D51BC5, 0x141D524CC, 0x141D527F2, 0x141D57FF8, 0x141D58670, 0x141D59368, 0x141D59747, 0x141D59D82, 0x141D5D2DA, 0x141D5D54E, 0x141D5D781, 0x141D5DB8D, 0x141D5E0E2, 0x141D61072, 0x141D6169F, 0x141D6208C, 0x141D62DE3, 0x141D638A3, 0x141D6418C, 0x141D64981, 0x141D65B93, 0x141D66D07, 0x141D67E65, 0x141D682F9, 0x141D68BA4, 0x141D68E5E, 0x141D69CE7, 0x141D6D5A7, 0x141D6DDA0, 0x141D6E79E, 0x141D6EAD4, 0x141D6F9D3, 0x141D71D38, 0x141D72460, 0x141D72DB2, 0x141D732A6, 0x141D73624, 0x141D74DC9, 0x141D75A40];

function dumpTables() {
    const ctx = this.context[CTX];
    SLOTS.forEach(function (off) {
        try {
            const p = ctx.add(off).readPointer();
            console.log("ctx+0x" + off.toString(16) + " -> table 0x" + p.toString(16));
            for (let i = 0; i < 64; i++) {
                const h = p.add(i * 8).readPointer();
                if (h.compare(ptr("0x0")) <= 0) break;
                console.log("  opcode 0x" + i.toString(16) + " -> handler 0x" + h.toString(16));
            }
        } catch (e) { console.log("slot 0x" + off.toString(16) + " 读取失败: " + e); }
    });
}

// 用法：在任一派发点处调用 dumpTables.call(this)，或挂 Interceptor
