import pefile, re, json
p = r'out/runtime/DiskGenius/DiskGenius.exe'
data = open(p, 'rb').read()
pe = pefile.PE(p, fast_load=True)
print('base', hex(pe.OPTIONAL_HEADER.ImageBase), 'size', len(data))
for i, s in enumerate(pe.sections):
    print(i, repr(s.Name), hex(s.VirtualAddress), hex(s.Misc_VirtualSize), hex(s.SizeOfRawData), hex(s.PointerToRawData), hex(s.Characteristics))

secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def off2va(off):
    for va, vs, raw, rsz in secs:
        if raw <= off < raw + rsz:
            return pe.OPTIONAL_HEADER.ImageBase + va + (off - raw)
    return None

needles = ['[license]', '[LicenseInfo]', 'Options.ini', 'regver', 'appname=', 'license=', 'VerifyDate', 'OfflineReg.dat', '&skey=', 'encryption=']
for n in needles:
    for enc, tag in (('utf-16-le', 'u16'), ('latin1', 'a')):
        b = n.encode(enc)
        hits = []
        st = 0
        while True:
            i = data.find(b, st)
            if i < 0: break
            hits.append((i, off2va(i)))
            st = i + 1
            if len(hits) > 6: break
        if hits:
            print(n, tag, [(hex(i), hex(v) if v else None) for i, v in hits[:6]])
