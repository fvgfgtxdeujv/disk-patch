import os, subprocess, glob, time, ctypes, signal
PREFIX="/tmp/zaka-20261119/wine64"; DGDIR="/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
env=dict(os.environ, WINEPREFIX=PREFIX, DISPLAY=":95")
xv=subprocess.Popen(["Xvfb",":95","-screen","0","1280x900x24"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(2)
p=subprocess.Popen(["/usr/lib/wine/wine64","DiskGenius.exe"],cwd=DGDIR,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print("Popen pid:", p.pid)
time.sleep(8)
cands=[]
for d in glob.glob("/proc/[0-9]*"):
    try: maps=open(d+"/maps",errors="ignore").read()
    except: continue
    if "DiskGenius.exe" in maps:
        cands.append(int(d.split("/")[-1]))
print("candidates:", cands)
libc=ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH=16; PTRACE_DETACH=17
for pid in cands:
    r=libc.ptrace(PTRACE_ATTACH, pid, None, None)
    ok = (r==0)
    err=ctypes.get_errno()
    print(f"attach {pid}: ret={r} errno={err} ({os.strerror(err) if err else 'ok'})")
    if ok:
        os.waitpid(pid, 0)
        try:
            with open(f"/proc/{pid}/mem","rb",0) as m:
                m.seek(0x140000000); print("  read at imagebase ok:", len(m.read(16)))
        except Exception as e: print("  mem read:", e)
        libc.ptrace(PTRACE_DETACH, pid, None, None)
p.terminate(); time.sleep(1)
subprocess.run(["wineserver","-k"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
xv.terminate()
