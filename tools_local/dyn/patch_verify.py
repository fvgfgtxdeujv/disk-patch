import os, subprocess, time, ctypes
PREFIX="/tmp/zaka-20261119/wine64"; DGDIR="/tmp/zaka-20261119/disk-patch/dg/DiskGenius"
INI=os.path.join(DGDIR,"Options.ini"); LOADER="/usr/lib/wine/wine64"
libc=ctypes.CDLL("libc.so.6",use_errno=True)
def rd(pid,a,n):
    with open(f"/proc/{pid}/mem","rb",0) as m: m.seek(a); return m.read(n)
def wr(pid,a,b):
    with open(f"/proc/{pid}/mem","r+b",0) as m: m.seek(a); m.write(b)
key="appname=DiskGenius&license=A&user=ZakaTest&email=zaka@example.com"
lines=["[license]",'appname = "DiskGenius"','user = "ZakaTest"','email = "zaka@example.com"',
       'regcode = "QK7X-M2PV-ZLHD-W8CT-RBNQ"','regver = "6.2.0.1829_x64_pro_eng"',f'key = "{key}"',""]
if os.path.exists(INI): os.chmod(INI,0o666)
open(INI,"wb").write(b"\xff\xfe"+("\r\n".join(lines)+"\r\n").encode("utf-16-le"))
env=dict(os.environ,WINEPREFIX=PREFIX,DISPLAY=":95")
xv=subprocess.Popen(["Xvfb",":95","-screen","0","1280x900x24"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(2)
proc=subprocess.Popen([LOADER,"DiskGenius.exe"],cwd=DGDIR,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(0.8)
pid=proc.pid
if libc.ptrace(16,pid,None,None)!=0: print("attach fail"); raise SystemExit
os.waitpid(pid,0)
target=0x14020b2d1
try:
    orig=rd(pid,target,6); print("原:",orig.hex())
    wr(pid,target,b"\x90"*6)
    back=rd(pid,target,6); print("改后:",back.hex(),"写入有效:",back==b"\x90"*6)
except Exception as e:
    print("patch err",e)
libc.ptrace(7,pid,None,None)
time.sleep(8)
print("INI 还在:",os.path.exists(INI))
proc.terminate(); time.sleep(1)
subprocess.run(["wineserver","-k"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
xv.terminate()
