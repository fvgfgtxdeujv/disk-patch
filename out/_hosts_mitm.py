# -*- coding: utf-8 -*-
"""Hosts 劫持 + 本地 TLS 伪装服务器，抓 DiskGenius 的 HTTPS 请求/响应。
需管理员：改 hosts、装临时根证书（结束后删除）、监听 443、写 HKLM。
"""
import argparse, json, os, socket, ssl, subprocess, sys, threading, time, winreg
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOSTS = r'C:\Windows\System32\drivers\etc\hosts'
DOMAINS = ['internal.eassos.com', 'www.eassos.com', 'eassos.com', 'activate.eassos.com']
MARK_A, MARK_B = '# >>> DGPROBE', '# <<< DGPROBE'

def ensure_certs(root):
    ca_p = os.path.join(root, 'out', '_mitm_ca.pem')
    key_p = os.path.join(root, 'out', '_mitm_ca.key')
    ch_p = os.path.join(root, 'out', '_mitm_chain.pem')
    if os.path.exists(ca_p) and os.path.exists(key_p) and os.path.exists(ch_p):
        return ca_p, ch_p
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DGProbe Local CA')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAINS[0])]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in DOMAINS]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    open(ca_p, 'wb').write(ca.public_bytes(serialization.Encoding.PEM))
    open(key_p, 'wb').write(ca_key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    blob = (leaf.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            + ca.public_bytes(serialization.Encoding.PEM))
    open(ch_p, 'wb').write(blob)
    return ca_p, ch_p

def setlic(v):
    for sub in ('Reg', 'CReg'):
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0,
                           winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, 'license', 0, winreg.REG_BINARY, v); k.Close()

def baklic():
    d = {}
    for sub in ('Reg', 'CReg'):
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0,
                           winreg.KEY_READ)
        try: d[sub] = winreg.QueryValueEx(k, 'license')
        except OSError: d[sub] = (None, None)
        k.Close()
    return d

def restorelic(d):
    for sub, (v, t) in d.items():
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Eassos\DiskGenius\%s' % sub, 0,
                           winreg.KEY_SET_VALUE)
        if v is None:
            try: winreg.DeleteValue(k, 'license')
            except OSError: pass
        else: winreg.SetValueEx(k, 'license', 0, t, v)
        k.Close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', default=None)
    ap.add_argument('--seconds', type=int, default=16)
    ap.add_argument('--body', default='appname=DiskGenius&license=SIG&user=Boss&email=boss@example.com')
    a = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe = os.path.join(root, 'out', 'runtime', 'DiskGenius', 'DiskGenius.exe')
    logp = os.path.join(root, 'out', '_mitm_%s.jsonl' % (a.key or 'empty'))
    f = open(logp, 'w', encoding='utf-8')
    def log(o):
        o['t'] = round(time.time() - T0, 3)
        f.write(json.dumps(o, ensure_ascii=False) + '\n'); f.flush()

    ca_p, ch_p = ensure_certs(root)
    hosts0 = open(HOSTS, 'rb').read()
    lic0 = baklic()
    T0 = time.time()
    srv = None
    try:
        # hosts
        block = ('\r\n' + MARK_A + '\r\n' + '\r\n'.join('127.0.0.1 ' + d for d in DOMAINS)
                 + '\r\n' + MARK_B + '\r\n').encode()
        open(HOSTS, 'wb').write(hosts0 + block)
        subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
        # CA
        r = subprocess.run(['certutil', '-addstore', '-f', 'Root', ca_p], capture_output=True, text=True)
        log({'ev': 'ca_add', 'rc': r.returncode})
        # server
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ch_p)
        ctx.set_alpn_protocols(['http/1.1'])
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', 443)); srv.listen(16); srv.settimeout(0.5)
        log({'ev': 'listen', 'port': 443})

        def handle(c):
            try:
                c.settimeout(6)
                s = ctx.wrap_socket(c, server_side=True)
                data = b''
                while b'\r\n\r\n' not in data and len(data) < 65536:
                    chunk = s.recv(4096)
                    if not chunk: break
                    data += chunk
                head, _, rest = data.partition(b'\r\n\r\n')
                lines = head.decode('latin1').split('\r\n')
                clen = 0
                for ln in lines[1:]:
                    if ln.lower().startswith('content-length:'):
                        clen = int(ln.split(':', 1)[1].strip())
                body = rest
                while len(body) < clen:
                    chunk = s.recv(4096)
                    if not chunk: break
                    body += chunk
                log({'ev': 'req', 'sni': c.server_hostname if False else getattr(s, 'server_hostname', None),
                     'line': lines[0], 'headers': lines[1:], 'body': body[:4000].decode('latin1', 'replace')})
                resp = ('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n'
                        'Connection: close\r\n\r\n%s' % (len(a.body.encode()), a.body)).encode()
                s.sendall(resp)
                s.close()
            except Exception as e:
                log({'ev': 'tls_err', 'err': repr(e)})

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=handle, args=(c,), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()

        setlic(b'' if a.key is None else a.key.encode('utf-16-le'))
        p = subprocess.Popen([exe], cwd=os.path.dirname(exe))
        log({'ev': 'launch', 'pid': p.pid, 'key': a.key})
        time.sleep(a.seconds)
        p.terminate()
        time.sleep(0.5)
    finally:
        try:
            if srv: srv.close()
        except Exception:
            pass
        open(HOSTS, 'wb').write(hosts0)
        subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
        try:
            restorelic(lic0)
        except Exception as e:
            log({'ev': 'lic_restore_err', 'err': repr(e)})
        try:
            der = ssl.PEM_cert_to_DER_cert(open(ca_p).read())
            import hashlib
            th = hashlib.sha1(der).hexdigest()
            r = subprocess.run(['certutil', '-delstore', 'Root', th], capture_output=True, text=True)
            log({'ev': 'ca_del', 'rc': r.returncode, 'sha1': th})
        except Exception as e:
            log({'ev': 'ca_del_err', 'err': repr(e)})
        log({'ev': 'restored'})
    print('done', logp)
    return 0

if __name__ == '__main__':
    sys.exit(main())
