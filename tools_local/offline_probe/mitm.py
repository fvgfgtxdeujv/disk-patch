"""极简 MITM 代理：接管 Wine winhttp 的 CONNECT，用自签证书解密，记录请求并回可控响应。"""
import socket, ssl, threading, os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, "mitm.txt")
CERT = os.path.join(BASE, "cert.pem")
KEY = os.path.join(BASE, "key.pem")


def log(s):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(s + "\n")


def handle(conn, addr):
    try:
        conn.settimeout(20)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode("latin1")
        log("=== CLIENT HELLO-HEAD ===")
        log(head)
        if head.upper().startswith("CONNECT"):
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(CERT, KEY)
            ctx.check_hostname = False
            tls = ctx.wrap_socket(conn, server_side=True)
            log("--- TLS established ---")
            req = b""
            tls.settimeout(15)
            while b"\r\n\r\n" not in req:
                c = tls.recv(65536)
                if not c:
                    break
                req += c
            hdr, _, rest = req.partition(b"\r\n\r\n")
            log("=== REQUEST ===")
            log(hdr.decode("latin1"))
            clen = 0
            for line in hdr.decode("latin1").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    clen = int(line.split(":")[1].strip())
            body = rest
            while len(body) < clen:
                c = tls.recv(65536)
                if not c:
                    break
                body += c
            log("BODY(%d): %r" % (len(body), body))
            try:
                log("BODY-TEXT: " + body.decode("utf-8", "replace"))
            except Exception:
                pass
            resp = b"OK"
            rp = os.path.join(BASE, "response.txt")
            if os.path.exists(rp):
                resp = open(rp, "rb").read()
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(resp) + resp)
            try:
                tls.close()
            except Exception:
                pass
        else:
            log("=== PLAIN REQUEST ===")
            log(head)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    except Exception as e:
        log("ERR: %r" % (e,))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(20)
    print("mitm listening", port, flush=True)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
