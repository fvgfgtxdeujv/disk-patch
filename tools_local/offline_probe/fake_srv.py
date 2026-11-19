"""本地假服务器：抓 OfflineReg 的 POST，并回一个可控响应。"""
import http.server, socketserver, sys, json, os

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured.txt")

class H(http.server.BaseHTTPRequestHandler):
    def _log(self, body=b""):
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("=== %s %s\n" % (self.command, self.path))
            for k, v in self.headers.items():
                f.write("  %s: %s\n" % (k, v))
            f.write("  BODY(%d): %r\n" % (len(body), body))
            try:
                f.write("  BODY-DECODED: %s\n" % body.decode("utf-8", "replace"))
            except Exception:
                pass
            f.write("\n")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self._log(body)
        resp = open(os.path.join(os.path.dirname(LOG), "response.txt"), "rb").read() if os.path.exists(os.path.join(os.path.dirname(LOG), "response.txt")) else b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    def do_GET(self):
        self._log()
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), H) as s:
        print("listening", port, flush=True)
        s.serve_forever()
