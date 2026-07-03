#!/usr/bin/env python3
"""极简静态服务器，为「机器资源池」新版前端提供页面。

前端是纯静态单文件 (index.html)，通过浏览器直接调用 TensorHive API (:1111)。
用法:  python serve.py [port]   (默认 8090)
"""
import sys
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
WEBROOT = os.path.dirname(os.path.abspath(__file__))


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # 开发期禁用缓存，改动即时生效
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *args):
        pass  # 静默访问日志


if __name__ == "__main__":
    handler = partial(Handler, directory=WEBROOT)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    print(f"[机器资源池] 新版前端: http://0.0.0.0:{PORT}  (serving {WEBROOT})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
