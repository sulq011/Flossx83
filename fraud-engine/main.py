#!/usr/bin/env python3
"""
Flossx83 Fraud Engine — API Server (dual mode)
==============================================
Preferred : uvicorn main:app --reload           (FastAPI, see requirements.txt)
Fallback  : python3 main.py                     (stdlib http.server, zero deps)

Endpoints:
  POST /score   body {"mti":"0200","fields":{...}}  -> fraud decision JSON
  GET  /health                                          -> {"status":"ok"}
  GET  /rules                                           -> active rules config
  POST /reset                                           -> clear velocity/replay state (tests)

Port: env FRAUD_PORT (default 8091). Fraud engine NEVER receives raw PAN/CVV —
the switch tokenizes PAN (F2) before calling this service (PCI trust boundary).
The stdlib server accepts BOTH Content-Length and chunked (Transfer-Encoding)
request bodies — Java/Spring clients may stream chunked.
"""
import json
import os
import sys

from engine import FraudEngine

engine = FraudEngine()
try:
    from fastapi import FastAPI
    from pydantic import BaseModel

    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False

if HAVE_FASTAPI:
    app = FastAPI(title="Flossx83 Fraud Engine", version="1.1.0")

    class ScoreBody(BaseModel):
        mti: str | None = None
        fields: dict | None = None

    @app.post("/score")
    def score(body: ScoreBody):
        return engine.score({"mti": body.mti, "fields": body.fields or {}})

    @app.get("/health")
    def health():
        return {"status": "ok", "engine": "fastapi", "rules_loaded": engine.rules}

    @app.get("/rules")
    def rules():
        return engine.rules

    @app.post("/reset")
    def reset():
        engine.reset()
        return {"status": "reset"}

    if __name__ == "__main__":
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("FRAUD_PORT", "8091")))
else:
    # ---------- stdlib fallback server (identical API) ----------
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keep-alive with proper Content-Length

        def _json(self, code: int, payload: dict):
            body = json.dumps(payload, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            """Read the request body: Content-Length OR chunked transfer-encoding."""
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in te:
                chunks = []
                while True:
                    line = self.rfile.readline(65537).strip()
                    if b";" in line:  # ignore chunk extensions
                        line = line.split(b";")[0]
                    size = int(line or b"0", 16)
                    if size == 0:
                        while True:  # consume trailers until blank line
                            trailer = self.rfile.readline(65537)
                            if trailer in (b"\r\n", b"\n", b""):
                                break
                        return b"".join(chunks)
                    chunks.append(self.rfile.read(size))
                    self.rfile.readline(65537)  # trailing CRLF after each chunk
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"status": "ok", "engine": "stdlib"})
            elif self.path == "/rules":
                self._json(200, engine.rules)
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/reset":
                engine.reset()
                self._json(200, {"status": "reset"})
                return
            if self.path != "/score":
                self._json(404, {"error": "not found"})
                return
            try:
                raw = self._read_body()
                sys.stderr.write("[fraud] BODY: %r\n" % raw[:500])
                msg = json.loads(raw.decode() or "{}")
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "invalid JSON"})
                return
            self._json(200, engine.score(msg))

        def log_message(self, fmt, *args):
            sys.stderr.write("[fraud] " + fmt % args + "\n")

    if __name__ == "__main__":
        port = int(os.environ.get("FRAUD_PORT", "8091"))
        print(f"[fraud] stdlib mode on 0.0.0.0:{port} (install fastapi+uvicorn for the full stack)")
        ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
