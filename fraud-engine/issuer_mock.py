#!/usr/bin/env python3
# issuer_mock v2 — مُصدر وهمي لمعمل Flossx83 (stdlib فقط) — بورت 8092
# POST /switch/authorize {pan,cvv,expiry,amount(minor),mti,stan}
#   -> {approved,response_code,auth_code,reason,balance_minor}
# POST /reset | GET /health | GET /cards
import json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("ISSUER_PORT", "8092"))
API_KEY = os.environ.get("ISSUER_API_KEY", "")   # اتركه فارغًا إذا لم تضبط issuer.api-key في السويتش

# سجل البطاقات: PAN -> cvv / الرصيد (وحدات كبرى) / مفعلة / انتهاء MM/YY
CARDS = {
    "4000001234567899": {"cvv": "123", "balance": 4000.00, "enabled": True, "expiry": "12/29"},
    "4111111111111111": {"cvv": "123", "balance": 5000.00, "enabled": True, "expiry": "11/27"},
    # بطاقات سعودية (BIN بنوك حقيقية + Luhn مولّد — أرقام معملية)
    "4444947123456715": {"cvv": "123", "balance": 15000.00, "enabled": True, "expiry": "12/28"},  # الراجحي
    "4651542045869133": {"cvv": "456", "balance": 25000.00, "enabled": True, "expiry": "04/29"},  # الأهلي SNB
    "4659617319028467": {"cvv": "789", "balance": 9000.00,  "enabled": True, "expiry": "08/27"},  # الرياض
    "4638695174290386": {"cvv": "321", "balance": 7500.00,  "enabled": True, "expiry": "01/29"},  # الفرنسي BSF
}
INIT = {p: c["balance"] for p, c in CARDS.items()}
LOCK = threading.Lock()

def mask(pan): return pan[:4] + "***" + pan[-4:]

def expiry_ok(exp):
    if not exp: return True                      # الفحص اختياري (السويتش لا يرسل F14 عادة)
    digits = "".join(c for c in str(exp) if c.isdigit())
    if len(digits) < 4: return True
    mm, yy = int(digits[:2]), int(digits[2:4])
    now = time.localtime()
    return (yy, mm) >= (now.tm_year % 100, now.tm_mon)

def authorize(body):
    pan = str(body.get("pan", ""))
    cvv = str(body.get("cvv", ""))
    expiry = str(body.get("expiry", ""))
    stan = str(body.get("stan", "") or "000000")
    try: amount = int(float(body.get("amount", 0) or 0))
    except Exception: amount = 0
    with LOCK:
        card = CARDS.get(pan)
        if card is None:
            return {"approved": False, "response_code": "14", "auth_code": "000000", "reason": "unknown_card"}
        if not card.get("enabled", True):
            return {"approved": False, "response_code": "05", "auth_code": "000000", "reason": "card_disabled"}
        if not expiry_ok(expiry):
            return {"approved": False, "response_code": "54", "auth_code": "000000", "reason": "card_expired"}
        if cvv and card["cvv"] != cvv:
            return {"approved": False, "response_code": "05", "auth_code": "000000", "reason": "cvv_mismatch"}
        balance_minor = int(round(card["balance"] * 100))
        if amount > balance_minor:
            return {"approved": False, "response_code": "51", "auth_code": "000000",
                    "reason": "insufficient_funds", "balance_minor": balance_minor}
        card["balance"] = round((balance_minor - amount) / 100.0, 2)
        print(f"[AUTH] {mask(pan)} amount={amount} -> 00 auth=A{stan[-5:]} balance_minor={balance_minor - amount}", flush=True)
        return {"approved": True, "response_code": "00", "auth_code": "A" + stan[-5:],
                "reason": "ok", "balance_minor": balance_minor - amount}

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                n = int(self.rfile.readline().strip() or b"0", 16)
                if n == 0: self.rfile.readline(); break
                data += self.rfile.read(n); self.rfile.readline()
            return data
        return self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        if API_KEY and self.headers.get("X-API-Key", "") != API_KEY:
            return self._json({"error": "unauthorized"}, 401)
        raw = self._body()
        try: body = json.loads(raw or b"{}")
        except Exception: body = {}
        if self.path == "/switch/authorize":
            r = authorize(body)
            print(f"[REQ] {mask(str(body.get('pan','')))} mti={body.get('mti','')} -> {r['response_code']}", flush=True)
            return self._json(r)
        if self.path == "/reset":
            with LOCK:
                for p, b in INIT.items(): CARDS[p]["balance"] = b
            print("[RESET] balances restored", flush=True)
            return self._json({"status": "reset", "cards": len(CARDS)})
        self._json({"error": "not found"}, 404)
    def do_GET(self):
        if self.path == "/health":
            return self._json({"status": "ok", "port": PORT, "cards": len(CARDS), "engine": "issuer_mock v2"})
        if self.path == "/cards":
            with LOCK:
                return self._json({mask(p): {"balance": c["balance"], "enabled": c["enabled"], "expiry": c["expiry"]} for p, c in CARDS.items()})
        self._json({"error": "not found"}, 404)
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(f"issuer_mock v2 on :{PORT}  cards={len(CARDS)}  api_key={'set' if API_KEY else 'off'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
