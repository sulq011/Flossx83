#!/usr/bin/env python3
"""
pos-cli v1.2 - POS terminal simulator (Python stdlib only).
NEW in v1.2: TCP framing with a 2-byte BIG-ENDIAN binary length header,
matching TcpServer v1.5 and iso8583sim (--header 2b --format ascii-hex).
Flags: --tcp host:port | --http url, --pan, --amount, --cvv, --stan, --mti
"""
import argparse
import socket
import sys
import time
import urllib.request

DEFAULT_PAN = "4000001234567899"

# Fixed field lengths for decoding replies (ascii-hex bitmap)
FIXED_LEN = {3: 6, 4: 12, 7: 10, 11: 6, 12: 6, 13: 4, 14: 4, 38: 6, 39: 2,
             41: 8, 42: 15, 49: 3}


def bitmap_hex(bits):
    v = 0
    for b in bits:
        v |= 1 << (64 - b)
    return format(v, "016X")


def build_message(args):
    mti = args.mti if args.mti else "0200"
    pan = args.pan if args.pan else DEFAULT_PAN
    amount_minor = int(round((args.amount if args.amount is not None else 0.0) * 100))
    stan = args.stan if args.stan else time.strftime("%H%M%S")
    stan = format(int(stan), "06d")[-6:] if stan.isdigit() else stan

    f7 = time.strftime("%m%d%H%M%S")
    f12 = time.strftime("%H%M%S")
    f13 = time.strftime("%m%d")
    f52 = None
    if args.cvv:
        f52 = args.cvv.ljust(16, "0")[:16]

    bits = [2, 3, 4, 7, 11, 12, 13] + ([52] if f52 else [])
    msg = mti + bitmap_hex(bits)
    msg += format(len(pan), "02d") + pan          # F2 LLVAR
    msg += "000000"                                # F3 processing code
    msg += format(amount_minor, "012d")            # F4 amount (minor units)
    msg += f7 + stan + f12 + f13                   # F7, F11, F12, F13
    if f52:
        msg += f52                                  # F52 (padded CVV)
    return msg


def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_tcp(host, port, message, timeout=15):
    payload = message.encode("ascii")
    frame = len(payload).to_bytes(2, "big") + payload
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(frame)
        header = recvall(s, 2)
        if header is None:
            return None
        length = int.from_bytes(header, "big")
        data = recvall(s, length)
    return None if data is None else data.decode("ascii", "replace")


def send_http(url, message, timeout=15):
    req = urllib.request.Request(url, data=message.encode("ascii"),
                                 headers={"Content-Type": "text/plain"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def decode_reply(reply):
    if not reply or len(reply) < 20:
        print("[POS] reply too short to decode:", reply)
        return
    mti = reply[:4]
    bm = int(reply[4:20], 16)
    pos = 20
    fields = {}
    for bit in range(1, 65):
        if (bm >> (64 - bit)) & 1:
            if bit == 2:
                ln = int(reply[pos:pos + 2])
                pos += 2
                fields[2] = reply[pos:pos + ln]
                pos += ln
            else:
                ln = FIXED_LEN.get(bit)
                if ln is None:
                    break
                fields[bit] = reply[pos:pos + ln]
                pos += ln
    f39 = fields.get(39, "?")
    f38 = fields.get(38, "-")
    amt = f"{int(fields[4]) / 100:.2f}" if fields.get(4, "").isdigit() else "?"
    pan = fields.get(2, "-")
    pan_short = pan[:6] + "..." + pan[-3:] if len(pan) > 12 else pan
    print(f"[POS] DECODED: MTI={mti} F39={f39} F38={f38} amount={amt} "
          f"stan={fields.get(11, '?')} pan={pan_short}")


def main():
    p = argparse.ArgumentParser(description="POS terminal simulator v1.2 (2-byte framed TCP)")
    p.add_argument("--tcp", help="host:port of the switch")
    p.add_argument("--http", help="switch HTTP endpoint URL")
    p.add_argument("--pan", default=DEFAULT_PAN)
    p.add_argument("--amount", type=float, default=25.0)
    p.add_argument("--cvv", help="3-4 digit CVV (adds F52)")
    p.add_argument("--stan", help="6-digit STAN (F11)")
    p.add_argument("--mti", help="message MTI (default 0200)")
    args = p.parse_args()

    if not args.tcp and not args.http:
        p.error("choose --tcp host:port or --http url")

    message = build_message(args)
    print(f"[POS] Message ({len(message)} chars): {message}")

    if args.tcp:
        host, port = args.tcp.split(":")
        port = int(port)
        print(f"[POS] TCP -> {host}:{port} (2-byte framed, {len(message)} chars)")
        reply = send_tcp(host, port, message)
        if reply is None:
            print("[POS] no reply (connection closed / timeout)")
            sys.exit(1)
        print(f"[POS] switch replied: {reply}")
        decode_reply(reply)
    else:
        print(f"[POS] HTTP -> {args.http} ({len(message)} chars)")
        reply = send_http(args.http, message)
        print(f"[POS] switch replied: {reply}")


if __name__ == "__main__":
    main()
