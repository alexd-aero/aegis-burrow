#!/usr/bin/env python3
# Aegis x Burrow machine agent. Keeps this machine reachable from the gate it
# is linked to, wherever it is: one WebSocket out to the gate's own address
# (the same HTTPS a browser uses). When the gate asks, it opens a stream and
# joins it to this machine's SSH server on 127.0.0.1 - and to nothing else.
# Every request it makes is signed with this machine's own key.
# Config: ~/.config/aegis-fleet/agent.json  Log: ~/.config/aegis-fleet/agent.log
import base64, hashlib, hmac, json, os, select, socket, ssl, struct, sys, threading, time
from urllib.parse import urlsplit, urlencode

VERSION = "1"
CFG = json.load(open(os.path.join(os.path.expanduser("~/.config/aegis-fleet"), "agent.json")))
BASE, MID, KEY, SSH_PORT = CFG["base"].rstrip("/"), CFG["id"], CFG["key"].encode(), int(CFG.get("ssh_port", 22))

def say(*a):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), *a, flush=True)

def signed(path, n=None):
    ts = str(int(time.time()))
    parts = [MID, ts] + ([n] if n is not None else [])
    sig = hmac.new(KEY, "|".join(parts).encode(), hashlib.sha256).hexdigest()
    q = {"id": MID, "ts": ts, "sig": sig}
    if n is not None: q["n"] = n
    return path + "?" + urlencode(q)

class Refused(Exception): pass
class Forgotten(Exception): pass

def remove_myself():
    # the gate forgot this machine: stop starting, and go
    d = os.path.expanduser("~/.config/aegis-fleet")
    os.system("systemctl --user disable aegis-fleet-agent.service >/dev/null 2>&1; rm -f ~/.config/systemd/user/aegis-fleet-agent.service")
    os.system("(crontab -l 2>/dev/null | grep -v aegis-fleet/agent.py | crontab -) 2>/dev/null")
    for f in ("agent.json", "agent.py", "agent.pid"):
        try: os.remove(os.path.join(d, f))
        except OSError: pass
    say("the gate forgot this machine: the agent removed itself")

class WS:
    def __init__(self, path):
        u = urlsplit(BASE)
        tls = u.scheme == "https"
        port = u.port or (443 if tls else 80)
        s = socket.create_connection((u.hostname, port), timeout=20)
        if tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        host = u.hostname + ("" if u.port is None else ":%d" % u.port)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: aegis-fleet-agent/%s\r\n\r\n"
                   % (path, host, key, VERSION)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d: raise OSError("closed during the handshake")
            buf += d
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n")[0]
        if b" 101 " not in status:
            if b" 410 " in status: raise Forgotten(status.decode(errors="replace"))
            if b" 403 " in status or b" 401 " in status: raise Refused(status.decode(errors="replace"))
            raise OSError(status.decode(errors="replace"))
        s.settimeout(None)
        self.s = s
    def send(self, data, op=None):
        if isinstance(data, str): data, op = data.encode(), op or 1
        op = op or 2
        n = len(data)
        head = bytes([0x80 | op])
        head += bytes([0x80 | n]) if n < 126 else (bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
        mask = os.urandom(4)
        body = _mask(data, mask)
        self.s.sendall(head + mask + body)
    def frames(self):
        out = []
        while True:
            b = self.buf
            if len(b) < 2: break
            op, n, off = b[0] & 15, b[1] & 127, 2
            if n == 126:
                if len(b) < 4: break
                n, off = struct.unpack(">H", b[2:4])[0], 4
            elif n == 127:
                if len(b) < 10: break
                n, off = struct.unpack(">Q", b[2:10])[0], 10
            if len(b) < off + n: break
            out.append((op, b[off:off + n]))
            self.buf = b[off + n:]
        return out
    def readable(self):
        return (hasattr(self.s, "pending") and self.s.pending() > 0) or len(self.buf) >= 2
    def pull(self):
        d = self.s.recv(65536)
        if not d: raise OSError("closed")
        self.buf += d
    def close(self):
        try: self.s.close()
        except Exception: pass

def _mask(data, mask):
    n = len(data)
    if not n: return b""
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")

def stream(n):
    ws = t = None
    try:
        ws = WS(signed("/__gate/fleet/agent/stream", n))
        t = socket.create_connection(("127.0.0.1", SSH_PORT), timeout=10)
        t.settimeout(None)
        while True:
            r = [ws.s] if ws.readable() else select.select([ws.s, t], [], [], 300)[0]
            if not r: continue
            if ws.s in r:
                ws.pull()
                for op, body in ws.frames():
                    if op == 8: return
                    if op == 9: ws.send(body, 10); continue
                    if op in (1, 2, 0): t.sendall(body)
            if t in r:
                d = t.recv(65536)
                if not d: return
                ws.send(d, 2)
    except Exception as e:
        say("stream", n, "ended:", e)
    finally:
        for x in (ws, t):
            try: x and x.close()
            except Exception: pass

def control():
    ws = WS(signed("/__gate/fleet/agent"))
    ws.send("hello " + json.dumps({"v": VERSION, "host": socket.gethostname(), "ssh": SSH_PORT}))
    say("connected to", BASE)
    last = time.time()
    while True:
        if not ws.readable():
            r = select.select([ws.s], [], [], 25)[0]
            if not r:
                ws.send("ping")
                if time.time() - last > 90: raise OSError("the gate stopped answering")
                continue
        ws.pull()
        last = time.time()
        for op, body in ws.frames():
            if op == 8: raise OSError("the gate closed the link")
            if op == 9: ws.send(body, 10); continue
            msg = body.decode(errors="replace") if op == 1 else ""
            if msg.startswith("open "):
                threading.Thread(target=stream, args=(msg[5:].strip(),), daemon=True).start()

def main():
    wait, refused = 2, 0
    while True:
        try:
            control()
            wait, refused = 2, 0
        except Forgotten:
            remove_myself()
            return
        except Refused as e:
            refused += 1
            say("the gate refused this machine (%s): was it forgotten there? trying again later" % e)
            time.sleep(3600 if refused > 3 else 300)
            continue
        except Exception as e:
            say("link down:", e)
        time.sleep(wait)
        wait = min(60, wait * 2)

if __name__ == "__main__":
    main()
