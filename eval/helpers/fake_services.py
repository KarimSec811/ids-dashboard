#!/usr/bin/env python3
"""Stand-in for a Metasploitable-style victim: listens on a set of classic ports with
realistic banners. Used by eval/netns_lab.sh so the evaluation can run without VMs.
(With the real VM lab you do not need this file.)"""
import socketserver
import threading
import time

BANNERS = {
    22: b"SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\r\n",
    23: b"\xff\xfd\x18\xff\xfd\x20Ubuntu 8.04\r\nmetasploitable login: ",
    25: b"220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n",
    110: b"+OK Dovecot ready.\r\n",
    139: b"", 445: b"", 512: b"", 513: b"", 514: b"",
    3306: b"J\x00\x00\x00\x0a5.0.51a-3ubuntu5\x00",
    5432: b"", 5900: b"RFB 003.003\n", 6667: b":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname\r\n",
}
PAGE = b"<html><body><h1>Metasploitable2</h1></body></html>"


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            banner = BANNERS.get(self.server.server_address[1], b"")
            if banner:
                self.request.sendall(banner)
            while self.request.recv(1024):
                pass
        except OSError:
            pass


class Http(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            self.request.recv(2048)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
                                 b"Connection: close\r\n\r\n%s" % (len(PAGE), PAGE))
        except OSError:
            pass


class Ftp(socketserver.BaseRequestHandler):
    """vsftpd-like: every password is wrong (530), which is what a brute force sees."""
    def handle(self):
        self.request.settimeout(10)
        f = self.request.makefile("rwb", buffering=0)
        try:
            f.write(b"220 (vsFTPd 2.3.4)\r\n")
            for line in iter(f.readline, b""):
                cmd = line[:4].upper()
                if cmd == b"USER":
                    f.write(b"331 Please specify the password.\r\n")
                elif cmd == b"PASS":
                    f.write(b"530 Login incorrect.\r\n")
                elif cmd == b"QUIT":
                    f.write(b"221 Goodbye.\r\n")
                    break
                else:
                    f.write(b"530 Please login with USER and PASS.\r\n")
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def main():
    plan = {21: Ftp, 80: Http, 8080: Http, 8180: Http}
    plan.update({p: Banner for p in BANNERS})
    for port, handler in plan.items():
        threading.Thread(target=Server(("0.0.0.0", port), handler).serve_forever, daemon=True).start()
    print(f"fake services listening on {len(plan)} ports", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
