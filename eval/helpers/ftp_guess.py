#!/usr/bin/env python3
"""Tiny FTP password guesser (stand-in for hydra): ftp_guess.py HOST PORT ATTEMPTS"""
import socket
import sys
import time

host, port, attempts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sock = None
for i in range(attempts):
    if sock is None or i % 3 == 0:                       # like hydra: a few tries per connection
        if sock:
            sock.close()
        sock = socket.create_connection((host, port), timeout=3)
        sock.recv(256)
    sock.sendall(b"USER admin\r\n")
    sock.recv(256)
    sock.sendall(b"PASS guess%d\r\n" % i)
    sock.recv(256)
    time.sleep(0.15)
sock.close()
