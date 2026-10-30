#!/usr/bin/env python3
"""Benign: an admin touring a server's services, several ports, all successful.
service_tour.py HOST ROUNDS"""
import socket
import sys
import time

host, rounds = sys.argv[1], int(sys.argv[2])
for _ in range(rounds):
    for port in (21, 22, 23, 25, 80, 3306, 8080):
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.settimeout(1)
                if port in (80, 8080):
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                try:
                    s.recv(256)
                except OSError:
                    pass
        except OSError:
            pass
        time.sleep(0.1)
