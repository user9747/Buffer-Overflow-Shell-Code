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

