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
