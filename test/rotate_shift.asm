mov eax, 0xdeadbeef
mov cl, 0x8
ror eax, cl
rol eax, cl
shrd eax, ecx, cl
