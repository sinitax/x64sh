pxor xmm0, xmm0
pcmpeqd xmm1, xmm1
movmskps eax, xmm1
paddq xmm0, xmm1
