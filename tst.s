data: 
str: .asciz "Hello"
arr: .skip 12
num: .word 19

_start: 
@ data processing
mov r0, #1
cmp r1, r0
movlt r1, r0
movs r2, r0, lsl #2 
and r1, r1, r2
eorsgt r0, r1, sp
sub r2, r3, r4
rsb r5, r2, r0, asr #3
add r4, r0, #300
adc r7, r1, r4
sbc r1, r2, r9
rsc r0, r2, fp
tst r0, lr
teq r2, sp
cmn r9, #1
orr r0, r4, r8
bic r0, r1, r3
mvn r1, r1

@ mul
mul r1, r2, r3
umull r1, r2, r3, r4
smullgt r2, r3, r4, r5

@ load/store
ldrlt r0, [r1]
ldrb r1, [r2, #3]
ldr r3, [r4, -r5, lsl #3]!
streq r0, [r2], #4
strb r2, [r3], -r4, asr #5

@ branch
b 0x1111
bx r3
bl 0x3434

@ swi
swi 0