---
title: "Hack The Box – ReRop"
description: "Static 64-bit binary abusing a hidden ROP chain in the .data section, stack pivot via lea rsp, chained gadgets for flag validation, and full reverse engineering of a static ELF."
publishDate: 2026-01-20
tags: ["Reverse Engineering", "rop", "static-binary", "x86-64", "hackthebox"]
featured: false
img: "/assets/blog/htb.png"
img_alt: "HTB ReRop return-oriented programming reverse engineering write-up"
---

# ReRop

We are given a 64-bit binary called rerop:

```sh
$ file rerop
rerop: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=0f6c70533a1090f9215451cd4d03a4bd6f387264, for GNU/Linux 3.2.0, not stripped
```

```sh
$ ./rerop
Enter the flag: HTB{asdf}
Nope
```

## Reverse engineering

If we open the binary in IDA, we will see the following main function:

```c
int __fastcall main(int argc, const char** argv, const char** envp) {
  printf("Enter the flag: ");
  fgets(buf, 64, stdin);
  buf[j_strcspn_ifunc(buf, "\n")] = 0;
  check(&data_0);
  puts(buf);
  return 0;
}
```

It looks pretty simple, right? It only takes use input to buf (a global variable at 0x4c7820), and then calls check with data (another global variable at 0x4c5100) as an argument; notice that the binary is not PIE, so all addresses are static regardless of ASLR. This is check:

```c
void check() {
  ;
}
```

Even simpler! No way this is the function… Let’s analyze the assembly code:

```sh
$ objdump -M intel --disassemble-symbols=check rerop
```

```text
rerop:	file format elf64-x86-64

Disassembly of section .text:

00000000004017b5 <check>:
  4017b5: f3 0f 1e fa                  	endbr64
  4017b9: 48 8d 27                     	lea	rsp, [rdi]
  4017bc: c3                           	ret
  4017bd: 90                           	nop
  4017be: 0f 0b                        	ud2
```

Alright, so this function simply takes the first argument ($rdi) and copies that to $rsp. And here comes the magic: the ret instruction, which

> Transfers program control to a return address located on the top of the stack

However, the top of the stack ($rsp) has been replaced by $rdi, so the program is actually returning to an address inside of the data buffer.

Let’s take a look at this buffer with xxd:

```sh
$ xxd -e -g 8 -s 0xc4100 -c 8 rerop | head -20
```

```text
000c4100: 0000000000450ec7  ..E.....
000c4108: 0000000000000065  e.......
000c4110: 0000000000401eef  ..@.....
000c4118: 0000000000000000  ........
000c4120: 0000000000409f1e  ..@.....
000c4128: 0000000000000001  ........
000c4130: 0000000000458142  B.E.....
000c4138: 0000000000000000  ........
000c4140: 000000000041aab6  ..A.....
000c4148: 0000000000451fe0  ..E.....
000c4150: 0000000000450ec7  ..E.....
000c4158: 0000000000001198  ........
000c4160: 0000000000452000  . E.....
000c4168: 0000000000458142  B.E.....
000c4170: 0000000000000000  ........
000c4178: 0000000000401eef  ..@.....
000c4180: 00000000004c7820   xL.....
000c4188: 0000000000450ec7  ..E.....
000c4190: 0000000000000019  ........
000c4198: 0000000000451ff0  ..E.....
```

We need to subtract 0x4c5100 - 0x401000 to get the actual offset within the ELF file. As can be seen, we only have addresses within the binary (0x4.....) and other numbers.

## Return-Oriented Programming

If you are not familiar with Return-Oriented Programming (ROP), this might be a little weird. This technique is mainly used in binary exploitation (pwn) in order to achieve arbitrary code execution when there are no executable memory addresses to place custom shellcode. The idea of this technique is to reuse instructions from the binary or shared libraries to execute the parts needed to get the desired result. For this, the control flow of the program must be controlled, so that the program can be redirected to anywhere.

The use ROP depends on gadgets. These are sequences of instructions that end typically in ret (others can end in jmp or call). For example, pop rdi; ret is a very useful gadget, because it takes the next value from the stack and puts it in $rdi (the first argument of a function); and then returns to the next address within the stack. By chaining several gadget address on the stack (known as ROP chain), one can achieve almost arbitrary code execution (depending on the gadgets available).

## ROP chain

Going back to the ROP chain we have in data, we need to find what gadgets are being used. For this, we can use the following Python code using pwntools:

```python
from pwn import asm, context, disasm, ELF

context.binary = ELF('rerop', checksec=False)
elf = context.binary.data

rop_chain = [
    int.from_bytes(elf[i : i + 8], 'little')
    for i in range(0x4c5100 - 0x401000, 0x4c6400 - 0x401000 + 8, 8)
]

ret = asm('ret')

for i, addr in enumerate(rop_chain):
    print()
    print(hex(8 * i), '->', hex(addr))

    if 0x401000 <= addr < 0x498000:
        ret_index = elf[addr - 0x400000:].index(ret)
        print(disasm(elf[addr - 0x400000 : addr - 0x400000 + ret_index + 1]))
```

With this, we take the contents of data (from 0x4c5100 to 0x4c6400), parse it as 8-byte elements and try to disassemble the addresses as long as they belong to an executable area of memory (from 0x401000 to 0x49793d).

This is how the ROP chain starts:

```text
$ python3 solve.py

0x0 -> 0x450ec7
   0:   58                      pop    rax
   1:   c3                      ret

0x8 -> 0x65

0x10 -> 0x401eef
   0:   5f                      pop    rdi
   1:   c3                      ret

0x18 -> 0x0

0x20 -> 0x409f1e
   0:   5e                      pop    rsi
   1:   c3                      ret

0x28 -> 0x1

0x30 -> 0x458142
   0:   5a                      pop    rdx
   1:   c3                      ret

0x38 -> 0x0

0x40 -> 0x41aab6
   0:   0f 05                   syscall
   2:   c3                      ret
```

## Solution

Taking into account that there are several checks of the form

```text
((buf[k] + a) ^ b) - c == 0
```

We can parse the ROP chain to take the k, a, b and c values and find the expected value of buf[k]:

```text
buf[k] = (b ^ c) - a
```

We can use the address of movzx rax, BYTE PTR [rax]; ret (0x45202f) as a reference to all checks and parse from there. Next, we simply find the values of the flag:

```python
flag = bytearray(rop_chain.count(0x45202f))

for i, addr in enumerate(rop_chain):
    if addr == 0x45202f:
        k, a, b, c = rop_chain[i - 3], rop_chain[i + 3], rop_chain[i + 6], rop_chain[i + 9]
        # ((flag[k] + a) ^ b) - c == 0
        flag[k] = (b ^ c) - a

print()
print(flag.decode())
```

## Flag

```text
HTB{W4iT_W4S_Th@t_PWN_0R_R3V}
```

```sh
$ ./rerop
Enter the flag: HTB{W4iT_W4S_Th@t_PWN_0R_R3V}
Correct Flag!
```
