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

unit uSharedTypes;

interface

uses Winapi.Winsock2;

type
  PSocket = ^TSocket;

  TArchitecture = (
    x86_32,
    x86_64,
    aUnsupported
  );

  TFuncIn_Header = record
    Architecture : TArchitecture;
  end;

  TFuncIn__RemoteShell__Information = record
    Header                : TFuncIn_Header;

    // we use UInt64 for interoperability between an x32 controller
    // and a x64 loader and vis-versa.
    SocketFd              : UInt64;
    __WaitForSingleObject : UInt64;
    __CreateProcessA      : UInt64;
    __ExitThread          : UInt64;
  end;

implementation

end.
