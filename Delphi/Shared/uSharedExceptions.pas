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

unit uSharedExceptions;

interface

uses Winapi.Windows,
     Winapi.Winsock2,
     System.Classes,
     System.SysUtils;

type
  EWindowsException = class(Exception)
  private
    FLastError : Integer;
  public
    {@C}
    constructor Create(const WinAPI : String); overload;

    {@G}
    property LastError : Integer read FLastError;
  end;

  ESocketException = class(Exception)
  private
    FWSALastError : Integer;
  public
    {@C}
    constructor Create(const AWinsockFunctionName : String); overload;

    {@G}
    property WSALastError : Integer read FWSALastError;
  end;


implementation

(* EWindowsException *)

{ EWindowsException.Create }
constructor EWindowsException.Create(const WinAPI : String);
var AFormatedMessage : String;
begin
  FLastError := GetLastError();

  AFormatedMessage := Format('%s: last_err=%d, last_err_msg="%s".', [
      WinAPI,
      FLastError,
      SysErrorMessage(FLastError)
  ]);

  ///
  inherited Create(AFormatedMessage);
end;

// ***

(* ESocketException *)

{ ESocketException.Create }
constructor ESocketException.Create(const AWinsockFunctionName : String);
var AFormatedMessage : String;
begin
  FWSALastError := WSAGetLastError();

  AFormatedMessage := Format('(%s) %s.', [
      AWinsockFunctionName,
      SysErrorMessage(FWSALastError)
  ]);

  ///
  inherited Create(AFormatedMessage);
end;


end.
