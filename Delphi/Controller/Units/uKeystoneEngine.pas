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

unit uKeystoneEngine;

interface

uses Winapi.Windows,
     System.Classes,
     System.SysUtils,
     uSharedTypes;

const KeystoneLibrary =
        {$IFDEF WIN32}
          '../../../../Libs/x32/keystone.dll'
        {$ELSE}
          '../../../../Libs/x64/keystone.dll'
        {$ENDIF};

      KS_ERR_ASM = 128;

type
  TKeystoneEngineArchitecture = (
    KS_ARCH_X86 = 4
  );

  TKeystoneEngineMode = (
    KS_MODE_32 = 4,
    KS_MODE_64 = 8
  );

  TKeystoneEngineError = (
    KS_ERR_OK = 0,       // No error: everything was fine
    KS_ERR_NOMEM,        // Out-Of-Memory error: ks_open(), ks_emulate()
    KS_ERR_ARCH,         // Unsupported architecture: ks_open()
    KS_ERR_HANDLE,       // Invalid handle
    KS_ERR_MODE,         // Invalid/unsupported mode: ks_open()
    KS_ERR_VERSION,      // Unsupported version (bindings)
    KS_ERR_OPT_INVALID   // Unsupported option
  );

  EKeystoneException = class(Exception)
  public
    {@C}
    constructor Create(const AError : TKeystoneEngineError); overload;
    constructor Create(const AError : Integer); overload;
  end;

  function ks_open(
    Architecture: Integer;
    AMode: Integer;
    var pEngine: Pointer
  ): TKeystoneEngineError; cdecl; external KeystoneLibrary;

  function ks_asm(
    pEngine: Pointer;
    pCode: PAnsiChar;
    pAddress: UInt64;
    var pShellcode: Pointer;
    var AShellcodeSize: SIZE_T;
    var ACount: SIZE_T
  ): Integer; cdecl; external KeystoneLibrary;

  function ks_close(pEngine: Pointer): TKeystoneEngineError; cdecl; external KeystoneLibrary;
  procedure ks_free(pEngine: Pointer); cdecl; external KeystoneLibrary;

  function ks_errno(pEngine: Pointer) : Cardinal; cdecl; external KeystoneLibrary;
  function ks_strerror(AError : TKeystoneEngineError) : PAnsiChar; cdecl; external KeystoneLibrary;

  procedure KeystoneAssemble(const ACode : AnsiString; var pShellcode : Pointer; var AShellcodeSize : SIZE_T; const AArchitecture : TArchitecture = x86_32); overload;
  function KeystoneAssemble(const ACode : AnsiString; var AStream : TMemoryStream; const AArchitecture : TArchitecture = x86_32) : Boolean; overload;
  function KeystoneAssemble(const ACode : AnsiString; const AArchitecture : TArchitecture = x86_32) : String; overload;

implementation

uses uFunctions;

(* Standalone Functions *)

{ _.KeystoneAssemble }
procedure KeystoneAssemble(const ACode : AnsiString; var pShellcode : Pointer; var AShellcodeSize : SIZE_T; const AArchitecture : TArchitecture = x86_32);
var pEngine   : Pointer;
    ARet      : TKeystoneEngineError;
    ACount    : SIZE_T;
    AError    : Integer;
    AKSArch   : TKeystoneEngineArchitecture;
    AKSMode   : TKeystoneEngineMode;
begin
  case AArchitecture of
    x86_32: begin
      AKSArch := TKeystoneEngineArchitecture.KS_ARCH_X86;
      AKSMode := TKeystoneEngineMode.KS_MODE_32;
    end;

    x86_64: begin
      AKSArch := TKeystoneEngineArchitecture.KS_ARCH_X86;
      AKSMode := TKeystoneEngineMode.KS_MODE_64;
    end;

    ///
    else
      raise Exception.Create('Unsuported Architecture');
  end;

  ARet := ks_open(Integer(AKSArch), Integer(AKSMode), pEngine);
  if ARet <> TKeystoneEngineError.KS_ERR_OK then
    raise EKeystoneException.Create(ARet);
  try
    if ks_asm(pEngine, PAnsiChar(ACode), 0, pShellCode, AShellcodeSize, ACount) <> 0 then
      raise EKeystoneException.Create(ks_errno(pEngine));
  finally
    if Assigned(pEngine) then
      ks_free(pEngine);
  end;
end;

{ _.KeystoneAssemble }
function KeystoneAssemble(const ACode : AnsiString; var AStream : TMemoryStream; const AArchitecture : TArchitecture = x86_32) : Boolean;
var pShellcode     : Pointer;
    AShellcodeSize : SIZE_T;
begin
  KeystoneAssemble(ACode, pShellcode, AShellcodeSize, AArchitecture);
  ///

  if not Assigned(AStream) then
    AStream := TMemoryStream.Create();
  ///

  AStream.Write(PByte(pShellcode)^, AShellcodeSize);
  AStream.Position := 0;
end;

{ _.KeystoneAssemble }
function KeystoneAssemble(const ACode : AnsiString; const AArchitecture : TArchitecture = x86_32) : String;
var AByte          : Byte;
    I              : Cardinal;
    pShellcode     : Pointer;
    AShellcodeSize : SIZE_T;
    AStringBuilder : TStringBuilder;
begin
  KeystoneAssemble(ACode, pShellcode, AShellcodeSize, AArchitecture);
  ///

  AStringBuilder := TStringBuilder.Create();
  try
    for I := 0 to AShellcodeSize -1 do
      AStringBuilder.Append(Format('\x%.2x', [
        PByte(NativeUInt(pShellcode) + (I * SizeOf(Byte)))^
      ]));
  finally
    result := AStringBuilder.ToString();

    ///
    if Assigned(AStringBuilder) then
      FreeAndNil(AStringBuilder);
  end;
end;

(* Classes *)

constructor EKeystoneException.Create(const AError : TKeystoneEngineError);
begin
  inherited Create(
    Format('Keystone Engine Error=[%d], Message=[%s]', [
      Cardinal(AError),
      ks_strerror(AError)
    ])
  );
end;

constructor EKeystoneException.Create(const AError : Integer);
begin
  if AError >= KS_ERR_ASM then
    inherited Create('Input Assembly Syntax Error.')
  else
    Create(TKeystoneEngineError(AError));
end;


end.
