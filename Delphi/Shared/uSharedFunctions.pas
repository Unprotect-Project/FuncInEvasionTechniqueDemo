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

unit uSharedFunctions;

interface

uses Winapi.Windows,
     Winapi.Winsock2,
     System.Classes,
     System.Math,
     System.SysUtils;

  function SendInt64(const ASocket : TSocket; const AValue : Int64) : Integer;
  function RecvInt64(const ASocket : TSocket) : Int64;

  function BufferToHexView(const AStream : TMemoryStream) : String; overload;
  function BufferToHexView(const pBuffer : PVOID; const ABufferSize : UInt64) : String; overload;
  function BufferToHexView(const AFileName : TFileName) : String; overload;

implementation

{ _.SendInt64 }
function SendInt64(const ASocket : TSocket; const AValue : Int64) : Integer;
var ABuffer : array[0..SizeOf(Int64)-1] of byte;
begin
  Move(AValue, ABuffer, SizeOf(Int64));

  result := send(ASocket, ABuffer, SizeOf(Int64), 0);
end;

{ _.ReceiveInt64 }
function RecvInt64(const ASocket : TSocket) : Int64;
var ABuffer : array[0..SizeOf(Int64)-1] of byte;
begin
  if recv(ASocket, ABuffer, SizeOf(Int64), 0) <> SizeOf(Int64) then
    Exit(0);

  Move(ABuffer, result, SizeOf(Int64));
end;

{ _.BufferToHexView }
function BufferToHexView(const pBuffer : PVOID; const ABufferSize : UInt64) : String; overload;
var ARow           : array of byte;
    ABytesRead     : UInt64;
    x              : Byte;
    AStringBuilder : TStringBuilder;
    AHexBuilder    : TStringBuilder;
    AAsciiBuilder  : TStringBuilder;

    function PrintChar(const AChar : Byte) : Char;
    begin
      if AChar in [32..126] then
        result := Chr(AChar)
      else
        result := '.';
    end;

const SPACE = #32;

begin
  result := '';
  ///

  AStringBuilder := TStringBuilder.Create();
  AHexBuilder := TStringBuilder.Create(48);
  AAsciiBuilder := TStringBuilder.Create(16);
  try
    ABytesRead := 0;

    SetLength(ARow, 16);
    repeat
      if ABufferSize - ABytesRead < 16 then
        SetLength(ARow, ABufferSize - ABytesRead);
      ///

      CopyMemory(PByte(ARow), Pointer(NativeUInt(pBuffer) + ABytesRead), Length(ARow));

      AHexBuilder.Clear();
      AAsciiBuilder.Clear();

      for x := 0 to Length(ARow) -1 do begin
        AHexBuilder.Append(SPACE + IntToHex(ARow[x]));
        AAsciiBuilder.Append(PrintChar(ARow[x]));
      end;

      AStringBuilder.AppendLine(
        Format('%p:%p %-48s %s', [
          Pointer(NativeUInt(pBuffer) + ABytesRead),
          Pointer(ABytesRead),
          AHexBuilder.ToString(),
          AAsciiBuilder.ToString()
        ])
      );

      ///
      Inc(ABytesRead, Length(ARow));
    until ABytesRead = ABufferSize;

    ///
    result := AStringBuilder.ToString();
  finally
    if Assigned(AStringBuilder) then
      FreeAndNil(AStringBuilder);

    if Assigned(AHexBuilder) then
      FreeAndNil(AHexBuilder);

    if Assigned(AAsciiBuilder) then
      FreeAndNil(AAsciiBuilder);
  end;
end;

{ _.BufferToHexView }
function BufferToHexView(const AStream : TMemoryStream) : String; overload;
begin
  result := '';
  ///

  if not Assigned(AStream) or (AStream.Size = 0) then
    Exit();

  ///
  result := BufferToHexView(AStream.Memory, AStream.Size);
end;

{ _.BufferToHexView }
function BufferToHexView(const AFileName : TFileName) : String; overload;
var AFileStream : TFileStream;
    AStream     : TMemoryStream;
begin
  AFileStream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  AStream := TMemoryStream.Create();
  try
    AStream.CopyFrom(AFileStream, AFileStream.Size);

    ///
    result := BufferToHexView(AStream);
  finally
    if Assigned(AStream) then
      FreeAndNil(AStream);

    if Assigned(AFileStream) then
      FreeAndNil(AFileStream);
  end;
end;


end.
