unit mdns;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, IdGlobal, IdIPMCastServer;

type
  { Store your identity (user, host, port) so the mDNS code can build presence packets. }
  TMDNSConfig = record
    UserName: string;   // e.g. "inky"
    HostName: string;   // e.g. "lovelace.local"
    Port: Word;         // e.g. 5298
    IPAddress: string;
  end;

  { Event signature for receiving any inbound DNS packets (after we parse them) }
  TMDNSPacketEvent = procedure(const AData: TIdBytes; const ASourceIP: string; ASourcePort: Word) of object;

  { The main thread that listens on the TIdIPMCastServer Binding in a loop }
  TMDNSResponderThread = class(TThread)
  private
    FServer: TIdIPMCastServer;
    FOnPacket: TMDNSPacketEvent;
    FConfig: TMDNSConfig;

    // Store the pending data for the main thread callback:
    FPacketData: TIdBytes;
    FPacketIP: string;
    FPacketPort: Word;

    procedure HandleMDNSQuery(const AData: TIdBytes);
    procedure CallOnPacket;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TIdIPMCastServer; const AConfig: TMDNSConfig);

    property OnPacket: TMDNSPacketEvent read FOnPacket write FOnPacket;
    property Config: TMDNSConfig read FConfig write FConfig;
  end;

{ Builds a minimal DNS response (PTR+SRV+TXT) for "_presence._tcp.local" }
function BuildMDNSResponse(const AConfig: TMDNSConfig): TIdBytes;

{ Utility for reading a domain name from raw DNS data }
function DecodeDomainName(const AData: TIdBytes; var StartPos: Integer): string;

{ Utility for writing a domain name into a TMemoryStream in DNS label form }
procedure EncodeDomainName(Stream: TMemoryStream; const DomainName: string);


implementation

uses
  IdSocketHandle;
procedure LogLine(const s: string);
begin
  writeln(s);

end;

{------------------------------------------------------------------------------}
function CopyStr(const AData: TIdBytes; StartPos, Len: Integer): string;
begin
  SetString(Result, PChar(@AData[StartPos]), Len);
end;

{------------------------------------------------------------------------------}
function DecodeDomainName(const AData: TIdBytes; var StartPos: Integer): string;
var
  Len: Byte;
  part: string;
begin
  Result := '';
  while (StartPos < Length(AData)) and (AData[StartPos] <> 0) do
  begin
    // check if top 2 bits are '11' => pointer compression
    if (AData[StartPos] and $C0) = $C0 then
    begin
      // In minimal code, we skip full pointer logic for brevity
      // Normally you'd jump to pointer offset. For now just break or skip:
      Inc(StartPos);
      Break;
    end
    else
    begin
      Len := AData[StartPos];
      Inc(StartPos);
      part := CopyStr(AData, StartPos, Len);
      Inc(StartPos, Len);
      if Result = '' then
        Result := part
      else
        Result := Result + '.' + part;
    end;
  end;
  // skip the trailing 0 byte if present
  if (StartPos < Length(AData)) and (AData[StartPos] = 0) then
    Inc(StartPos);
end;

{------------------------------------------------------------------------------}
procedure EncodeDomainName(Stream: TMemoryStream; const DomainName: string);
{ Convert "inky.lovelace.local" into DNS labels: [length][label]...[0] }
var
  Labels: TStringList;
  i, L: Integer;
  tempByte: Byte;
begin
  Labels := TStringList.Create;
  try
    Labels.StrictDelimiter := True;
    Labels.Delimiter := '.';
    Labels.DelimitedText := DomainName;

    for i := 0 to Labels.Count - 1 do
    begin
      L := Length(Labels[i]);
      tempByte := L;
      Stream.Write(tempByte, 1); // label length
      if L > 0 then
        Stream.Write(PChar(Labels[i])^, L); // label chars
    end;
    // terminating zero
    tempByte := 0;
    Stream.Write(tempByte, 1);
  finally
    Labels.Free;
  end;
end;

procedure WriteWordBE(Stream: TMemoryStream; Value: Word);
var
  b: Byte;
begin
  b := (Value shr 8) and $FF;
  Stream.Write(b, 1);
  b := Value and $FF;
  Stream.Write(b, 1);
end;

procedure WriteLongWordBE(Stream: TMemoryStream; Value: Cardinal);
var
  b: Byte;
begin
  b := (Value shr 24) and $FF;
  Stream.Write(b, 1);
  b := (Value shr 16) and $FF;
  Stream.Write(b, 1);
  b := (Value shr 8) and $FF;
  Stream.Write(b, 1);
  b := Value and $FF;
  Stream.Write(b, 1);
end;

{------------------------------------------------------------------------------}
function BuildMDNSResponse(const AConfig: TMDNSConfig): TIdBytes;
var
  ms: TMemoryStream;
  dataLenPos: Int64;
  startPos: Int64;
  dataLen: Integer;
  userService: string;
  txtLine: string;
  txtLenByte: Byte;
  ipParts: TStringList;
  i: Integer;
  b: Byte;
begin
  userService := AConfig.UserName + '@' + AConfig.HostName + '._presence._tcp.local';

  ms := TMemoryStream.Create;
  try
    // DNS Header
    WriteWordBE(ms, 0);       // Transaction ID
    WriteWordBE(ms, $8400);   // Flags: QR=1, AA=1
    WriteWordBE(ms, 0);       // QDCount=0
    WriteWordBE(ms, 3);       // ANCount=3 (PTR, SRV, TXT)
    WriteWordBE(ms, 0);       // NSCount=0
    WriteWordBE(ms, 1);       // ARCount=1 (A record)

    // 1) PTR Record
    EncodeDomainName(ms, '_presence._tcp.local');
    WriteWordBE(ms, $000C);   // TYPE=PTR (0x000C)
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 120); // TTL=120
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    EncodeDomainName(ms, userService); // e.g., "inky@lovelace._presence..."
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // 2) SRV Record
    EncodeDomainName(ms, userService);
    WriteWordBE(ms, $0021);   // TYPE=SRV
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 120); // TTL=120
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    WriteWordBE(ms, 0);       // Priority=0
    WriteWordBE(ms, 0);       // Weight=0
    WriteWordBE(ms, AConfig.Port); // Port
    EncodeDomainName(ms, AConfig.HostName); // Target host (e.g., "lovelace.local")
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // 3) TXT Record
    EncodeDomainName(ms, userService);
    WriteWordBE(ms, $0010);   // TYPE=TXT
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 120);
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    txtLine := 'txtvers=1';
    txtLenByte := Length(txtLine);
    ms.Write(txtLenByte, 1);
    ms.Write(PChar(txtLine)^, txtLenByte);
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // 4) A Record (Additional)
    EncodeDomainName(ms, AConfig.HostName);
    WriteWordBE(ms, $0001);   // TYPE=A
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 120); // TTL=120
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    // Write IP bytes (e.g., 192.168.1.43 → 4 bytes)
    ipParts := TStringList.Create;
    try
      ipParts.Delimiter := '.';
      ipParts.DelimitedText := AConfig.IPAddress;
      for i := 0 to 3 do begin
        b := StrToInt(ipParts[i]);
        ms.Write(b, 1);
      end;
    finally
      ipParts.Free;
    end;
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // Finalize
    SetLength(Result, ms.Size);
    ms.Position := 0;
    ms.Read(Result[0], ms.Size);
  finally
    ms.Free;
  end;
end;

{------------------------------------------------------------------------------}
constructor TMDNSResponderThread.Create(AServer: TIdIPMCastServer; const AConfig: TMDNSConfig);
begin
  inherited Create(False);
  FreeOnTerminate := True;
  FServer := AServer;
  FConfig := AConfig;
end;

{------------------------------------------------------------------------------}

procedure TMDNSResponderThread.CallOnPacket;
begin
  if Assigned(FOnPacket) then
  begin
    FOnPacket(FPacketData, FPacketIP, FPacketPort);
  end;
end;

{------------------------------------------------------------------------------}

procedure TMDNSResponderThread.HandleMDNSQuery(const AData: TIdBytes);
var
  flags, qdCount: Word;
  curPos: Integer;
  qName: string;
  qType, qClass: Word;
  isQueryForPresence: Boolean;
  response: TIdBytes;
begin
  if Length(AData) < 12 then Exit;

  // Log the incoming query
  LogLine('Received mDNS query: ' + BytesToString(AData));

  // parse header
  flags := (AData[2] shl 8) or AData[3];
  // if QR=1 => it's a response, ignore
  if (flags and $8000) <> 0 then
    Exit;

  qdCount := (AData[4] shl 8) or AData[5];
  curPos := 12;
  isQueryForPresence := False;

  while (qdCount > 0) and (curPos < Length(AData)) do
  begin
    qName := DecodeDomainName(AData, curPos);
    if (curPos + 4) > Length(AData) then Exit;
    qType := (AData[curPos] shl 8) or AData[curPos+1];
    qClass:= (AData[curPos+2] shl 8) or AData[curPos+3];
    Inc(curPos, 4);

    // look for _presence._tcp.local, type=PTR(12), class=IN(1)
    if (LowerCase(qName) = '_presence._tcp.local') and (qType = 12) and ((qClass and $7FFF)=1) then
      isQueryForPresence := True;

    Dec(qdCount);
  end;

  if isQueryForPresence then
  begin
    // Build response from the config
    response := BuildMDNSResponse(FConfig);

    // Log the outgoing response
    LogLine('Sending mDNS response: ' + BytesToString(response));

    if Assigned(FServer.Binding) then
      FServer.Binding.SendTo('224.0.0.251', 5353, response, 0, Length(response), Id_IPv4);
  end;
end;

{------------------------------------------------------------------------------}
procedure TMDNSResponderThread.Execute;
var
  buf: TIdBytes;
  bytesRead: Integer;
  peerIP: string;
  peerPort: Word;
  ipVer: TIdIPVersion;
begin
  LogLine('MDNS Responder Thread started');
  while not Terminated do
  begin
    if (FServer <> nil) and (FServer.Binding <> nil) then
    begin
      SetLength(buf, 1600);
      peerIP := '';
      peerPort := 0;
      ipVer := Id_IPv4;

      SetLength(buf, 4096);
      bytesRead := FServer.Binding.RecvFrom(buf, peerIP, peerPort, ipVer);
      if bytesRead > 0 then
      begin
        LogLine('Received ' + IntToStr(bytesRead) + ' bytes from ' + peerIP);
        SetLength(buf, bytesRead);

        // 1) Possibly respond if it's a presence query
        HandleMDNSQuery(buf);

        // 2) If we have an event, pass data to main thread
        if Assigned(FOnPacket) then
        begin
          // Store them in fields
          FPacketData := buf;
          FPacketIP   := peerIP;
          FPacketPort := peerPort;
          // Synchronize the call
          Synchronize(@CallOnPacket);
        end;

      end;
    end;
    Sleep(10);
  end;
  LogLine('MDNS Responder Thread terminated');
end;

end.

