unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  IdTCPClient, IdTCPServer, IdContext,
  IdIPMCastServer, IdUDPClient, IdGlobal,
  xep0174,
  mdns;

type

  { TForm1 }

  TForm1 = class(TForm)
    BtnSend: TButton;
    BtnRefreshContacts: TButton; // optional
    ListBoxContacts: TListBox;
    MemoSend: TMemo;
    MemoReceived: TMemo;
    IdTCPClient1: TIdTCPClient;
    IdTCPServer1: TIdTCPServer;
    IdIPMCastServer1: TIdIPMCastServer;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure BtnSendClick(Sender: TObject);
    procedure BtnRefreshContactsClick(Sender: TObject);
    procedure OnClientExecute(AContext: TIdContext);
    procedure UpdateListBox;
  private
    FMDNSThread: TMDNSResponderThread;
    FRoster: TRoster;
    procedure OnMDNSPacket(const AData: TIdBytes; const ASourceIP: string; ASourcePort: Word);
    procedure LogLine(const S: string);
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

uses
  IdUDPBase; // if you want to manually send queries in BtnRefreshContactsClick


procedure TForm1.UpdateListBox;
var
  i: Integer;
begin
  ListBoxContacts.Items.Clear;
  for i := 0 to High(FRoster.Contacts) do
    ListBoxContacts.Items.Add(FRoster.Contacts[i].Username);
end;



procedure TForm1.FormCreate(Sender: TObject);
var
  config: TMDNSConfig;
begin
  // Example: set up your identity
  config.UserName := 'inky';
  config.HostName := 'lovelace.local';
  config.Port     := 5298;
  config.IPAddress := '192.168.1.77';

  FRoster := TRoster.Create;
  FRoster.AddContact('noch', 'debet.local', '192.168.1.43', 5298);
  UpdateListbox;


  // Start TCP server for inbound chat
  IdTCPServer1.DefaultPort := config.Port;
  IdTCPServer1.OnExecute := @OnClientExecute;
  IdTCPServer1.Active := True;

  // Set up the IP multicast server (for mDNS)
  IdIPMCastServer1.Binding.IP := '0.0.0.0';
  IdIPMCastServer1.Active := False;
  IdIPMCastServer1.BoundPort := 5353;
  IdIPMCastServer1.MulticastGroup := '224.0.0.251';
  IdIPMCastServer1.Active := True;

  // Create the mDNS responder thread
  FMDNSThread := TMDNSResponderThread.Create(IdIPMCastServer1, config);
  // Hook a callback so we can see inbound DNS traffic if we want
  FMDNSThread.OnPacket := @OnMDNSPacket;
end;

procedure TForm1.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if Assigned(FMDNSThread) then
  begin
    FMDNSThread.Terminate;
    FMDNSThread := nil; // Freed automatically
  end;

  if IdTCPServer1.Active then
    IdTCPServer1.Active := False;

  if IdIPMCastServer1.Active then
    IdIPMCastServer1.Active := False;
end;

procedure TForm1.BtnSendClick(Sender: TObject);
begin
  // Example: send a test message to some IP/port
  if MemoSend.Text = '' then Exit;

  IdTCPClient1.Host := '192.168.1.43';
  IdTCPClient1.Port := 5298;
  IdTCPClient1.Connect;
  try
    IdTCPClient1.IOHandler.WriteLn(MemoSend.Text);
  finally
    IdTCPClient1.Disconnect;
  end;

  LogLine('Sent: '+ MemoSend.Text);
  MemoSend.Clear;
end;

procedure TForm1.BtnRefreshContactsClick(Sender: TObject);
var
  query: TIdBytes;
  idx: Integer;
begin
  SetLength(query, 38);
  FillChar(query[0], 38, 0);
  // Basic DNS query: QDCount=1, Q= _presence._tcp.local, Type=PTR(12), Class=IN(1)
  query[0] := 0; // TxID=0
  query[1] := 0;
  query[2] := 0; // Flags=0
  query[3] := 0;
  // QDCount=1
  query[4] := 0;
  query[5] := 1;
  // ANCount, NSCount, ARCount=0
  query[6] := 0;
  query[7] := 0;
  query[8] := 0;
  query[9] := 0;
  query[10] := 0;
  query[11] := 0;

  // Encode "_presence._tcp.local"
  idx := 12;
  query[idx] := 9; Inc(idx);
  Move('_presence'[1], query[idx], 9);
  Inc(idx, 9);
  query[idx] := 4; Inc(idx);
  Move('_tcp'[1], query[idx], 4);
  Inc(idx, 4);
  query[idx] := 5; Inc(idx);
  Move('local'[1], query[idx], 5);
  Inc(idx, 5);
  query[idx] := 0; // terminator
  Inc(idx);

  // QType=PTR(12)
  query[idx] := 0;
  query[idx+1] := 12;
  Inc(idx,2);
  // QClass=IN(1)
  query[idx] := 0;
  query[idx+1] := 1;
  Inc(idx,2);

  // Log the query
  LogLine('Sending mDNS query: ' + BytesToString(query));

  // Now send
  if IdIPMCastServer1.Binding <> nil then
  begin
    IdIPMCastServer1.Binding.SendTo(
      '224.0.0.251',
      5353,
      query, 0, Length(query),
      Id_IPv4
    );
   //UDPClient := TIdUDPClient.Create(nil);
  //try
  //  UDPClient.BoundIP := IdIPMCastServer1.Binding.IP;
  //  UDPClient.BoundPort := 5353;
  //  UDPClient.Host := '224.0.0.251'; // Multicast address
  //
   // UDPClient.SendBuffer('224.0.0.251', 5353, query);
   // LogLine('Sent _presence._tcp.local PTR query via UDP');
 // finally
 //   UDPClient.Free;
    LogLine('Sent _presence._tcp.local PTR query');
  end;
end;

procedure TForm1.OnClientExecute(AContext: TIdContext);
var
  s: string;
begin
  s := 'Client connected: ' + AContext.Binding.PeerIP;
  LogLine(s);

  if not AContext.Connection.IOHandler.InputBufferIsEmpty then
  begin
    s := AContext.Connection.IOHandler.AllData;
    LogLine('Received: ' + s);
  end
  else
    LogLine('Received empty or no data');
end;

function ExtractUsername(const ServiceName: string): string;
var
  PosAt: Integer;
begin
  PosAt := Pos('@', ServiceName);
  if PosAt > 0 then
    Result := Copy(ServiceName, 1, PosAt - 1)
  else
    Result := '';
end;

procedure TForm1.OnMDNSPacket(const AData: TIdBytes; const ASourceIP: string; ASourcePort: Word);
var
  flags, qdCount, anCount: Word;
  curPos: Integer;
  i, j: Integer;
  //name: string;
  rType, rClass, dataLen: Word;
  ttl: Cardinal;
  srvPort: Word;
  targetHost, txtData: string;
  ipAddress: string;
begin
  LogLine(Format('Got %d bytes from %s:%d (DNS)', [Length(AData), ASourceIP, ASourcePort]));

  if Length(AData) < 12 then Exit;

  // Parse DNS header
  flags := (AData[2] shl 8) or AData[3];
  qdCount := (AData[4] shl 8) or AData[5];
  anCount := (AData[6] shl 8) or AData[7];
  curPos := 12;

  // Skip questions section
  for i := 0 to qdCount - 1 do
  begin
    DecodeDomainName(AData, curPos);
    Inc(curPos, 4); // Skip type and class
  end;

  // Parse answers and additional records
  for i := 0 to anCount + ((AData[8] shl 8) or AData[9]) - 1 do // Include additional
  begin
    name := DecodeDomainName(AData, curPos);
    if curPos + 10 > Length(AData) then Break;

    rType := (AData[curPos] shl 8) or AData[curPos+1];
    rClass := (AData[curPos+2] shl 8) or AData[curPos+3];
    ttl := (AData[curPos+4] shl 24) or (AData[curPos+5] shl 16) or
           (AData[curPos+6] shl 8) or AData[curPos+7];
    dataLen := (AData[curPos+8] shl 8) or AData[curPos+9];
    Inc(curPos, 10);

    // Check if it's a PTR record for "_presence._tcp.local"
    if (rType = $000C) and (name = '_presence._tcp.local') then
    begin
      // PTR points to the service instance name
      name := DecodeDomainName(AData, curPos);
    end
    // Check for SRV record
    else if (rType = $0021) then
    begin
      // Skip priority, weight
      Inc(curPos, 4);
      srvPort := (AData[curPos] shl 8) or AData[curPos+1];
      Inc(curPos, 2);
      targetHost := DecodeDomainName(AData, curPos);
      // Add to roster
      FRoster.AddContact(ExtractUsername(name), targetHost, '', srvPort);
      UpdateListBox;
    end
    // Check for A record
    else if (rType = $0001) and (dataLen = 4) then
    begin
      ipAddress := Format('%d.%d.%d.%d', [AData[curPos], AData[curPos+1], AData[curPos+2], AData[curPos+3]]);
      // Update the contact's IP if targetHost matches
      for j := 0 to High(FRoster.Contacts) do
        if FRoster.Contacts[j].Hostname = name then
          FRoster.Contacts[j].IP := ipAddress;
      UpdateListBox;
    end;

    Inc(curPos, dataLen);
  end;
end;

procedure TForm1.LogLine(const S: string);
begin
  MemoReceived.Lines.Add(S);
end;

end.

