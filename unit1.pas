unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  IdTCPClient, IdTCPServer, IdContext, IdUDPServer, IdGlobal, IdSocketHandle,
  xep0174;

type
  { TForm1 }
  TForm1 = class(TForm)
    BtnSend: TButton;
    BtnRefreshContacts: TButton;
    ListBoxContacts: TListBox;
    IdTCPClient1: TIdTCPClient;
    IdTCPServer1: TIdTCPServer;
    IdUDPServer1: TIdUDPServer;
    MemoSend: TMemo;
    MemoReceived: TMemo;
    procedure BtnRefreshContactsClick(Sender: TObject);
    procedure BtnSendClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure OnClientExecute(AContext: TIdContext);
    procedure DiscoverMDNSClients;
    procedure OnUDPRead(AThread: TIdUDPListenerThread; const AData: TIdBytes;
      ABinding: TIdSocketHandle);
    procedure UpdateListBox;
  private
    FLastReceivedMessage: string;
    FLastPeerIP: string;
    procedure DisplayReceivedMessage;
  public
  end;

var
  Form1: TForm1;
  Roster: TRoster;

implementation

{$R *.lfm}

{---------------------------
  Helper Function: DecodeDomainName
---------------------------}
function DecodeDomainName(const AData: TIdBytes; var Offset: Integer): string;
var
  LabelLen: Byte;
  s, resultStr: string;
  pointerOffset, originalOffset: Integer;
  jumped: Boolean;
begin
  resultStr := '';
  jumped := False;
  originalOffset := Offset;
  while True do
  begin
    if Offset >= Length(AData) then Break;  // Safety check.
    LabelLen := AData[Offset];
    if LabelLen = 0 then
    begin
      Inc(Offset);
      Break;
    end;
    if (LabelLen and $C0) = $C0 then
    begin
      pointerOffset := ((LabelLen and $3F) shl 8) or AData[Offset + 1];
      if not jumped then
        originalOffset := Offset + 2;
      Offset := pointerOffset;
      jumped := True;
    end
    else
    begin
      Inc(Offset); // Skip length byte.
      if Offset + LabelLen > Length(AData) then Break; // Safety check.
      SetString(s, PAnsiChar(@AData[Offset]), LabelLen);
      Inc(Offset, LabelLen);
      if resultStr <> '' then
        resultStr := resultStr + '.';
      resultStr := resultStr + s;
    end;
  end;
  if jumped then
    Offset := originalOffset;
  Result := resultStr;
end;

{---------------------------
  TForm1 Methods
---------------------------}

procedure TForm1.FormCreate(Sender: TObject);
var
  b: TIdSocketHandle;
begin
  // Create the roster and add a default contact.
  Roster := TRoster.Create;
  Roster.AddContact('noch', 'debet.local', '192.168.1.43', 5298);

  // Set up and start the TCP server.
  IdTCPServer1.OnExecute := @OnClientExecute;
  StartListening(IdTCPServer1, 5298);

 // Configure the UDP server for mDNS responses.
IdUDPServer1.Active := False;
IdUDPServer1.Bindings.Clear;
IdUDPServer1.ReuseSocket := rsTrue;   // <--- Add this line here
b := IdUDPServer1.Bindings.Add;
b.IP := '0.0.0.0';  // Listen on all interfaces.
b.Port := 5353;
// Join the multicast group using the binding's AddMulticastMembership method.
b.AddMulticastMembership('224.0.0.251');
IdUDPServer1.OnUDPRead := @OnUDPRead;
IdUDPServer1.Active := True;

end;

procedure TForm1.DiscoverMDNSClients;
var
  Query: TIdBytes;
  DestIP: string;
  Index: Integer;
begin
  DestIP := '224.0.0.251';  // multicast group address.
  SetLength(Query, 38);     // allocate 38 bytes for the query
  // DNS Header (12 bytes)
  Query[0] := 0; Query[1] := 0;     // Transaction ID = 0.
  Query[2] := 0; Query[3] := 0;     // Flags = 0.
  Query[4] := 0; Query[5] := 1;     // Questions = 1.
  Query[6] := 0; Query[7] := 0;     // Answer RRs = 0.
  Query[8] := 0; Query[9] := 0;     // Authority RRs = 0.
  Query[10] := 0; Query[11] := 0;   // Additional RRs = 0.
  // Query Name: "_presence._tcp.local"
  Index := 12;
  Query[Index] := 9; Inc(Index);
  Move('_presence', Query[Index], 9); Inc(Index, 9);
  Query[Index] := 4; Inc(Index);
  Move('_tcp', Query[Index], 4); Inc(Index, 4);
  Query[Index] := 5; Inc(Index);
  Move('local', Query[Index], 5); Inc(Index, 5);
  Query[Index] := 0; Inc(Index);  // null terminator.
  // Query Type (PTR = 0x000C)
  Query[Index] := 0; Query[Index+1] := 12; Inc(Index, 2);
  // Query Class (IN = 0x0001) without unicast response bit.
  Query[Index] := 0; Query[Index+1] := 1; Inc(Index, 2);

  // Send the query using the UDP server (so that the source port is 5353).
  IdUDPServer1.SendBuffer(DestIP, 5353, Query);
end;

procedure TForm1.OnUDPRead(AThread: TIdUDPListenerThread; const AData: TIdBytes;
  ABinding: TIdSocketHandle);
var
  curPos: Integer;
  QDCount, ANCount: Word;
  i: Integer;
  dummy: string;
  rrName: string;
  rrType, rrClass: Word;
  rrTTL: Cardinal;
  rrDataLength: Word;
  PeerFullName: string;
  PeerName: string;
  ExistsInRoster: Boolean;
begin
  if Length(AData) < 12 then Exit;
  curPos := 0;
  // Skip DNS header: Transaction ID (2 bytes) and Flags (2 bytes)
  Inc(curPos, 4);
  QDCount := (AData[curPos] shl 8) or AData[curPos + 1];
  Inc(curPos, 2);
  ANCount := (AData[curPos] shl 8) or AData[curPos + 1];
  Inc(curPos, 2);
  Inc(curPos, 4);  // Skip NSCount and ARCount.
  // Skip the Question Section.
  for i := 1 to QDCount do
  begin
    dummy := DecodeDomainName(AData, curPos);
    Inc(curPos, 4);  // Skip QTYPE and QCLASS.
  end;
  PeerFullName := '';
  // Process Answer Records.
  for i := 1 to ANCount do
  begin
    rrName := DecodeDomainName(AData, curPos);
    if curPos + 10 > Length(AData) then Break;
    rrType := (AData[curPos] shl 8) or AData[curPos+1];
    Inc(curPos, 2);
    rrClass := (AData[curPos] shl 8) or AData[curPos+1];
    Inc(curPos, 2);
    rrTTL := (AData[curPos] shl 24) or (AData[curPos+1] shl 16) or
             (AData[curPos+2] shl 8) or AData[curPos+3];
    Inc(curPos, 4);
    rrDataLength := (AData[curPos] shl 8) or AData[curPos+1];
    Inc(curPos, 2);
    // Look for a PTR record (type 12).
    if rrType = 12 then
    begin
      PeerFullName := DecodeDomainName(AData, curPos);
      Break; // Use the first PTR record found.
    end else
      Inc(curPos, rrDataLength);
  end;
  MemoReceived.Lines.Add('Extracted PTR: ' + PeerFullName);
  if PeerFullName <> '' then
  begin
    i := Pos('@', PeerFullName);
    if i > 1 then
      PeerName := Copy(PeerFullName, 1, i - 1)
    else
      PeerName := PeerFullName;
  end
  else
    PeerName := '';
  if (PeerName <> '') and (ABinding.PeerIP <> '') then
  begin
    MemoReceived.Lines.Add('Extracted Peer: ' + PeerName + ' (' + ABinding.PeerIP + ')');
    FLastReceivedMessage := PeerName;
    ExistsInRoster := False;
    for i := 0 to Length(Roster.Contacts) - 1 do
    begin
      if Roster.Contacts[i].Username = PeerName then
      begin
        ExistsInRoster := True;
        Break;
      end;
    end;
    if not ExistsInRoster then
    begin
      Roster.AddContact(PeerName, PeerName + '.local', ABinding.PeerIP, 5298);
      MemoReceived.Lines.Add('Added to roster: ' + PeerName);
    end
    else
      MemoReceived.Lines.Add('Peer already in roster: ' + PeerName);
    if ListBoxContacts.Items.IndexOf(PeerName) = -1 then
    begin
      ListBoxContacts.Items.Add(PeerName);
      MemoReceived.Lines.Add('Added to ListBox: ' + PeerName);
    end
    else
      MemoReceived.Lines.Add('Already in ListBox: ' + PeerName);
    Application.ProcessMessages;
  end
  else
    MemoReceived.Lines.Add('Invalid peer data received!');
end;

procedure TForm1.UpdateListBox;
var
  i: Integer;
begin
  ListBoxContacts.Items.Clear;
  for i := 0 to High(Roster.Contacts) do
    ListBoxContacts.Items.Add(Roster.Contacts[i].Username);
end;

procedure TForm1.BtnSendClick(Sender: TObject);
var
  SelectedContact: TRosterEntry;
begin
  if ListBoxContacts.ItemIndex < 0 then
  begin
    MemoReceived.Lines.Add('Select a contact first!');
    Exit;
  end;
  SelectedContact := Roster.Contacts[ListBoxContacts.ItemIndex];
  IdTCPClient1.Host := SelectedContact.IP;
  IdTCPClient1.Port := SelectedContact.Port;
  if MemoSend.Lines.Text = '' then
  begin
    SendMessage(IdTCPClient1, SelectedContact.IP, SelectedContact.Port,
      'Hello, Pidgin!', 'inky@lovelace',
      SelectedContact.Username + '@' + SelectedContact.Hostname);
  end
  else
  begin
    SendMessage(IdTCPClient1, SelectedContact.IP, SelectedContact.Port,
      MemoSend.Lines.Text, 'inky@lovelace',
      SelectedContact.Username + '@' + SelectedContact.Hostname);
    MemoSend.Lines.Text := '';
  end;
end;

procedure TForm1.BtnRefreshContactsClick(Sender: TObject);
begin
  DiscoverMDNSClients;
end;

procedure TForm1.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if IdTCPServer1.Active then
    IdTCPServer1.Active := False;
  if IdUDPServer1.Active then
    IdUDPServer1.Active := False;
  Roster.Free;
end;

procedure TForm1.DisplayReceivedMessage;
begin
  MemoReceived.Lines.Add(FLastReceivedMessage);
end;

procedure TForm1.OnClientExecute(AContext: TIdContext);
begin
  FLastReceivedMessage := 'Client connected: ' + AContext.Connection.Socket.Binding.PeerIP;
  TThread.Synchronize(nil, @DisplayReceivedMessage);
  if not AContext.Connection.IOHandler.InputBufferIsEmpty then
  begin
    FLastReceivedMessage := AContext.Connection.IOHandler.AllData;
    TThread.Synchronize(nil, @DisplayReceivedMessage);
  end
  else
  begin
    FLastReceivedMessage := 'Received empty or no data.';
    TThread.Synchronize(nil, @DisplayReceivedMessage);
  end;
end;

end.

