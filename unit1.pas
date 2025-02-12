unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  IdTCPClient, IdTCPServer, IdContext, IdUDPClient, IdGlobal, IdSocketHandle,
  IdIPMCastServer, // for multicast server
  xep0174;

type
  { TMulticastReceiverThread }
  TMulticastReceiverThread = class(TThread)
  private
    FServer: TIdIPMCastServer;
    FReceivedBuffer: TIdBytes;

    procedure DoProcessBuffer;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TIdIPMCastServer);
  end;

  { TForm1 }
  TForm1 = class(TForm)
    BtnSend: TButton;
    BtnRefreshContacts: TButton;
    ListBoxContacts: TListBox;
    IdTCPClient1: TIdTCPClient;
    IdTCPServer1: TIdTCPServer;
    IdUDPClient1: TIdUDPClient;
    IdIPMCastServer1: TIdIPMCastServer;
    MemoSend: TMemo;
    MemoReceived: TMemo;
    procedure BtnRefreshContactsClick(Sender: TObject);
    procedure BtnSendClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure OnClientExecute(AContext: TIdContext);
    procedure DiscoverMDNSClients;
    procedure OnMDNSResponse(AThread: TObject; const AData: TIdBytes;
      ABinding: TIdSocketHandle);
    procedure UpdateListBox;
  private
    FLastReceivedMessage: string;
    FReceiverThread: TMulticastReceiverThread;
    FLastPeerIP: string;
    procedure DisplayReceivedMessage;
  public
  end;

var
  Form1: TForm1;
  Roster: TRoster;

implementation

{$R *.lfm}

{===========================
  TMulticastReceiverThread
===========================}

constructor TMulticastReceiverThread.Create(AServer: TIdIPMCastServer);
begin
  inherited Create(False);  // start immediately
  FreeOnTerminate := True;
  FServer := AServer;
end;

procedure TMulticastReceiverThread.DoProcessBuffer;
begin
  // Call the main form's MDNS response handler.
  // (Passing nil for AThread.)
  if Assigned(Form1) then
    Form1.OnMDNSResponse(nil, FReceivedBuffer, FServer.Binding);
end;

procedure TMulticastReceiverThread.Execute;
var
  LBuffer: TIdBytes;
  LBytesRead: Integer;
  LPeerIP: string;
  LPeerPort: Word;
  LIPVersion: TIdIPVersion;
begin
  while not Terminated do
  begin
    // Allocate a buffer for incoming data.
    SetLength(LBuffer, 4096);
    // Initialize variables for the sender info.
    LPeerIP := '';
    LPeerPort := 0;
    LIPVersion := Id_IPv4;  // initialize; RecvFrom will update this if needed.
    // Call RecvFrom with the proper parameters.
    LBytesRead := FServer.Binding.RecvFrom(LBuffer, LPeerIP, LPeerPort, LIPVersion);
     if LBytesRead >= 0 then
           writeln('RecvFrom returned: ', LBytesRead);
    if LBytesRead > 0 then
    begin
      SetLength(LBuffer, LBytesRead);
      // Store the sender's IP address in a form field.
      Form1.FLastPeerIP := LPeerIP;
      // Remove the following line because PeerIP is read-only:
      // FServer.Binding.PeerIP := LPeerIP;
      FReceivedBuffer := LBuffer;
      Synchronize(@DoProcessBuffer);
    end;
    Sleep(10); // Small delay to avoid a tight loop.
  end;
end;


{===========================
  Helper Function: DecodeDomainName
===========================}

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
      Inc(Offset); // Skip the length byte.
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

{===========================
  TForm1 Methods
===========================}


procedure TForm1.FormCreate(Sender: TObject);
begin
  // Step 1: Create Roster but don't rely on mDNS
  Roster := TRoster.Create;

  // Manually add a buddy:
  // Suppose Pidgin is on machine 192.168.1.43, port 5298
  // "noch" is the username, "debet.local" is the host label (arbitrary)
  Roster.AddContact('noch', 'debet.local', '192.168.1.43', 5298);
  UpdateListBox;

  // Step 2: Start your TCP server so Pidgin can connect to you
  IdTCPServer1.OnExecute := @OnClientExecute;
  StartListening(IdTCPServer1, 5298);


  IdIPMCastServer1.Active := False;
  IdIPMCastServer1.BoundPort := 5353;
  IdIPMCastServer1.MulticastGroup := '224.0.0.251';
  IdIPMCastServer1.Active := True;
  FReceiverThread := TMulticastReceiverThread.Create(IdIPMCastServer1);

end;


procedure TForm1.DiscoverMDNSClients;
var
  Query: TIdBytes;
  DestIP: string;
  Index: Integer;
begin
  DestIP := '224.0.0.251';  // mDNS multicast group.
  SetLength(Query, 38);     // Allocate 38 bytes for the query.
  // DNS Header (12 bytes)
  Query[0] := 0; Query[1] := 0;   // Transaction ID = 0.
  Query[2] := 0; Query[3] := 0;   // Flags = 0.
  Query[4] := 0; Query[5] := 1;   // Questions = 1.
  Query[6] := 0; Query[7] := 0;   // Answer RRs = 0.
  Query[8] := 0; Query[9] := 0;   // Authority RRs = 0.
  Query[10] := 0; Query[11] := 0; // Additional RRs = 0.
  // Query Name "_presence._tcp.local"
  Index := 12;
  Query[Index] := 9; Inc(Index);  // Length of "_presence"
  Move('_presence', Query[Index], 9); Inc(Index, 9);
  Query[Index] := 4; Inc(Index);  // Length of "_tcp"
  Move('_tcp', Query[Index], 4); Inc(Index, 4);
  Query[Index] := 5; Inc(Index);  // Length of "local"
  Move('local', Query[Index], 5); Inc(Index, 5);
  Query[Index] := 0; Inc(Index);  // Null terminator.
  // Query Type (PTR = 0x000C)
  Query[Index] := 0; Query[Index+1] := 12; Inc(Index, 2);
  // Query Class (IN = 0x0001) with unicast response bit (0x8001)
  //Query[Index] := $80; Query[Index+1] := 1; Inc(Index, 2);
  // the above replaced with
  // Query Class (IN = 0x0001) without the unicast response bit,
  // so that responders send multicast replies.
  Query[Index] := 0; Query[Index+1] := 1; Inc(Index, 2);


  // Send the query using the UDP client.
  IdUDPClient1.Host := DestIP;
  IdUDPClient1.Port := 5353;
  IdUDPClient1.SendBuffer(Query);
end;

procedure TForm1.OnMDNSResponse(AThread: TObject; const AData: TIdBytes;
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
  // Skip Question Section.
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
    rrType := (AData[curPos] shl 8) or AData[curPos + 1];
    Inc(curPos, 2);
    rrClass := (AData[curPos] shl 8) or AData[curPos + 1];
    Inc(curPos, 2);
    rrTTL := (AData[curPos] shl 24) or (AData[curPos + 1] shl 16) or
             (AData[curPos + 2] shl 8) or AData[curPos + 3];
    Inc(curPos, 4);
    rrDataLength := (AData[curPos] shl 8) or AData[curPos + 1];
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
  end else
    PeerName := '';
  if (PeerName <> '') and (FLastPeerIP <> '') then
  begin
    MemoReceived.Lines.Add('Extracted Peer: ' + PeerName + ' (' + FLastPeerIP + ')');
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
      Roster.AddContact(PeerName, PeerName + '.local', FLastPeerIP, 5298);
      MemoReceived.Lines.Add('Added to roster: ' + PeerName);
    end else
      MemoReceived.Lines.Add('Peer already in roster: ' + PeerName);
    if ListBoxContacts.Items.IndexOf(PeerName) = -1 then
    begin
      ListBoxContacts.Items.Add(PeerName);
      MemoReceived.Lines.Add('Added to ListBox: ' + PeerName);
    end else
      MemoReceived.Lines.Add('Already in ListBox: ' + PeerName);
    Application.ProcessMessages;
  end else
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

  // This does a one-shot connect to port 5298 of the buddy’s IP and sends one stanza
  SendMessage(
    IdTCPClient1,
    SelectedContact.IP,
    SelectedContact.Port,
    MemoSend.Lines.Text,         // The message body
    'inky@myhost',               // "from"
    SelectedContact.Username + '@' + SelectedContact.Hostname // "to"
  );

  // Clear after sending
  MemoSend.Lines.Clear;
end;

procedure TForm1.BtnRefreshContactsClick(Sender: TObject);
begin
  DiscoverMDNSClients;
end;

procedure TForm1.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if IdTCPServer1.Active then
    IdTCPServer1.Active := False;
  if IdIPMCastServer1.Active then
    IdIPMCastServer1.Active := False;
  if Assigned(FReceiverThread) then
    FReceiverThread.Terminate;
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
  end else
  begin
    FLastReceivedMessage := 'Received empty or no data.';
    TThread.Synchronize(nil, @DisplayReceivedMessage);
  end;
end;

end.

