unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  IdTCPClient, IdTCPServer, IdContext,
  IdIPMCastServer, IdGlobal,
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
  private
    FMDNSThread: TMDNSResponderThread;
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

procedure TForm1.FormCreate(Sender: TObject);
var
  config: TMDNSConfig;
begin
  // Example: set up your identity
  config.UserName := 'inky';
  config.HostName := 'lovelace.local';
  config.Port     := 5298;

  // Start TCP server for inbound chat
  IdTCPServer1.DefaultPort := config.Port;
  IdTCPServer1.OnExecute := @OnClientExecute;
  IdTCPServer1.Active := True;

  // Set up the IP multicast server (for mDNS)
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
{ Optional: manually broadcast a "who's out there?" _presence._tcp.local query. }
var
  query: TIdBytes;
  idx: Integer;
begin
  SetLength(query, 38);
  // Basic DNS query: QDCount=1, Q= _presence._tcp.local, Type=PTR(12), Class=IN(1)
  // This is just an example. Real code might be same as in your old "DiscoverMDNSClients."
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

  // Now send
  if IdIPMCastServer1.Binding <> nil then
  begin
    IdIPMCastServer1.Binding.SendTo(
      '224.0.0.251',
      5353,
      query, 0, Length(query),
      Id_IPv4
    );
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

procedure TForm1.OnMDNSPacket(const AData: TIdBytes; const ASourceIP: string; ASourcePort: Word);
begin
  LogLine(Format('Got %d bytes from %s:%d (DNS)', [Length(AData), ASourceIP, ASourcePort]));
  // You could parse further if you want to discover other peers' presence
end;

procedure TForm1.LogLine(const S: string);
begin
  MemoReceived.Lines.Add(S);
end;

end.

