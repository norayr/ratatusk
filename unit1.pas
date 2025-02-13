unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  IdTCPClient, IdTCPServer, IdContext,
  IdIPMCastServer, IdUDPClient, IdGlobal,
  xep0174,
  mdnsCore, mdnsResolver, mdnsResolverLinux;
  //mdns;

type

  { TForm1 }

  TForm1 = class(TForm)
    BtnSend: TButton;
    ListBoxContacts: TListBox;
    MemoSend: TMemo;
    MemoReceived: TMemo;
    IdTCPClient1: TIdTCPClient;
    IdTCPServer1: TIdTCPServer;
    MdnsResolver: TMdnsResolver;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure BtnSendClick(Sender: TObject);
    procedure OnClientExecute(AContext: TIdContext);
    procedure UpdateListBox;
  private
    FRoster: TRoster;
    procedure OnMdnsResolved(Sender: TObject; const Result: TmdnsResult);
    procedure LogLine(const S: string);
  public
  end;

 type
  { Store your identity (user, host, port) so the mDNS code can build presence packets. }
  TMDNSConfig = record
    UserName: string;   // e.g. "inky"
    HostName: string;   // e.g. "lovelace.local"
    Port: Word;         // e.g. 5298
    IPAddress: string;
  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}



procedure TForm1.UpdateListBox;
var
  i: Integer;
begin
  ListBoxContacts.Items.Clear;
  for i := 0 to High(FRoster.Contacts) do
    ListBoxContacts.Items.Add(FRoster.Contacts[i].Username);
end;

procedure TForm1.OnMdnsResolved(Sender: TObject; const Result: TmdnsResult);
var
  Username, Hostname: string;
begin
  if Result.isError then Exit;

  // Parse PTR record (service instance name)
  if Result.PTR.NameHost.Contains('@') then
  begin
    Username := Copy(Result.PTR.NameHost, 1, Pos('@', Result.PTR.NameHost)-1);
    Hostname := Copy(Result.PTR.NameHost, Pos('@', Result.PTR.NameHost)+1, Length(Result.PTR.NameHost));
    Hostname := StringReplace(Hostname, '._presence._tcp.local', '', [rfReplaceAll]);

    // Add to roster
    FRoster.AddContact(Username, Hostname, Result.A.IpAddress, Result.SRV.Port);
    UpdateListBox;
  end;
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

  // Set up mDNS Resolver (Discover)
  MdnsResolver := TMdnsResolver.Create(Self);
  MdnsResolver.ServiceType := '_presence._tcp.local';
  MdnsResolver.OnResolved := @OnMdnsResolved;
  MdnsResolver.StartResolve;

  MdnsResolver.StartAdvertise(
    'inky',          // UserName
    'lovelace.local',// HostName
    '192.168.1.77', // IPAddress
    5298            // Port
  );

  // Set up the IP multicast server (for mDNS)
  //IdIPMCastServer1.Binding.IP := '0.0.0.0';
  //IdIPMCastServer1.Active := False;
  //IdIPMCastServer1.BoundPort := 5353;
  //IdIPMCastServer1.MulticastGroup := '224.0.0.251';
  //IdIPMCastServer1.Active := True;

  // Create the mDNS responder thread
  //FMDNSThread := TMDNSResponderThread.Create(IdIPMCastServer1, config);
  // Hook a callback so we can see inbound DNS traffic if we want
  //FMDNSThread.OnPacket := @OnMDNSPacket;
end;

procedure TForm1.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  if IdTCPServer1.Active then
    IdTCPServer1.Active := False;
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

procedure TForm1.LogLine(const S: string);
begin
  MemoReceived.Lines.Add(S);
end;

end.

