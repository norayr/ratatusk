unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, IdTCPClient,
  IdTCPServer, IdContext, xep0174;

type
  { TForm1 }
  TForm1 = class(TForm)
    Button1: TButton;
    IdTCPClient1: TIdTCPClient;  // Ensure this is declared
    IdTCPServer1: TIdTCPServer;
    MemoSend: TMemo;
    MemoReceived: TMemo;

    procedure Button1Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure OnClientExecute(AContext: TIdContext);
  private
    FLastReceivedMessage: string;
    procedure DisplayReceivedMessage;
  public
  end;

var
  Form1: TForm1;
  Roster: xep0174.TRoster;
implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  Roster := TRoster.Create;
  Roster.AddContact('noch', 'debet.local', '192.168.1.43', 5298);

  // Assign the server event
  IdTCPServer1.OnExecute := @OnClientExecute;

  StartListening(IdTCPServer1, 5298);




end;

procedure TForm1.Button1Click(Sender: TObject);
begin
    // Ensure IdTCPClient1 is properly set up
  IdTCPClient1.Host := '192.168.1.43';
  IdTCPClient1.Port := 5298;

  // Send a message with correct XMPP format
  if MemoSend.Lines.Text = '' then
  begin
    SendMessage(IdTCPClient1, '192.168.1.43', 5298, 'Hello, Pidgin!', 'inky@lovelace', 'noch@debet');
  end
 else
  begin
    SendMessage(IdTCPClient1, '192.168.1.43', 5298, MemoSend.Lines.Text, 'inky@lovelace', 'noch@debet');
    MemoSend.Lines.Text:= '';
  end;
end;

procedure TForm1.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
    if IdTCPServer1.Active then
    begin
      IdTCPServer1.Active := False;
    end;
  Roster.Free;
end;

procedure TForm1.DisplayReceivedMessage;
begin
  //MemoReceived.Lines.Add('Received: ' + Msg);
  //MemoReceived.Lines.Add('Received: ' + FLastReceivedMessage);
  MemoReceived.Lines.Add(FLastReceivedMessage);
end;

procedure TForm1.OnClientExecute(AContext: TIdContext);
var
  Msg: string;
begin
   //Msg := AContext.Connection.IOHandler.ReadLn;
  //WriteLn('Received message: ', Msg);
  FLastReceivedMessage := 'Client connected: ' + AContext.Connection.Socket.Binding.PeerIP;
  TThread.Synchronize(nil, @DisplayReceivedMessage);

  if not AContext.Connection.IOHandler.InputBufferIsEmpty then
  begin
    FLastReceivedMessage := AContext.Connection.IOHandler.AllData; // Read full message
    TThread.Synchronize(nil, @DisplayReceivedMessage);
  end
  else
  begin
    FLastReceivedMessage := 'Received empty or no data.';
    TThread.Synchronize(nil, @DisplayReceivedMessage);
  end;
end;

end.

