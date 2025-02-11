{
  This FreePascal program implements a minimal XMPP-like chat client
  without Avahi/mDNS. It uses direct TCP connections to send and receive
  messages between manually added peers, now using Indy for better cross-platform support.
}

unit xep0174;

interface

uses
  Classes, SysUtils, IdTCPClient, IdTCPServer;

type
  TRosterEntry = record
    Username: string;
    Hostname: string;
    IP: string;
    Port: Integer;
  end;

  TRoster = class
  private

  public
    Contacts: array of TRosterEntry;
    procedure AddContact(AUsername, AHostname, AIP: string; APort: Integer);
    procedure RemoveContact(AUsername: string);
    function GetContact(AUsername: string): TRosterEntry;
  end;


procedure SendMessage(Client: TIdTCPClient; AIP: string; APort: Integer; AMessage: string; AFrom, ATo: string);
procedure StartListening(Server: TIdTCPServer; APort: Integer);

implementation

procedure TRoster.AddContact(AUsername, AHostname, AIP: string; APort: Integer);
begin
  SetLength(Contacts, Length(Contacts) + 1);
  Contacts[High(Contacts)].Username := AUsername;
  Contacts[High(Contacts)].Hostname := AHostname;
  Contacts[High(Contacts)].IP := AIP;
  Contacts[High(Contacts)].Port := APort;
end;

procedure TRoster.RemoveContact(AUsername: string);
var
  i, j: Integer;
begin
  for i := 0 to High(Contacts) do
    if Contacts[i].Username = AUsername then
    begin
      for j := i to High(Contacts) - 1 do
        Contacts[j] := Contacts[j + 1];
      SetLength(Contacts, Length(Contacts) - 1);
      Break;
    end;
end;

function TRoster.GetContact(AUsername: string): TRosterEntry;
var
  i: Integer;
begin
  for i := 0 to High(Contacts) do
    if Contacts[i].Username = AUsername then
      Exit(Contacts[i]);
  raise Exception.Create('Contact not found');
end;

procedure SendMessage(Client: TIdTCPClient; AIP: string; APort: Integer; AMessage: string; AFrom, ATo: string);
var
  XMPPMessage: string;
begin
  Client.Host := AIP;
  Client.Port := APort;
  Client.Connect;
  try
    // Construct a proper XMPP message with required attributes
    XMPPMessage :=
      '<message to="' + ATo + '" from="' + AFrom + '" type="chat" xmlns="jabber:client">' +
      '<body>' + AMessage + '</body>' +
      '</message>';

    Client.IOHandler.WriteLn(XMPPMessage);
  finally
    Client.Disconnect;
  end;
end;


procedure StartListening(Server: TIdTCPServer; APort: Integer);
begin
  Server.DefaultPort := APort;
  Server.Active := True;
end;

end.

