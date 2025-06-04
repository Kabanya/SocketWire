#if defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstring>
#include <iostream>
#include <thread>
#include <functional>
#include <vector>

#include "ServerTestSocket.h"
#include "NetSocket.h"
#include "BitStream.h"

using namespace SocketWire;

Socket serverSocket;
std::vector<Client> clients;

std::string client_to_string(const Client& client)
{
  return std::string(inet_ntoa(client.addr.sin_addr)) + ":" + std::to_string(ntohs(client.addr.sin_port));
}

void msg_to_all_clients(int sfd, const std::vector<Client>& clients, const std::string& message)
{
  BitStream stream;
  stream.Write(message);
  
  for (const Client& client : clients) {
    serverSocket.SendTo(stream.GetData(), stream.GetSizeBytes(), client.addr);
  }
  printf("msg to all clients: %s\n", message.c_str());
}

void msg_to_client(int sfd, const Client& client, const std::string& message)
{
  BitStream stream;
  stream.Write(message);
  serverSocket.SendTo(stream.GetData(), stream.GetSizeBytes(), client.addr);
  printf("msg to client (%s): %s\n", client_to_string(client).c_str(), message.c_str());
}

class ServerHandler : public EventHandler 
{
public:
  void OnDataReceived(const RecvData& recvData) override 
  {
    if (recvData.bytesRead == 0) return;
    
    BitStream stream(reinterpret_cast<const uint8_t*>(recvData.data), recvData.bytesRead);
    std::string message;
    stream.Read(message);
    
    Client currentClient;
    currentClient.addr = recvData.fromAddr;
    currentClient.id = client_to_string(currentClient);
    
    bool clientExists = false;
    for (const Client& client : clients) 
    {
      if (client.addr.sin_addr.s_addr == recvData.fromAddr.sin_addr.s_addr && 
        client.addr.sin_port == recvData.fromAddr.sin_port) {
        clientExists = true;
        currentClient = client;
        break;
      }
    }
    
    if (!clientExists) 
    {
      clients.push_back(currentClient);
      std::string welcomeMsg = "\n/c - message to all users\n/help - for help";
      msg_to_client(0, currentClient, welcomeMsg);
    }
    
    if (message.length() > 3 && message.substr(0, 3) == "/c ") 
    {
      std::string chatMessage = message.substr(3);
      std::string senderInfo = client_to_string(currentClient);
      
      printf("msg from (%s): %s\n", senderInfo.c_str(), chatMessage.c_str());
      std::string broadcastMsg = "CHAT (" + senderInfo + "): " + chatMessage;
      msg_to_all_clients(0, clients, broadcastMsg);
    }
    else {
      printf("(%s) %s\n", currentClient.id.c_str(), message.c_str());
    }
  }
  void OnSocketError(int) override {}
};

int main(int argc, const char **argv)
{
  const char *port = "2025";
  
  ServerHandler handler;
  serverSocket.SetEventHandler(&handler);
  
  if (serverSocket.Bind(nullptr, port) != 0) {
    printf("cannot create socket\n");
    return 1;
  }
  printf("listening on port %s!\n", port);

  while (true) 
  {
    serverSocket.PollReceive();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return 0;
}