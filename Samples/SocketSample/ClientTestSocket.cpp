#if defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstring>
#include <cstdio>
#include <iostream>
#include <thread>

#include "NetSocket.h"
#include "ClientTestSocket.h"
#include "BitStream.h"

using namespace SocketWire;

Socket clientSocket;
sockaddr_in serverAddr;


class ClientHandler : public EventHandler 
{
public:
  void OnDataReceived(const RecvData& recvData) override {
    if (recvData.bytesRead == 0) return;
    
    BitStream stream(reinterpret_cast<const uint8_t*>(recvData.data), recvData.bytesRead);
    std::string message;
    stream.Read(message);
    std::cout << "\r" << message << "\n>";
    std::cout.flush();
  }
  void OnSocketError(int) override {}
};

void client_receive_loop(int sfd)
{
  while (true) {
    clientSocket.PollReceive();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
/* without using Socket Class :*/
// void receive_messages(int sfd)
// {
//   constexpr size_t buf_size = 1000;
//   char buffer[buf_size];
  
//   while (true)
//   {
//     fd_set readSet;
//     FD_ZERO(&readSet);
//     FD_SET(sfd, &readSet);

//     timeval timeout = { 0, 100000 }; // 100 ms
//     select(sfd + 1, &readSet, NULL, NULL, &timeout);

//     if (FD_ISSET(sfd, &readSet))
//     {
//       memset(buffer, 0, buf_size);
//       sockaddr_in sender_addr;
//       socklen_t addr_len = sizeof(sender_addr);
      
//       ssize_t bytes_received = recvfrom(sfd, buffer, buf_size - 1, 0, 
//                                         (struct sockaddr*)&sender_addr, &addr_len);
      
//       if (bytes_received > 0)
//       {
//         std::cout << "\r" << buffer << "\n>";
//         std::cout.flush();
//       }
//     }
//   }
// }

void display_help()
{
  std::cout << "\n-----------------Client-INFO-------------------\n" 
            << "/c [msg] - Send a message to all connected clients\n"
            << "/mathduel - Challenge someone to a math duel\n"
            << "Any other message will be sent to the server only\n"
            << "----------------Message-ownership----------------\n"
            << "SERVER: [msg] - Send a message to the server\n"
            << "CHAT (sender): [msg] - message from another user\n"
            << "-------------------------------------------------\n\n" << std::endl;
}


int main(int argc, const char **argv)
{
  const char *port = "2025";
  
  ClientHandler handler;
  clientSocket.SetEventHandler(&handler);
  
  if (clientSocket.Bind(nullptr, "0") != 0) {
    printf("Cannot bind socket\n");
    return 1;
  }

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  serverAddr.sin_port = htons(2025);

  std::cout << "Client is using port: " << clientSocket.GetLocalPort() << std::endl;

  BitStream connectStream;
  connectStream.Write(std::string("New client!"));
  clientSocket.SendTo(connectStream.GetData(), connectStream.GetSizeBytes(), serverAddr);

  std::thread receive_thread([]() { client_receive_loop(0); });
  receive_thread.detach();
  
  while (true)
  {
    std::string input;
    printf(">");
    std::getline(std::cin, input);
    
    if (input == "/help" || input == "/h" || input == "/?" || input == "--help") 
    {
      display_help();
      continue;
    }
    
    if (!input.empty())
    {
      BitStream stream;
      stream.Write(input);
      clientSocket.SendTo(stream.GetData(), stream.GetSizeBytes(), serverAddr);
    }
  }
  return 0;
}