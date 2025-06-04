#include "NetSocket.h"
#include <iostream>
#include <unistd.h>

using namespace SocketWire;

class PrintHandler : public EventHandler 
{
public:
  void OnDataReceived(const RecvData& recvData) override 
  {
    std::cout << "Received: " << std::string(recvData.data, recvData.bytesRead) << std::endl;
  }
  void OnSocketError(int) override {}
};

int main() 
{
  Socket server;
  PrintHandler handler;
  server.SetEventHandler(&handler);

  if (server.Bind(nullptr, "40404") != 0) 
  {
    std::cout << "Bind failed\n";
    return 1;
  }
  std::cout << "Server listening on port 40404\n";
  while (true) 
  {
    server.PollReceive();
    usleep(10000);
  }
}