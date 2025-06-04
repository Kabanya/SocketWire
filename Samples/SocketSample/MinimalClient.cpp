#include "NetSocket.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace SocketWire;

class PrintHandler : public EventHandler 
{
public:
  void OnDataReceived(const RecvData& recvData) override {
    std::cout << "Received: " << std::string(recvData.data, recvData.bytesRead) << std::endl;
  }
  void OnSocketError(int) override {}
};

int main() 
{
  Socket client;
  PrintHandler handler;
  client.SetEventHandler(&handler);

  client.Bind(nullptr, "0");

  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dest.sin_port = htons(40404);

  std::string msg = "Hello from use case of Socket class!";
  client.SendTo(msg.c_str(), msg.size(), dest);

  for (int i = 0; i < 10; ++i) 
  {
    client.PollReceive();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return 0;
}