#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include <vector>
#include <netinet/in.h>

struct addrinfo;

namespace SocketWire 
{

int create_dgram_socket(const char *address, const char *port, addrinfo *res_addr);
void receive_messages(int sfd) __attribute__((weak));

struct RecvData 
{
  char data[1500];    
  int bytesRead;
  sockaddr_in fromAddr;
  uint64_t timeReceived;
};

class EventHandler 
{
public:
  virtual ~EventHandler() = default;
  virtual void OnDataReceived(const RecvData& recvData) = 0;
  virtual void OnSocketError(int errorCode) = 0;
};

class Socket
{
private:
  int socketFd = -1;
  EventHandler* eventHandler = nullptr;
    
public:
  Socket();
  ~Socket();

  int Bind(const char* address, const char* port);
  int SendTo(const void* data, size_t length, const sockaddr_in& dest);
  void SetEventHandler(EventHandler* handler);
  void PollReceive();

  operator int() const { return socketFd; }
  uint16_t GetLocalPort() const;

  static bool IsPortInUse(const char* address, const char* port);
  static std::vector<std::string> GetLocalIPs();
};

} // namespace SocketWire

#endif // NET_SOCKET_H