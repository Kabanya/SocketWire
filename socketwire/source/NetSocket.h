#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include <netinet/in.h>
#include <string>
#include <vector>

struct addrinfo;

namespace socketwire
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
  virtual void onDataReceived(const RecvData& recv_data) = 0;
  virtual void onSocketError(int error_code) = 0;
};

class Socket
{
private:
  int socketFd = -1;
  EventHandler* eventHandler = nullptr;

public:
  Socket();
  ~Socket();

  int bind(const char* address, const char* port);
  int sendTo(const void* data, size_t length, const sockaddr_in& dest);
  void setEventHandler(EventHandler* handler);
  void pollReceive();

  explicit operator int() const { return socketFd; }
  uint16_t getLocalPort() const;

  static bool isPortInUse(const char* address, const char* port);
  static std::vector<std::string> getLocalIPs();
};

} // namespace socketwire

#endif // NET_SOCKET_H