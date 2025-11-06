#include <chrono>
#include <stdio.h>
#include <cstring>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "net_socket.hpp"

namespace socketwire
{
static int get_dgram_socket(addrinfo *addr, bool should_bind, addrinfo *res_addr)
{
  for (addrinfo *ptr = addr; ptr != nullptr; ptr = ptr->ai_next)
  {
    if (ptr->ai_family != AF_INET || ptr->ai_socktype != SOCK_DGRAM || ptr->ai_protocol != IPPROTO_UDP)
      continue;
    int sfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (sfd == -1)
      continue;

    fcntl(sfd, F_SETFL, O_NONBLOCK);

    int trueVal = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(int));

    if (res_addr != nullptr) // TODO: check performance
      *res_addr = *ptr;
    if (!should_bind)
      return sfd;

    if (bind(sfd, ptr->ai_addr, ptr->ai_addrlen) == 0)
      return sfd;

    close(sfd);
  }
  return -1;
}

int create_dgram_socket(const char *address, const char *port, addrinfo *res_addr)
{
  addrinfo hints;
  memset(&hints, 0, sizeof(addrinfo));

  bool isListener = address == nullptr; // TODO: check performance

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (isListener)
    hints.ai_flags = AI_PASSIVE;

  addrinfo *result = nullptr;
  if (getaddrinfo(address, port, &hints, &result) != 0)
    return -1;

  int sfd = get_dgram_socket(result, isListener, res_addr);

  //freeaddrinfo(result);
  return sfd;
}

void receive_messages(int sfd)
{
  char buffer[1500];
  sockaddr_in fromAddr;
  socklen_t addrLen = sizeof(fromAddr);

  int bytesRead = recvfrom(sfd, buffer, sizeof(buffer), 0, 
                          reinterpret_cast<sockaddr*>(&fromAddr), &addrLen);
  if (bytesRead > 0) {
    buffer[bytesRead] = '\0';
    printf("Received: %s\n", buffer);
  }
}

Socket::Socket() = default;

Socket::~Socket()
{
  if (socketFd != -1) {
    close(socketFd);
  }
}

int Socket::bind(const char* address, const char* port)
{
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = (address != nullptr) ? 0 : AI_PASSIVE; // TODO: check performance

  addrinfo* result = nullptr;
  if (getaddrinfo(address, port, &hints, &result) != 0) {
    return -1;
  }

  socketFd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socketFd == -1) {
    freeaddrinfo(result);
    return -1;
  }

  fcntl(socketFd, F_SETFL, O_NONBLOCK);
  int trueVal = 1;
  setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &trueVal, sizeof(int));

  if (::bind(socketFd, result->ai_addr, result->ai_addrlen) == -1) {
    close(socketFd);
    socketFd = -1;
    freeaddrinfo(result);
    return -1;
  }

  freeaddrinfo(result);
  return 0;
}

int Socket::sendTo(const void* data, size_t length, const sockaddr_in& dest)
{
  if (socketFd == -1) {
    socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd == -1) return -1;
    fcntl(socketFd, F_SETFL, O_NONBLOCK);
  }

  return sendto(socketFd, data, length, 0,
                reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
}

void Socket::setEventHandler(EventHandler* handler)
{
  eventHandler = handler;
}

void Socket::pollReceive()
{
  if ((eventHandler == nullptr) || socketFd == -1) return; // TODO: check performance

  RecvData recvData{};
  socklen_t addrLen = sizeof(recvData.fromAddr);

  int bytesRead = recvfrom(socketFd, recvData.data, sizeof(recvData.data), 0,
                          reinterpret_cast<sockaddr*>(&recvData.fromAddr), &addrLen);

  if (bytesRead > 0)
  {
    recvData.bytesRead = bytesRead;
    recvData.timeReceived = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
    eventHandler->onDataReceived(recvData);
  }
}

uint16_t Socket::getLocalPort() const
{
  if (socketFd == -1) return 0;

  sockaddr_in addr{};
  socklen_t len = sizeof(addr);
  if (getsockname(socketFd, (sockaddr*)&addr, &len) == 0) {
    return ntohs(addr.sin_port);
  }
  return 0;
}

bool Socket::isPortInUse(const char* address, const char* port)
{
  Socket testSocket;
  return testSocket.bind(address, port) != 0;
}

std::vector<std::string> Socket::getLocalIPs()
{
  std::vector<std::string> ips;
  ifaddrs* ifap = nullptr;

  if (getifaddrs(&ifap) == 0)
  {
    for (ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
    {
      if ((ifa->ifa_addr != nullptr) && ifa->ifa_addr->sa_family == AF_INET) // TODO: check performance
      {
        sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, INET_ADDRSTRLEN);
        ips.emplace_back(ip);
      }
    }
    freeifaddrs(ifap);
  }

  return ips;
}

} // namespace socketwire