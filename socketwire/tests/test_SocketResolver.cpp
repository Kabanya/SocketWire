#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <string>
#include <utility>

#include "socket_constants.hpp"
#include "socket_resolver.hpp"
#include "thread_pool.hpp"

using namespace socketwire;  // NOLINT

namespace {

TEST(SocketResolverTest, ParsesNumericAddressesAndIpv6Scope) {
  const auto ipv4 = socket_constants::TryFromString("127.0.0.1");
  ASSERT_TRUE(ipv4.has_value());
  EXPECT_FALSE(ipv4->isIPv6);
  EXPECT_EQ(ipv4->ipv4.hostOrderAddress, 0x7F000001u);

  const auto ipv6 = socket_constants::TryFromString("::1");
  ASSERT_TRUE(ipv6.has_value());
  EXPECT_TRUE(ipv6->isIPv6);
  EXPECT_EQ(ipv6->ipv6.scopeId, 0u);

  const auto scoped = socket_constants::TryFromString("fe80::1%4");
  ASSERT_TRUE(scoped.has_value());
  EXPECT_TRUE(scoped->isIPv6);
  EXPECT_EQ(scoped->ipv6.scopeId, 4u);

  EXPECT_EQ(socket_constants::FormatIPv6String(scoped->ipv6.bytes,
                                               scoped->ipv6.scopeId),
            "fe80::1%4");
}

TEST(SocketResolverTest, ResolvesIpv4Loopback) {
  const ResolveHostResult result =
    ResolveHost("127.0.0.1", 7777, AddressFamily::kIPv4);

  ASSERT_EQ(result.error, SocketError::kNone);
  ASSERT_FALSE(result.addresses.empty());
  EXPECT_FALSE(result.addresses.front().isIPv6);
  EXPECT_EQ(result.addresses.front().ipv4.hostOrderAddress, 0x7F000001u);
}

TEST(SocketResolverTest, ResolvesIpv6LoopbackWhenAvailable) {
  const ResolveHostResult result =
    ResolveHost("::1", 7777, AddressFamily::kIPv6);

  if (result.Failed()) {
    GTEST_SKIP() << "IPv6 loopback resolution is unavailable on this system";
  }

  ASSERT_FALSE(result.addresses.empty());
  EXPECT_TRUE(result.addresses.front().isIPv6);
}

TEST(SocketResolverTest, RejectsMalformedHostInput) {
  const std::string malformed("bad\0host", 8);
  const ResolveHostResult result =
    ResolveHost(std::string_view(malformed.data(), malformed.size()), 7777);

  EXPECT_EQ(result.error, SocketError::kInvalidParam);
  EXPECT_TRUE(result.addresses.empty());
}

TEST(SocketResolverTest, ResolvesAsyncOnThreadPool) {
  const ResolveHostResult sync =
    ResolveHost("127.0.0.1", 7777, AddressFamily::kIPv4);
  ASSERT_EQ(sync.error, SocketError::kNone);

  ThreadPool pool(1);
  pool.Start();

  std::promise<ResolveHostResult> promise;
  auto future = promise.get_future();

  ASSERT_TRUE(ResolveHostAsync(
    pool, "127.0.0.1", 7777, AddressFamily::kIPv4,
    [&promise](ResolveHostResult result) { promise.set_value(std::move(result)); }));

  ASSERT_EQ(future.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  const ResolveHostResult async = future.get();
  pool.Stop();

  EXPECT_EQ(async.error, sync.error);
  ASSERT_EQ(async.addresses.size(), sync.addresses.size());
  EXPECT_EQ(async.addresses.front(), sync.addresses.front());
}

TEST(SocketResolverTest, ListsNetworkInterfacesWhenSupported) {
  const ListNetworkInterfacesResult result = ListNetworkInterfaces();

  if (result.error == SocketError::kUnsupported) {
    GTEST_SKIP() << "Interface listing is unsupported on this platform";
  }

  ASSERT_EQ(result.error, SocketError::kNone);
  EXPECT_FALSE(result.interfaces.empty());

  for (const NetworkInterface& iface : result.interfaces) {
    EXPECT_FALSE(iface.name.empty());
    EXPECT_FALSE(iface.addresses.empty());

    for (const SocketAddress& address : iface.addresses) {
      const std::string formatted =
        address.isIPv6
          ? socket_constants::FormatIPv6String(address.ipv6.bytes,
                                               address.ipv6.scopeId)
          : socket_constants::FormatIPv4String(address.ipv4.hostOrderAddress);
      EXPECT_FALSE(formatted.empty());
    }
  }
}

}  // namespace
