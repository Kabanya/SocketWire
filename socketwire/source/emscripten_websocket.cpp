#include "i_socket.hpp"

#if defined(__EMSCRIPTEN__)
#include <emscripten/websocket.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <vector>
#endif

namespace socketwire {

#if defined(__EMSCRIPTEN__)
namespace {

constexpr std::uint16_t kSyntheticPeerPort = 0;
constexpr unsigned short kWebSocketOpen = 1;
constexpr unsigned short kWebSocketClosing = 2;

[[nodiscard]] SocketAddress SyntheticPeerAddress() {
  return SocketAddress::FromIPv4(0);
}

[[nodiscard]] bool IsSuccess(EMSCRIPTEN_RESULT result) {
  return result == EMSCRIPTEN_RESULT_SUCCESS;
}

[[nodiscard]] SocketError ToSocketError(EMSCRIPTEN_RESULT result) {
  return IsSuccess(result) ? SocketError::kNone : SocketError::kSystem;
}

class EmscriptenWebSocketSocket final : public ISocket {
 public:
  explicit EmscriptenWebSocketSocket(const WebSocketConfig& cfg)
      : config_(cfg) {}

  ~EmscriptenWebSocketSocket() override { Close(); }

  EmscriptenWebSocketSocket(const EmscriptenWebSocketSocket&) = delete;
  EmscriptenWebSocketSocket& operator=(const EmscriptenWebSocketSocket&) =
    delete;

  [[nodiscard]] bool Open() {
    if (socket_ > 0) return true;
    if (config_.url.empty() || !emscripten_websocket_is_supported()) {
      last_error_ = SocketError::kUnsupported;
      return false;
    }

    EmscriptenWebSocketCreateAttributes attrs;
    emscripten_websocket_init_create_attributes(&attrs);
    attrs.url = config_.url.c_str();
    attrs.protocols =
      config_.protocols.empty() ? nullptr : config_.protocols.c_str();
    attrs.createOnMainThread = config_.createOnMainThread;

    socket_ = emscripten_websocket_new(&attrs);
    if (socket_ <= 0) {
      socket_ = 0;
      last_error_ = SocketError::kSystem;
      return false;
    }

    (void)emscripten_websocket_set_onopen_callback(socket_, this, OnOpen);
    (void)emscripten_websocket_set_onmessage_callback(socket_, this, OnMessage);
    (void)emscripten_websocket_set_onerror_callback(socket_, this, OnError);
    (void)emscripten_websocket_set_onclose_callback(socket_, this, OnClose);
    return true;
  }

  SocketError Bind(const SocketAddress& address, std::uint16_t port) override {
    (void)address;
    (void)port;
    return socket_ > 0 ? SocketError::kNone : last_error_;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override {
    (void)to_addr;
    (void)to_port;

    if (data == nullptr || length == 0) {
      return {.bytes = -1, .error = SocketError::kInvalidParam};
    }
    if (length > config_.maxMessageSize ||
        length > std::numeric_limits<std::uint32_t>::max()) {
      return {.bytes = -1, .error = SocketError::kInvalidParam};
    }
    if (socket_ <= 0) return {.bytes = -1, .error = last_error_};
    if (closed_) return {.bytes = -1, .error = SocketError::kClosed};

    if (IsOpen()) {
      FlushQueuedSends();
      const SocketError err =
        SendBinary(static_cast<const std::uint8_t*>(data), length);
      if (err != SocketError::kNone) return {.bytes = -1, .error = err};
      return {.bytes = static_cast<std::ptrdiff_t>(length),
              .error = SocketError::kNone};
    }

    if (outgoing_.size() >= config_.maxQueuedMessages) {
      return {.bytes = -1, .error = SocketError::kWouldBlock};
    }

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    outgoing_.emplace_back(bytes, bytes + length);
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override {
    if (buffer == nullptr || capacity == 0) {
      return {.bytes = -1, .error = SocketError::kInvalidParam};
    }
    if (incoming_.empty()) {
      if (closed_) return {.bytes = -1, .error = SocketError::kClosed};
      if (last_error_ != SocketError::kNone) {
        return {.bytes = -1, .error = last_error_};
      }
      return {.bytes = -1, .error = SocketError::kWouldBlock};
    }

    const auto& message = incoming_.front();
    const std::size_t bytes_to_copy = std::min(capacity, message.size());
    std::memcpy(buffer, message.data(), bytes_to_copy);
    incoming_.pop_front();

    from_addr = SyntheticPeerAddress();
    from_port = kSyntheticPeerPort;
    return {.bytes = static_cast<std::ptrdiff_t>(bytes_to_copy),
            .error = SocketError::kNone};
  }

  SocketError SetBlocking(bool enable) override {
    return enable ? SocketError::kUnsupported : SocketError::kNone;
  }

  [[nodiscard]] bool IsBlocking() const override { return false; }
  [[nodiscard]] std::uint16_t LocalPort() const override { return 0; }
  [[nodiscard]] int NativeHandle() const override { return -1; }

  void Close() override {
    incoming_.clear();
    outgoing_.clear();
    open_ = false;
    closed_ = true;

    if (socket_ <= 0) return;

    (void)emscripten_websocket_set_onopen_callback(socket_, nullptr, nullptr);
    (void)emscripten_websocket_set_onmessage_callback(socket_, nullptr,
                                                      nullptr);
    (void)emscripten_websocket_set_onerror_callback(socket_, nullptr, nullptr);
    (void)emscripten_websocket_set_onclose_callback(socket_, nullptr, nullptr);
    (void)emscripten_websocket_close(socket_, 1000, "SocketWire close");
    (void)emscripten_websocket_delete(socket_);
    socket_ = 0;
  }

 private:
  [[nodiscard]] bool IsOpen() {
    if (socket_ <= 0) return false;

    unsigned short state = 0;
    const EMSCRIPTEN_RESULT result =
      emscripten_websocket_get_ready_state(socket_, &state);
    if (!IsSuccess(result)) {
      last_error_ = ToSocketError(result);
      return false;
    }

    open_ = state == kWebSocketOpen;
    if (state >= kWebSocketClosing) closed_ = true;
    return open_;
  }

  SocketError SendBinary(const std::uint8_t* data, std::size_t length) {
    const EMSCRIPTEN_RESULT result =
      emscripten_websocket_send_binary(socket_, const_cast<std::uint8_t*>(data),
                                       static_cast<std::uint32_t>(length));
    const SocketError err = ToSocketError(result);
    if (err != SocketError::kNone) last_error_ = err;
    return err;
  }

  void FlushQueuedSends() {
    while (IsOpen() && !outgoing_.empty()) {
      const auto& message = outgoing_.front();
      if (SendBinary(message.data(), message.size()) != SocketError::kNone) {
        break;
      }
      outgoing_.pop_front();
    }
  }

  static bool OnOpen(int event_type, const EmscriptenWebSocketOpenEvent* event,
                     void* user_data) {
    (void)event_type;
    (void)event;
    auto* self = static_cast<EmscriptenWebSocketSocket*>(user_data);
    if (self == nullptr) return true;
    self->open_ = true;
    self->closed_ = false;
    self->last_error_ = SocketError::kNone;
    self->FlushQueuedSends();
    return true;
  }

  static bool OnMessage(int event_type,
                        const EmscriptenWebSocketMessageEvent* event,
                        void* user_data) {
    (void)event_type;
    auto* self = static_cast<EmscriptenWebSocketSocket*>(user_data);
    if (self == nullptr || event == nullptr || event->isText) return true;
    if (event->data == nullptr || event->numBytes == 0) return true;
    if (event->numBytes > self->config_.maxMessageSize) {
      self->last_error_ = SocketError::kInvalidParam;
      return true;
    }

    self->incoming_.emplace_back(event->data, event->data + event->numBytes);
    return true;
  }

  static bool OnError(int event_type,
                      const EmscriptenWebSocketErrorEvent* event,
                      void* user_data) {
    (void)event_type;
    (void)event;
    auto* self = static_cast<EmscriptenWebSocketSocket*>(user_data);
    if (self == nullptr) return true;
    self->last_error_ = SocketError::kSystem;
    return true;
  }

  static bool OnClose(int event_type,
                      const EmscriptenWebSocketCloseEvent* event,
                      void* user_data) {
    (void)event_type;
    (void)event;
    auto* self = static_cast<EmscriptenWebSocketSocket*>(user_data);
    if (self == nullptr) return true;
    self->open_ = false;
    self->closed_ = true;
    return true;
  }

  WebSocketConfig config_;
  EMSCRIPTEN_WEBSOCKET_T socket_ = 0;
  std::deque<std::vector<std::uint8_t>> incoming_;
  std::deque<std::vector<std::uint8_t>> outgoing_;
  SocketError last_error_ = SocketError::kNone;
  bool open_ = false;
  bool closed_ = false;
};

class EmscriptenSocketFactory final : public ISocketFactory {
 public:
  std::unique_ptr<ISocket> CreateUdpSocket(
    [[maybe_unused]] const SocketConfig& cfg) override {
    return nullptr;
  }
};

}  // namespace

void RegisterEmscriptenSocketFactory() {
  static EmscriptenSocketFactory factory;
  SocketFactoryRegistry::SetFactory(&factory);
}

std::unique_ptr<ISocket> CreateEmscriptenWebSocketClient(
  const WebSocketConfig& cfg) {
  auto socket = std::make_unique<EmscriptenWebSocketSocket>(cfg);
  if (!socket->Open()) return nullptr;
  return socket;
}
#else
void RegisterEmscriptenSocketFactory() {}

std::unique_ptr<ISocket> CreateEmscriptenWebSocketClient(
  [[maybe_unused]] const WebSocketConfig& cfg) {
  return nullptr;
}
#endif

}  // namespace socketwire
