#pragma once

#include <array>
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <limits>
#include <optional>
#include <queue>
#include <span>
#include <unordered_map>
#include <vector>

namespace socketwire::detail {

enum class PacketType : std::uint8_t {
  kUnreliable = 0,
  kReliable = 1,
  kUnsequenced = 2,
  kConnect = 3,
  kAccept = 4,
  kDisconnect = 5,
  kPing = 6,
  kPong = 7,
  kAck = 8,
  kFragment = 9,
  kBatch = 10
};

enum class PacketDecodeError : std::uint8_t {
  kTooSmall,
  kBadMagic,
  kUnsupportedVersion,
  kUnknownType,
  kUnknownFlags,
  kTruncated,
  kInvalidLength,
  kInvalidExtension,
  kInvalidBatch
};

enum class PacketEncodeError : std::uint8_t {
  kInvalidPayload,
  kPacketTooLarge,
  kUnsupportedPayload
};

struct DeadlineMetadata {
  bool hasDeadline = false;
  std::uint32_t deadline_ms = 0;
  std::chrono::steady_clock::time_point createdTime;
  std::chrono::steady_clock::time_point expireTime;
};

struct FragmentMetadata {
  bool hasFragment = false;
  std::uint16_t groupId = 0;
  std::uint16_t fragmentIndex = 0;
  std::uint16_t fragmentTotal = 0;
};

struct DecodedPacket {
  PacketType type = PacketType::kUnreliable;
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;
  bool hasDeadline = false;
  std::uint32_t deadline_ms = 0;
  std::uint32_t ageMsAtSend = 0;
  FragmentMetadata fragment{};
  std::span<const std::uint8_t> payload{};
};

struct PacketBuild {
  PacketType type = PacketType::kUnreliable;
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;
  DeadlineMetadata deadline{};
  FragmentMetadata fragment{};
  std::span<const std::uint8_t> payload{};
};

struct PacketKey {
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;

  [[nodiscard]] bool operator==(const PacketKey& other) const = default;
};

struct PacketKeyHash {
  [[nodiscard]] std::size_t operator()(const PacketKey& key) const noexcept;
};

class PacketCodec {
 public:
  static constexpr std::array<std::uint8_t, 2> kMagic = {0x53, 0x57};
  static constexpr std::uint8_t kVersion = 2;
  static constexpr std::size_t kBaseHeaderSize = 12;
  static constexpr std::size_t kDeadlineExtensionSize = 8;
  static constexpr std::size_t kFragmentExtensionSize = 6;

  [[nodiscard]] static std::expected<std::size_t, PacketEncodeError> Encode(
    const PacketBuild& packet, std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> out);

  [[nodiscard]] static std::expected<std::size_t, PacketEncodeError>
  EncodeHeader(const PacketBuild& packet, std::size_t payload_size,
               std::chrono::steady_clock::time_point now,
               std::span<std::uint8_t> out);

  [[nodiscard]] static std::expected<DecodedPacket, PacketDecodeError> Decode(
    std::span<const std::uint8_t> bytes);

  [[nodiscard]] static std::expected<std::vector<std::span<const std::uint8_t>>,
                                     PacketDecodeError>
  DecodeBatchPayload(std::span<const std::uint8_t> payload,
                     std::uint16_t max_commands);

  [[nodiscard]] static std::expected<std::vector<std::uint8_t>,
                                     PacketEncodeError>
  EncodeBatchPayload(std::span<const std::span<const std::uint8_t>> commands,
                     std::uint16_t max_commands);

  [[nodiscard]] static std::size_t HeaderSize(const PacketBuild& packet);
  [[nodiscard]] static const char* ToString(PacketDecodeError error) noexcept;

 private:
  static constexpr std::uint8_t kFlagDeadline = 0x01;
  static constexpr std::uint8_t kFlagFragment = 0x02;
  static constexpr std::uint8_t kKnownFlags = kFlagDeadline | kFlagFragment;
};

class PayloadBuffer {
 public:
  static constexpr std::size_t kInlineCapacity = 256;

  [[nodiscard]] bool Empty() const noexcept { return size_ == 0; }
  [[nodiscard]] std::size_t Size() const noexcept { return size_; }

  [[nodiscard]] std::uint8_t* Data() noexcept {
    return using_heap_ ? heap_.data() : inline_.data();
  }
  [[nodiscard]] const std::uint8_t* Data() const noexcept {
    return using_heap_ ? heap_.data() : inline_.data();
  }

  void Clear() noexcept {
    size_ = 0;
    using_heap_ = false;
    heap_.clear();
  }

  void Resize(std::size_t size) {
    size_ = size;
    if (size > kInlineCapacity) {
      using_heap_ = true;
      heap_.resize(size);
      return;
    }
    using_heap_ = false;
    heap_.clear();
  }

  void Assign(const std::uint8_t* src, std::size_t size) {
    Resize(size);
    if (size > 0 && src != nullptr) {
      std::memcpy(Data(), src, size);
    }
  }

  void Assign(std::span<const std::uint8_t> data) {
    Assign(data.data(), data.size());
  }

 private:
  std::array<std::uint8_t, kInlineCapacity> inline_{};
  std::vector<std::uint8_t> heap_;
  std::size_t size_ = 0;
  bool using_heap_ = false;
};

struct PendingPacket {
  std::uint32_t sequence = 0;
  PayloadBuffer data;
  std::chrono::steady_clock::time_point sendTime;
  std::uint32_t retries = 0;
  std::uint8_t channel = 0;
  PacketType type = PacketType::kReliable;
  std::chrono::steady_clock::time_point createdTime;
  std::uint32_t deadline_ms = 0;
  std::chrono::steady_clock::time_point expireTime;
  bool hasDeadline = false;
  FragmentMetadata fragment{};
};

class SendQueue {
 public:
  struct PendingHandle {
    std::size_t index = std::numeric_limits<std::size_t>::max();
    std::uint32_t generation = 0;
  };

  void Configure(std::uint32_t max_pending_packets);
  [[nodiscard]] bool CanAllocate() const;
  [[nodiscard]] std::uint32_t ActiveCount() const { return active_count_; }
  [[nodiscard]] std::expected<PendingHandle, bool> Allocate(
    std::uint8_t channel, std::uint32_t sequence);
  void ScheduleRetry(PendingHandle handle,
                     std::chrono::steady_clock::time_point now,
                     std::uint32_t retry_timeout_ms);
  [[nodiscard]] std::optional<PendingHandle> PopDue(
    std::chrono::steady_clock::time_point now);
  void Erase(PendingHandle handle);
  void Clear();
  [[nodiscard]] PendingPacket* Get(PendingHandle handle);
  [[nodiscard]] const PendingPacket* Get(PendingHandle handle) const;
  [[nodiscard]] PendingHandle Find(std::uint8_t channel,
                                   std::uint32_t sequence) const;
  [[nodiscard]] bool IsValid(PendingHandle handle) const;

 private:
  struct PendingSlot {
    PendingPacket packet;
    std::uint32_t generation = 0;
    bool active = false;
  };
  struct RetryEntry {
    std::chrono::steady_clock::time_point dueTime{};
    PendingHandle handle;
    std::uint32_t retryGeneration = 0;

    [[nodiscard]] bool operator>(const RetryEntry& other) const {
      return dueTime > other.dueTime;
    }
  };

  void ResetPendingPacketForReuse(PendingPacket& pending, std::uint8_t channel,
                                  std::uint32_t sequence);

  std::uint32_t max_pending_packets_ = 4096;
  std::vector<PendingSlot> slots_;
  std::vector<std::size_t> free_slots_;
  std::unordered_map<PacketKey, PendingHandle, PacketKeyHash> by_packet_;
  std::unordered_map<PacketKey, std::uint32_t, PacketKeyHash> packet_counts_;
  std::priority_queue<RetryEntry, std::vector<RetryEntry>, std::greater<>>
    retry_heap_;
  std::uint32_t active_count_ = 0;
};

class AckBatcher {
 public:
  void Configure(bool enabled, std::uint16_t max_commands);
  [[nodiscard]] bool Enabled() const { return enabled_; }
  [[nodiscard]] bool Empty() const { return queued_.empty(); }
  [[nodiscard]] std::size_t Size() const { return queued_.size(); }
  [[nodiscard]] std::uint16_t MaxCommands() const { return max_commands_; }
  [[nodiscard]] std::span<const PacketKey> Queued() const { return queued_; }
  void Add(std::uint8_t channel, std::uint32_t sequence);
  void RemovePrefix(std::size_t count);
  void Clear();
  [[nodiscard]] bool ShouldFlush() const {
    return queued_.size() >= max_commands_;
  }

 private:
  bool enabled_ = true;
  std::uint16_t max_commands_ = 32;
  std::vector<PacketKey> queued_;
};

class CongestionController {
 public:
  void Configure(std::uint32_t max_window);
  [[nodiscard]] bool CanSend(std::uint32_t inflight) const;
  [[nodiscard]] std::uint32_t Window() const { return current_window_; }
  void OnAck();
  void OnLoss();

 private:
  std::uint32_t max_window_ = 0;
  std::uint32_t current_window_ = 0;
  std::uint32_t ssthresh_ = 32;
};

class ReceiveSequencer {
 public:
  struct Message {
    std::uint32_t sequence = 0;
    std::uint8_t channel = 0;
    PayloadBuffer data;
  };

  enum class AcceptStatus : std::uint8_t {
    kDelivered,
    kQueued,
    kDuplicate,
    kDropped
  };

  struct AcceptResult {
    AcceptStatus status = AcceptStatus::kDropped;
    bool ack = false;
  };

  void Configure(std::uint8_t num_channels, std::uint32_t receive_window_size);
  void Reset();
  [[nodiscard]] bool ValidChannel(std::uint8_t channel) const;
  [[nodiscard]] AcceptResult AcceptReliable(
    std::uint8_t channel, std::uint32_t sequence,
    std::span<const std::uint8_t> payload, std::vector<Message>& ready);
  [[nodiscard]] AcceptResult AcceptUnsequenced(std::uint8_t channel,
                                               std::uint32_t sequence);

 private:
  struct ReceivedSlot {
    Message packet;
    bool occupied = false;
  };

  static constexpr std::uint32_t kSeqWindowSize = 1024;

  [[nodiscard]] bool IsDuplicateSequence(std::uint8_t channel,
                                         std::uint32_t sequence) const;
  void MarkSequenceReceived(std::uint8_t channel, std::uint32_t sequence);
  void DrainReady(std::uint8_t channel, std::vector<Message>& ready);
  [[nodiscard]] static bool IsSequenceNewer(std::uint32_t s1, std::uint32_t s2);

  std::vector<std::uint32_t> receive_sequence_;
  std::vector<std::uint32_t> seq_window_high_;
  std::vector<std::bitset<kSeqWindowSize>> seq_window_bits_;
  std::vector<std::vector<ReceivedSlot>> pending_;
};

class FragmentReassembler {
 public:
  struct CompleteMessage {
    std::uint8_t channel = 0;
    std::vector<std::uint8_t> payload;
  };

  enum class AddStatus : std::uint8_t {
    kAccepted,
    kCompleted,
    kDuplicate,
    kDropped
  };

  struct AddResult {
    AddStatus status = AddStatus::kDropped;
    std::optional<CompleteMessage> message;
    bool deadlineExpired = false;
  };

  void Configure(std::uint8_t num_channels,
                 std::uint32_t max_fragment_groups_per_channel,
                 std::uint32_t max_fragments_per_message,
                 std::uint32_t max_message_size,
                 std::uint32_t fragment_timeout_ms);
  void Reset();
  [[nodiscard]] AddResult AddFragment(
    std::uint8_t channel, const FragmentMetadata& fragment,
    std::span<const std::uint8_t> payload,
    std::chrono::steady_clock::time_point now, bool has_deadline,
    std::chrono::steady_clock::time_point expire_time);
  [[nodiscard]] std::uint32_t Cleanup(
    std::chrono::steady_clock::time_point now);

 private:
  struct FragmentGroup {
    std::uint16_t total = 0;
    std::vector<std::optional<std::vector<std::uint8_t>>> pieces;
    std::uint16_t receivedCount = 0;
    std::size_t receivedBytes = 0;
    std::chrono::steady_clock::time_point firstReceived;
    std::chrono::steady_clock::time_point expireTime;
    bool hasDeadline = false;
    std::uint8_t channel = 0;
  };

  std::uint32_t max_groups_per_channel_ = 32;
  std::uint32_t max_fragments_per_message_ = 512;
  std::uint32_t max_message_size_ = 64 * 1024;
  std::uint32_t fragment_timeout_ms_ = 5000;
  std::vector<std::unordered_map<std::uint16_t, FragmentGroup>> groups_;
};

}  // namespace socketwire::detail
