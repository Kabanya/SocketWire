#include "reliable_protocol.hpp"

#include <algorithm>
#include <utility>

namespace socketwire::detail {
namespace {

constexpr std::uint8_t kMaxPacketType =
  static_cast<std::uint8_t>(PacketType::kBatch);

void WriteU16(std::uint8_t* dst, std::uint16_t value) {
  dst[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  dst[1] = static_cast<std::uint8_t>(value & 0xFFu);
}

void WriteU32(std::uint8_t* dst, std::uint32_t value) {
  dst[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  dst[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  dst[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  dst[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

std::uint16_t ReadU16(const std::uint8_t* src) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[0]) << 8) |
                                    static_cast<std::uint16_t>(src[1]));
}

std::uint32_t ReadU32(const std::uint8_t* src) {
  return (static_cast<std::uint32_t>(src[0]) << 24) |
         (static_cast<std::uint32_t>(src[1]) << 16) |
         (static_cast<std::uint32_t>(src[2]) << 8) |
         static_cast<std::uint32_t>(src[3]);
}

std::uint32_t DeadlineAgeMs(std::chrono::steady_clock::time_point created_time,
                            std::chrono::steady_clock::time_point now) {
  const auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(now - created_time)
      .count();
  if (elapsed <= 0) return 0;
  if (std::cmp_greater(elapsed, std::numeric_limits<std::uint32_t>::max())) {
    return std::numeric_limits<std::uint32_t>::max();
  }
  return static_cast<std::uint32_t>(elapsed);
}

}  // namespace

std::size_t PacketCodec::HeaderSize(const PacketBuild& packet) {
  return kBaseHeaderSize +
         (packet.deadline.hasDeadline ? kDeadlineExtensionSize
                                      : std::size_t{0}) +
         (packet.fragment.hasFragment ? kFragmentExtensionSize
                                      : std::size_t{0});
}

std::expected<std::size_t, PacketEncodeError> PacketCodec::Encode(
  const PacketBuild& packet, std::chrono::steady_clock::time_point now,
  std::span<std::uint8_t> out) {
  if (packet.payload.size() > std::numeric_limits<std::uint16_t>::max()) {
    return std::unexpected(PacketEncodeError::kUnsupportedPayload);
  }
  if (packet.payload.size() > 0 && packet.payload.data() == nullptr) {
    return std::unexpected(PacketEncodeError::kInvalidPayload);
  }
  if (packet.fragment.hasFragment &&
      (packet.type != PacketType::kFragment ||
       packet.fragment.fragmentTotal == 0 ||
       packet.fragment.fragmentIndex >= packet.fragment.fragmentTotal)) {
    return std::unexpected(PacketEncodeError::kInvalidPayload);
  }

  const std::size_t header_size = HeaderSize(packet);
  const std::size_t total_size = header_size + packet.payload.size();
  if (out.size() < total_size) {
    return std::unexpected(PacketEncodeError::kPacketTooLarge);
  }

  const auto header_result =
    EncodeHeader(packet, packet.payload.size(), now, out);
  if (!header_result.has_value()) return std::unexpected(header_result.error());
  const std::size_t offset = *header_result;
  if (!packet.payload.empty()) {
    std::memcpy(out.data() + offset, packet.payload.data(),
                packet.payload.size());
  }
  return total_size;
}

std::expected<std::size_t, PacketEncodeError> PacketCodec::EncodeHeader(
  const PacketBuild& packet, std::size_t payload_size,
  std::chrono::steady_clock::time_point now, std::span<std::uint8_t> out) {
  if (payload_size > std::numeric_limits<std::uint16_t>::max()) {
    return std::unexpected(PacketEncodeError::kUnsupportedPayload);
  }
  if (packet.fragment.hasFragment &&
      (packet.type != PacketType::kFragment ||
       packet.fragment.fragmentTotal == 0 ||
       packet.fragment.fragmentIndex >= packet.fragment.fragmentTotal)) {
    return std::unexpected(PacketEncodeError::kInvalidPayload);
  }

  const std::size_t header_size = HeaderSize(packet);
  if (out.size() < header_size) {
    return std::unexpected(PacketEncodeError::kPacketTooLarge);
  }

  std::uint8_t flags = 0;
  if (packet.deadline.hasDeadline) flags |= kFlagDeadline;
  if (packet.fragment.hasFragment) flags |= kFlagFragment;

  out.data()[0] = kMagic.at(0);
  out.data()[1] = kMagic.at(1);
  out.data()[2] = kVersion;
  out.data()[3] = static_cast<std::uint8_t>(packet.type);
  out.data()[4] = packet.channel;
  out.data()[5] = flags;
  WriteU32(out.data() + 6, packet.sequence);
  WriteU16(out.data() + 10, static_cast<std::uint16_t>(payload_size));

  std::size_t offset = kBaseHeaderSize;
  if (packet.deadline.hasDeadline) {
    WriteU32(out.data() + offset, packet.deadline.deadline_ms);
    WriteU32(out.data() + offset + 4,
             DeadlineAgeMs(packet.deadline.createdTime, now));
    offset += kDeadlineExtensionSize;
  }
  if (packet.fragment.hasFragment) {
    WriteU16(out.data() + offset, packet.fragment.groupId);
    WriteU16(out.data() + offset + 2, packet.fragment.fragmentIndex);
    WriteU16(out.data() + offset + 4, packet.fragment.fragmentTotal);
    offset += kFragmentExtensionSize;
  }
  return offset;
}

std::expected<DecodedPacket, PacketDecodeError> PacketCodec::Decode(
  std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kBaseHeaderSize) {
    return std::unexpected(PacketDecodeError::kTooSmall);
  }
  if (bytes.data()[0] != kMagic.at(0) || bytes.data()[1] != kMagic.at(1)) {
    return std::unexpected(PacketDecodeError::kBadMagic);
  }
  if (bytes.data()[2] != kVersion) {
    return std::unexpected(PacketDecodeError::kUnsupportedVersion);
  }
  if (bytes.data()[3] > kMaxPacketType) {
    return std::unexpected(PacketDecodeError::kUnknownType);
  }
  const std::uint8_t flags = bytes.data()[5];
  if ((flags & ~kKnownFlags) != 0) {
    return std::unexpected(PacketDecodeError::kUnknownFlags);
  }

  DecodedPacket packet;
  packet.type = static_cast<PacketType>(bytes.data()[3]);
  packet.channel = bytes.data()[4];
  packet.sequence = ReadU32(bytes.data() + 6);
  const std::size_t payload_size = ReadU16(bytes.data() + 10);

  std::size_t offset = kBaseHeaderSize;
  if ((flags & kFlagDeadline) != 0) {
    if (bytes.size() < offset + kDeadlineExtensionSize) {
      return std::unexpected(PacketDecodeError::kTruncated);
    }
    packet.hasDeadline = true;
    packet.deadline_ms = ReadU32(bytes.data() + offset);
    packet.ageMsAtSend = ReadU32(bytes.data() + offset + 4);
    offset += kDeadlineExtensionSize;
  }
  if ((flags & kFlagFragment) != 0) {
    if (packet.type != PacketType::kFragment) {
      return std::unexpected(PacketDecodeError::kInvalidExtension);
    }
    if (bytes.size() < offset + kFragmentExtensionSize) {
      return std::unexpected(PacketDecodeError::kTruncated);
    }
    packet.fragment.hasFragment = true;
    packet.fragment.groupId = ReadU16(bytes.data() + offset);
    packet.fragment.fragmentIndex = ReadU16(bytes.data() + offset + 2);
    packet.fragment.fragmentTotal = ReadU16(bytes.data() + offset + 4);
    if (packet.fragment.fragmentTotal == 0 ||
        packet.fragment.fragmentIndex >= packet.fragment.fragmentTotal) {
      return std::unexpected(PacketDecodeError::kInvalidExtension);
    }
    offset += kFragmentExtensionSize;
  }

  if (bytes.size() != offset + payload_size) {
    return std::unexpected(PacketDecodeError::kInvalidLength);
  }

  packet.payload = bytes.subspan(offset, payload_size);
  return packet;
}

std::expected<std::vector<std::span<const std::uint8_t>>, PacketDecodeError>
PacketCodec::DecodeBatchPayload(std::span<const std::uint8_t> payload,
                                std::uint16_t max_commands) {
  if (payload.size() < sizeof(std::uint16_t)) {
    return std::unexpected(PacketDecodeError::kInvalidBatch);
  }
  const std::uint16_t command_count = ReadU16(payload.data());
  if (command_count == 0 || command_count > max_commands) {
    return std::unexpected(PacketDecodeError::kInvalidBatch);
  }

  std::vector<std::span<const std::uint8_t>> commands;
  commands.reserve(command_count);

  std::size_t offset = sizeof(std::uint16_t);
  for (std::uint16_t i = 0; i < command_count; ++i) {
    if (offset + sizeof(std::uint16_t) > payload.size()) {
      return std::unexpected(PacketDecodeError::kTruncated);
    }
    const std::uint16_t command_size = ReadU16(payload.data() + offset);
    offset += sizeof(std::uint16_t);
    if (command_size < kBaseHeaderSize ||
        offset + command_size > payload.size()) {
      return std::unexpected(PacketDecodeError::kInvalidBatch);
    }
    commands.push_back(payload.subspan(offset, command_size));
    offset += command_size;
  }
  if (offset != payload.size()) {
    return std::unexpected(PacketDecodeError::kInvalidBatch);
  }
  return commands;
}

std::expected<std::vector<std::uint8_t>, PacketEncodeError>
PacketCodec::EncodeBatchPayload(
  std::span<const std::span<const std::uint8_t>> commands,
  std::uint16_t max_commands) {
  if (commands.empty() || commands.size() > max_commands) {
    return std::unexpected(PacketEncodeError::kInvalidPayload);
  }

  std::size_t size = sizeof(std::uint16_t);
  for (const auto command : commands) {
    if (command.size() > std::numeric_limits<std::uint16_t>::max()) {
      return std::unexpected(PacketEncodeError::kUnsupportedPayload);
    }
    size += sizeof(std::uint16_t) + command.size();
  }
  if (size > std::numeric_limits<std::uint16_t>::max()) {
    return std::unexpected(PacketEncodeError::kUnsupportedPayload);
  }

  std::vector<std::uint8_t> payload(size);
  WriteU16(payload.data(), static_cast<std::uint16_t>(commands.size()));
  std::size_t offset = sizeof(std::uint16_t);
  for (const auto command : commands) {
    WriteU16(payload.data() + offset,
             static_cast<std::uint16_t>(command.size()));
    offset += sizeof(std::uint16_t);
    if (!command.empty()) {
      std::memcpy(payload.data() + offset, command.data(), command.size());
      offset += command.size();
    }
  }
  return payload;
}

const char* PacketCodec::ToString(PacketDecodeError error) noexcept {
  switch (error) {
    case PacketDecodeError::kTooSmall:
      return "TooSmall";
    case PacketDecodeError::kBadMagic:
      return "BadMagic";
    case PacketDecodeError::kUnsupportedVersion:
      return "UnsupportedVersion";
    case PacketDecodeError::kUnknownType:
      return "UnknownType";
    case PacketDecodeError::kUnknownFlags:
      return "UnknownFlags";
    case PacketDecodeError::kTruncated:
      return "Truncated";
    case PacketDecodeError::kInvalidLength:
      return "InvalidLength";
    case PacketDecodeError::kInvalidExtension:
      return "InvalidExtension";
    case PacketDecodeError::kInvalidBatch:
      return "InvalidBatch";
    default:
      return "Unknown";
  }
}

void SendQueue::Configure(std::uint32_t max_pending_packets) {
  max_pending_packets_ = max_pending_packets;
  const std::uint32_t reserve =
    max_pending_packets_ == 0 ? 1024U : max_pending_packets_;
  slots_.reserve(reserve);
  free_slots_.reserve(reserve);
  by_sequence_.reserve(reserve);
  sequence_counts_.reserve(reserve);
}

bool SendQueue::CanAllocate() const {
  return max_pending_packets_ == 0 || active_count_ < max_pending_packets_;
}

std::expected<SendQueue::PendingHandle, bool> SendQueue::Allocate(
  std::uint32_t sequence) {
  if (!CanAllocate()) return std::unexpected(false);

  std::size_t index = 0;
  if (!free_slots_.empty()) {
    index = free_slots_.back();
    free_slots_.pop_back();
  } else {
    index = slots_.size();
    slots_.emplace_back();
  }

  PendingSlot& slot = slots_.at(index);
  slot.active = true;
  ++slot.generation;
  if (slot.generation == 0) ++slot.generation;
  ResetPendingPacketForReuse(slot.packet, sequence);

  const PendingHandle handle{index, slot.generation};
  ++active_count_;
  ++sequence_counts_[sequence];
  if (by_sequence_.find(sequence) == by_sequence_.end()) {
    by_sequence_.emplace(sequence, handle);
  }
  return handle;
}

void SendQueue::ScheduleRetry(PendingHandle handle,
                              std::chrono::steady_clock::time_point now,
                              std::uint32_t retry_timeout_ms) {
  const PendingPacket* pending = Get(handle);
  if (pending == nullptr) return;
  retry_heap_.push(RetryEntry{now + std::chrono::milliseconds(retry_timeout_ms),
                              handle, pending->retries});
}

std::optional<SendQueue::PendingHandle> SendQueue::PopDue(
  std::chrono::steady_clock::time_point now) {
  while (!retry_heap_.empty()) {
    const RetryEntry entry = retry_heap_.top();
    const PendingPacket* pending = Get(entry.handle);
    if (pending == nullptr || pending->retries != entry.retryGeneration) {
      retry_heap_.pop();
      continue;
    }
    if (now < entry.dueTime) return std::nullopt;
    retry_heap_.pop();
    return entry.handle;
  }
  return std::nullopt;
}

void SendQueue::Erase(PendingHandle handle) {
  if (!IsValid(handle)) return;

  PendingSlot& slot = slots_.at(handle.index);
  const std::uint32_t sequence = slot.packet.sequence;
  const auto indexed = by_sequence_.find(sequence);
  const bool erased_indexed = indexed != by_sequence_.end() &&
                              indexed->second.index == handle.index &&
                              indexed->second.generation == handle.generation;
  const auto count_it = sequence_counts_.find(sequence);
  const bool has_sequence_collision =
    count_it != sequence_counts_.end() && count_it->second > 1;

  slot.active = false;
  if (active_count_ > 0) --active_count_;
  if (count_it != sequence_counts_.end()) {
    if (count_it->second > 1) {
      --count_it->second;
    } else {
      sequence_counts_.erase(count_it);
    }
  }

  if (erased_indexed) {
    by_sequence_.erase(indexed);
    if (has_sequence_collision) {
      for (std::size_t index = 0; index < slots_.size(); ++index) {
        const PendingSlot& candidate = slots_.at(index);
        if (!candidate.active || (index == handle.index &&
                                  candidate.generation == handle.generation)) {
          continue;
        }
        if (candidate.packet.sequence == sequence) {
          by_sequence_.emplace(sequence,
                               PendingHandle{index, candidate.generation});
          break;
        }
      }
    }
  }

  free_slots_.push_back(handle.index);
}

void SendQueue::Clear() {
  slots_.clear();
  free_slots_.clear();
  by_sequence_.clear();
  sequence_counts_.clear();
  retry_heap_ = {};
  active_count_ = 0;
}

PendingPacket* SendQueue::Get(PendingHandle handle) {
  if (!IsValid(handle)) return nullptr;
  return &slots_.at(handle.index).packet;
}

const PendingPacket* SendQueue::Get(PendingHandle handle) const {
  if (!IsValid(handle)) return nullptr;
  return &slots_.at(handle.index).packet;
}

SendQueue::PendingHandle SendQueue::Find(std::uint32_t sequence) const {
  const auto it = by_sequence_.find(sequence);
  return it == by_sequence_.end() ? PendingHandle{} : it->second;
}

bool SendQueue::IsValid(PendingHandle handle) const {
  if (handle.index == std::numeric_limits<std::size_t>::max() ||
      handle.index >= slots_.size()) {
    return false;
  }
  const PendingSlot& slot = slots_.at(handle.index);
  return slot.active && slot.generation == handle.generation;
}

void SendQueue::ResetPendingPacketForReuse(PendingPacket& pending,
                                           std::uint32_t sequence) {
  pending.sequence = sequence;
  pending.data.Clear();
  pending.sendTime = {};
  pending.retries = 0;
  pending.channel = 0;
  pending.type = PacketType::kReliable;
  pending.createdTime = {};
  pending.deadline_ms = 0;
  pending.expireTime = {};
  pending.hasDeadline = false;
  pending.fragment = {};
}

void AckBatcher::Configure(bool enabled, std::uint16_t max_commands) {
  enabled_ = enabled;
  max_commands_ = std::clamp<std::uint16_t>(max_commands, 1, 256);
  queued_.reserve(max_commands_);
}

void AckBatcher::Add(std::uint32_t sequence) {
  if (std::ranges::find(queued_, sequence) == queued_.end()) {
    queued_.push_back(sequence);
  }
}

void AckBatcher::RemovePrefix(std::size_t count) {
  count = std::min(count, queued_.size());
  queued_.erase(queued_.begin(),
                queued_.begin() + static_cast<std::ptrdiff_t>(count));
}

void AckBatcher::Clear() { queued_.clear(); }

void CongestionController::Configure(std::uint32_t max_window) {
  max_window_ = max_window;
  current_window_ = max_window_ == 0 ? 0 : std::min(4u, max_window_);
  ssthresh_ = max_window_ > 0 ? max_window_ : 32;
}

bool CongestionController::CanSend(std::uint32_t inflight) const {
  return current_window_ == 0 || inflight < current_window_;
}

void CongestionController::OnAck() {
  if (current_window_ == 0 || max_window_ == 0) return;
  if (current_window_ < max_window_) ++current_window_;
}

void CongestionController::OnLoss() {
  if (current_window_ == 0 || max_window_ == 0) return;
  current_window_ = std::max(1u, current_window_ / 2);
  ssthresh_ = current_window_;
}

void ReceiveSequencer::Configure(std::uint8_t num_channels,
                                 std::uint32_t receive_window_size) {
  const auto n = static_cast<std::size_t>(num_channels);
  receive_sequence_.assign(n, 0);
  seq_window_high_.assign(n, 0);
  seq_window_bits_.clear();
  seq_window_bits_.resize(n);
  pending_.clear();
  pending_.resize(n);
  const std::size_t window = std::max<std::uint32_t>(1, receive_window_size);
  for (auto& channel_pending : pending_) {
    channel_pending.resize(window);
  }
}

void ReceiveSequencer::Reset() {
  for (auto& high : seq_window_high_) high = 0;
  for (auto& bits : seq_window_bits_) bits.reset();
  std::ranges::fill(receive_sequence_, 0);
  for (auto& channel_pending : pending_) {
    for (auto& slot : channel_pending) {
      slot.packet.data.Clear();
      slot.occupied = false;
    }
  }
}

bool ReceiveSequencer::ValidChannel(std::uint8_t channel) const {
  return channel < receive_sequence_.size();
}

ReceiveSequencer::AcceptResult ReceiveSequencer::AcceptReliable(
  std::uint8_t channel, std::uint32_t sequence,
  std::span<const std::uint8_t> payload, std::vector<Message>& ready) {
  if (!ValidChannel(channel)) return {.status = AcceptStatus::kDropped};
  if (IsDuplicateSequence(channel, sequence)) {
    return {.status = AcceptStatus::kDuplicate, .ack = true};
  }

  auto& expected_sequence = receive_sequence_.at(channel);
  if (sequence == expected_sequence) {
    MarkSequenceReceived(channel, sequence);
    Message message;
    message.sequence = sequence;
    message.channel = channel;
    message.data.Assign(payload);
    ready.push_back(std::move(message));
    ++expected_sequence;
    DrainReady(channel, ready);
    return {.status = AcceptStatus::kDelivered, .ack = true};
  }

  if (!IsSequenceNewer(sequence, expected_sequence)) {
    return {.status = AcceptStatus::kDropped};
  }

  auto& pending_channel = pending_.at(channel);
  const std::uint32_t distance = sequence - expected_sequence;
  if (pending_channel.empty() || distance >= pending_channel.size()) {
    return {.status = AcceptStatus::kDropped};
  }

  ReceivedSlot& slot = pending_channel.at(sequence % pending_channel.size());
  if (slot.occupied && slot.packet.sequence != sequence) {
    return {.status = AcceptStatus::kDropped};
  }

  MarkSequenceReceived(channel, sequence);
  slot.packet.sequence = sequence;
  slot.packet.channel = channel;
  slot.packet.data.Assign(payload);
  slot.occupied = true;
  return {.status = AcceptStatus::kQueued, .ack = true};
}

ReceiveSequencer::AcceptResult ReceiveSequencer::AcceptUnsequenced(
  std::uint8_t channel, std::uint32_t sequence) {
  if (!ValidChannel(channel)) return {.status = AcceptStatus::kDropped};
  if (IsDuplicateSequence(channel, sequence)) {
    return {.status = AcceptStatus::kDuplicate, .ack = true};
  }
  MarkSequenceReceived(channel, sequence);
  return {.status = AcceptStatus::kDelivered, .ack = true};
}

bool ReceiveSequencer::IsDuplicateSequence(std::uint8_t channel,
                                           std::uint32_t sequence) const {
  if (!ValidChannel(channel)) return false;
  const std::uint32_t window_base =
    seq_window_high_.at(channel) - kSeqWindowSize;
  if (IsSequenceNewer(window_base, sequence)) return true;
  if (IsSequenceNewer(sequence, seq_window_high_.at(channel))) return false;
  return seq_window_bits_.at(channel).test(sequence % kSeqWindowSize);
}

void ReceiveSequencer::MarkSequenceReceived(std::uint8_t channel,
                                            std::uint32_t sequence) {
  if (!ValidChannel(channel)) return;
  if (IsSequenceNewer(sequence, seq_window_high_.at(channel))) {
    const std::uint32_t advance = sequence + 1 - seq_window_high_.at(channel);
    if (advance >= kSeqWindowSize) {
      seq_window_bits_.at(channel).reset();
    } else {
      for (std::uint32_t i = 0; i < advance; ++i) {
        seq_window_bits_.at(channel).set(
          (seq_window_high_.at(channel) + i) % kSeqWindowSize, false);
      }
    }
    seq_window_high_.at(channel) = sequence + 1;
  }
  seq_window_bits_.at(channel).set(sequence % kSeqWindowSize);
}

void ReceiveSequencer::DrainReady(std::uint8_t channel,
                                  std::vector<Message>& ready) {
  auto& expected_sequence = receive_sequence_.at(channel);
  auto& pending_channel = pending_.at(channel);
  while (!pending_channel.empty()) {
    ReceivedSlot& slot =
      pending_channel.at(expected_sequence % pending_channel.size());
    if (!slot.occupied || slot.packet.sequence != expected_sequence) break;
    ready.push_back(std::move(slot.packet));
    slot.packet.data.Clear();
    slot.occupied = false;
    ++expected_sequence;
  }
}

bool ReceiveSequencer::IsSequenceNewer(std::uint32_t s1, std::uint32_t s2) {
  return ((s1 > s2) && (s1 - s2 <= 0x7FFFFFFF)) ||
         ((s1 < s2) && (s2 - s1 > 0x7FFFFFFF));
}

void FragmentReassembler::Configure(
  std::uint8_t num_channels, std::uint32_t max_fragment_groups_per_channel,
  std::uint32_t max_fragments_per_message, std::uint32_t max_message_size,
  std::uint32_t fragment_timeout_ms) {
  max_groups_per_channel_ = std::max(1u, max_fragment_groups_per_channel);
  max_fragments_per_message_ = std::max(1u, max_fragments_per_message);
  max_message_size_ = std::max(1u, max_message_size);
  fragment_timeout_ms_ = fragment_timeout_ms;
  groups_.clear();
  groups_.resize(num_channels);
}

void FragmentReassembler::Reset() {
  for (auto& channel_groups : groups_) channel_groups.clear();
}

FragmentReassembler::AddResult FragmentReassembler::AddFragment(
  std::uint8_t channel, const FragmentMetadata& fragment,
  std::span<const std::uint8_t> payload,
  std::chrono::steady_clock::time_point now, bool has_deadline,
  std::chrono::steady_clock::time_point expire_time) {
  if (channel >= groups_.size() || !fragment.hasFragment ||
      fragment.fragmentTotal == 0 ||
      fragment.fragmentTotal > max_fragments_per_message_ ||
      payload.size() > max_message_size_) {
    return {};
  }

  auto& channel_groups = groups_.at(channel);
  auto it = channel_groups.find(fragment.groupId);
  if (it == channel_groups.end()) {
    if (channel_groups.size() >= max_groups_per_channel_) return {};
    FragmentGroup group;
    group.total = fragment.fragmentTotal;
    group.pieces.resize(fragment.fragmentTotal);
    group.firstReceived = now;
    group.hasDeadline = has_deadline;
    group.expireTime = expire_time;
    group.channel = channel;
    it = channel_groups.emplace(fragment.groupId, std::move(group)).first;
  }

  FragmentGroup& group = it->second;
  if (group.total != fragment.fragmentTotal ||
      fragment.fragmentIndex >= group.pieces.size()) {
    return {};
  }

  if (has_deadline && (!group.hasDeadline || expire_time < group.expireTime)) {
    group.hasDeadline = true;
    group.expireTime = expire_time;
  }
  if (group.hasDeadline && now >= group.expireTime) {
    channel_groups.erase(it);
    return {.status = AddStatus::kDropped,
            .message = std::nullopt,
            .deadlineExpired = true};
  }

  if (group.pieces.at(fragment.fragmentIndex).has_value()) {
    return {.status = AddStatus::kDuplicate, .message = std::nullopt};
  }
  if (group.receivedBytes + payload.size() > max_message_size_) {
    channel_groups.erase(it);
    return {};
  }

  group.pieces.at(fragment.fragmentIndex) =
    std::vector<std::uint8_t>(payload.begin(), payload.end());
  group.receivedBytes += payload.size();
  ++group.receivedCount;

  if (group.receivedCount != group.total) {
    return {.status = AddStatus::kAccepted, .message = std::nullopt};
  }

  CompleteMessage complete;
  complete.channel = channel;
  complete.payload.reserve(group.receivedBytes);
  for (auto& piece : group.pieces) {
    if (!piece.has_value()) return {};
    complete.payload.insert(complete.payload.end(), piece->begin(),
                            piece->end());
  }
  channel_groups.erase(it);
  return {.status = AddStatus::kCompleted, .message = std::move(complete)};
}

std::uint32_t FragmentReassembler::Cleanup(
  std::chrono::steady_clock::time_point now) {
  std::uint32_t expired_deadline_count = 0;
  for (auto& channel_groups : groups_) {
    for (auto it = channel_groups.begin(); it != channel_groups.end();) {
      const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          now - it->second.firstReceived)
          .count();
      const bool deadline_expired =
        it->second.hasDeadline && now >= it->second.expireTime;
      const bool timeout = std::cmp_greater(elapsed, fragment_timeout_ms_);
      if (deadline_expired || timeout) {
        if (deadline_expired) ++expired_deadline_count;
        it = channel_groups.erase(it);
      } else {
        ++it;
      }
    }
  }
  return expired_deadline_count;
}

}  // namespace socketwire::detail
