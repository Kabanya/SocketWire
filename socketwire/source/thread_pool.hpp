#pragma once

/// Small bounded thread pool for application-side SocketWire work.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace socketwire {

/// Executes application tasks outside the single-owner network loop.
///
/// ThreadPool is intentionally separate from ReliableConnection and
/// ConnectionManager. Worker tasks must not call socket or connection methods
/// directly; marshal network work back to the network thread instead.
class ThreadPool {
 public:
  using Task = std::function<void()>;

  explicit ThreadPool(std::size_t worker_count = DefaultWorkerCount(),
                      std::size_t max_queue_size = 1024);
  ~ThreadPool();

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;
  ThreadPool(ThreadPool&&) = delete;
  ThreadPool& operator=(ThreadPool&&) = delete;

  /// Queues a task without blocking. Returns false when stopped, full, or empty.
  bool Post(Task task);

  /// Waits until all queued and currently executing tasks finish.
  void WaitIdle();

  /// Stops accepting new tasks. When drain is false, queued tasks are dropped.
  void Shutdown(bool drain = true);

  [[nodiscard]] std::size_t WorkerCount() const;
  [[nodiscard]] std::size_t PendingCount() const;
  [[nodiscard]] static std::size_t DefaultWorkerCount();

 private:
  void WorkerLoop();

  const std::size_t configured_worker_count_ = 0;
  const std::size_t max_queue_size_ = 0;

  mutable std::mutex mutex_;
  std::condition_variable task_cv_;
  std::condition_variable idle_cv_;
  std::deque<Task> tasks_;
  std::vector<std::jthread> workers_;
  std::size_t active_tasks_ = 0;
  bool accepting_ = true;
};

}  // namespace socketwire
