#pragma once

/// Small thread pool for application-side SocketWire work.

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

  explicit ThreadPool(std::size_t thread_count);
  ~ThreadPool() noexcept;

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;
  ThreadPool(ThreadPool&&) = delete;
  ThreadPool& operator=(ThreadPool&&) = delete;

  /// Starts worker threads. Must be called exactly once before Submit().
  void Start();

  /// Queues a task without blocking. Returns false before Start(), after Stop(),
  /// or for an empty task.
  bool Submit(Task task);

  /// Stops accepting tasks, drains queued work, and joins all workers.
  void Stop();

private:
  void WorkerLoop();

  const std::size_t thread_count_ = 0;

  mutable std::mutex mutex_;
  std::condition_variable task_cv_;
  std::condition_variable join_cv_;
  std::deque<Task> tasks_;
  std::vector<std::thread> workers_;
  bool started_ = false;
  bool accepting_ = false;
  bool joining_ = false;
};

}  // namespace socketwire
