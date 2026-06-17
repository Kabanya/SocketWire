#pragma once

/// Drainable task queue for work that must run on the network thread.

#include <cstddef>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>

namespace socketwire {

/// Stores tasks from any thread and executes them on the thread calling Drain.
class TaskQueue {
 public:
  using Task = std::function<void()>;

  TaskQueue() = default;
  ~TaskQueue() = default;

  TaskQueue(const TaskQueue&) = delete;
  TaskQueue& operator=(const TaskQueue&) = delete;
  TaskQueue(TaskQueue&&) = delete;
  TaskQueue& operator=(TaskQueue&&) = delete;

  /// Queues a task. Returns false only for an empty task.
  bool Post(Task task);

  /// Executes tasks that were pending when Drain started.
  ///
  /// Tasks posted by a running task are intentionally deferred to a later
  /// Drain call, which keeps re-entrant network work explicit.
  std::size_t Drain(std::size_t max_tasks = std::numeric_limits<std::size_t>::max());

  [[nodiscard]] std::size_t PendingCount() const;
  void Clear();

 private:
  mutable std::mutex mutex_;
  std::deque<Task> tasks_;
};

}  // namespace socketwire
