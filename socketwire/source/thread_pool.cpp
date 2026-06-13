#include "thread_pool.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace socketwire {

ThreadPool::ThreadPool(std::size_t worker_count, std::size_t max_queue_size)
    : configured_worker_count_(std::max<std::size_t>(1, worker_count)),
      max_queue_size_(max_queue_size) {
  workers_.reserve(configured_worker_count_);
  for (std::size_t i = 0; i < configured_worker_count_; ++i) {
    workers_.emplace_back([this] { WorkerLoop(); });
  }
}

ThreadPool::~ThreadPool() { Shutdown(true); }

bool ThreadPool::Post(Task task) {
  if (!task) return false;

  {
    const std::lock_guard lock(mutex_);
    if (!accepting_) return false;
    if (max_queue_size_ > 0 && tasks_.size() >= max_queue_size_) return false;
    tasks_.push_back(std::move(task));
  }

  task_cv_.notify_one();
  return true;
}

void ThreadPool::WaitIdle() {
  std::unique_lock lock(mutex_);
  idle_cv_.wait(lock,
                [this] { return tasks_.empty() && active_tasks_ == 0; });
}

void ThreadPool::Shutdown(bool drain) {
  {
    const std::lock_guard lock(mutex_);
    if (!accepting_ && workers_.empty()) return;
    accepting_ = false;
    if (!drain) tasks_.clear();
  }

  task_cv_.notify_all();
  for (auto& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  workers_.clear();

  idle_cv_.notify_all();
}

std::size_t ThreadPool::WorkerCount() const {
  return configured_worker_count_;
}

std::size_t ThreadPool::PendingCount() const {
  const std::lock_guard lock(mutex_);
  return tasks_.size();
}

std::size_t ThreadPool::DefaultWorkerCount() {
  const std::size_t count =
    static_cast<std::size_t>(std::thread::hardware_concurrency());
  if (count <= 1) return 1;
  return count - 1;
}

void ThreadPool::WorkerLoop() {
  while (true) {
    Task task;
    {
      std::unique_lock lock(mutex_);
      task_cv_.wait(lock,
                    [this] { return !accepting_ || !tasks_.empty(); });
      if (tasks_.empty()) return;

      task = std::move(tasks_.front());
      tasks_.pop_front();
      ++active_tasks_;
    }

    try {
      task();
    } catch (...) {
      // Keep the worker alive; application tasks own their error handling.
    }

    {
      const std::lock_guard lock(mutex_);
      --active_tasks_;
      if (tasks_.empty() && active_tasks_ == 0) idle_cv_.notify_all();
    }
  }
}

}  // namespace socketwire
