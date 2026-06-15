#include "thread_pool.hpp"

#include <cassert>
#include <utility>

namespace socketwire {

ThreadPool::ThreadPool(std::size_t thread_count) : thread_count_(thread_count) {
  assert(thread_count_ > 0);
}

ThreadPool::~ThreadPool() { assert(workers_.empty()); }

void ThreadPool::Start() {
  assert(thread_count_ > 0);

  {
    const std::scoped_lock lock(mutex_);
    assert(!started_);
    started_ = true;
    accepting_ = true;
  }

  workers_.reserve(thread_count_);
  for (std::size_t i = 0; i < thread_count_; ++i) {
    workers_.emplace_back([this] { WorkerLoop(); });
  }
}

bool ThreadPool::Submit(Task task) {
  if (!task) return false;

  {
    const std::scoped_lock lock(mutex_);
    if (!started_) return false;
    if (!accepting_) return false;
    tasks_.push_back(std::move(task));
  }

  task_cv_.notify_one();
  return true;
}

void ThreadPool::Stop() {
  {
    const std::scoped_lock lock(mutex_);
    if (!started_ && workers_.empty()) return;
    accepting_ = false;
  }

  task_cv_.notify_all();
  for (auto& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  workers_.clear();
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
    }

    task();
  }
}

}  // namespace socketwire
