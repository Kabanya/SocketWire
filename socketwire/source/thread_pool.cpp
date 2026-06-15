#include "thread_pool.hpp"

#include <cassert>
#include <utility>

namespace socketwire {
namespace {

const ThreadPool*& CurrentThreadPool() {
  thread_local const ThreadPool* pool = nullptr;
  return pool;
}

}  // namespace

ThreadPool::ThreadPool(std::size_t thread_count) : thread_count_(thread_count) {
  assert(thread_count_ > 0);
}

ThreadPool::~ThreadPool() { Stop(); }

void ThreadPool::Start() {
  assert(thread_count_ > 0);

  const std::scoped_lock lock(mutex_);
  assert(!started_);
  assert(!joining_);
  started_ = true;
  accepting_ = true;
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
  const auto self_id = std::this_thread::get_id();
  const bool called_from_worker = CurrentThreadPool() == this;

  for (;;) {
    std::vector<std::thread> workers;
    {
      std::unique_lock lock(mutex_);
      if (!started_ && workers_.empty() && !joining_) return;
      accepting_ = false;

      if (joining_) {
        if (called_from_worker) return;
        task_cv_.notify_all();
        join_cv_.wait(lock, [this] { return !joining_; });
        continue;
      }

      for (auto it = workers_.begin(); it != workers_.end();) {
        if (it->joinable() && it->get_id() == self_id) {
          ++it;
          continue;
        }
        workers.push_back(std::move(*it));
        it = workers_.erase(it);
      }

      if (workers.empty()) {
        task_cv_.notify_all();
        return;
      }

      joining_ = true;
    }

    task_cv_.notify_all();
    for (auto& worker : workers) {
      if (worker.joinable()) worker.join();
    }

    {
      const std::scoped_lock lock(mutex_);
      joining_ = false;
    }
    join_cv_.notify_all();
  }
}

void ThreadPool::WorkerLoop() {
  CurrentThreadPool() = this;
  while (true) {
    Task task;
    {
      std::unique_lock lock(mutex_);
      task_cv_.wait(lock,
                    [this] { return !accepting_ || !tasks_.empty(); });
      if (tasks_.empty()) {
        CurrentThreadPool() = nullptr;
        return;
      }

      task = std::move(tasks_.front());
      tasks_.pop_front();
    }

    task();
  }
}

}  // namespace socketwire
