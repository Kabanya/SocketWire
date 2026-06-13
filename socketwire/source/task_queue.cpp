#include "task_queue.hpp"

#include <algorithm>
#include <utility>

namespace socketwire {

bool TaskQueue::Post(Task task) {
  if (!task) return false;

  const std::lock_guard lock(mutex_);
  tasks_.push_back(std::move(task));
  return true;
}

std::size_t TaskQueue::Drain(std::size_t max_tasks) {
  if (max_tasks == 0) return 0;

  std::deque<Task> ready;
  {
    const std::lock_guard lock(mutex_);
    const std::size_t count = std::min(max_tasks, tasks_.size());
    for (std::size_t i = 0; i < count; ++i) {
      ready.push_back(std::move(tasks_.front()));
      tasks_.pop_front();
    }
  }

  for (auto& task : ready) task();
  return ready.size();
}

std::size_t TaskQueue::PendingCount() const {
  const std::lock_guard lock(mutex_);
  return tasks_.size();
}

void TaskQueue::Clear() {
  const std::lock_guard lock(mutex_);
  tasks_.clear();
}

}  // namespace socketwire
