#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <cstddef>

// Thread-safe queue with bounded capacity.
// Producers block when full, consumers block when empty.
// Sending a nullopt signals "no more items" to consumers.
template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 1024)
        : max_size_(max_size), done_(false) {}

    // Push item — blocks if queue is full
    // Returns false if queue has been shut down
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this]{
            return queue_.size() < max_size_ || done_;
        });
        if (done_) return false;
        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    // Pop item — blocks until item available or done
    // Returns nullopt when queue is done and empty
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this]{
            return !queue_.empty() || done_;
        });
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }

    // Signal no more items will be pushed
    // Wakes all waiting consumers
    void shutdown() {
        std::unique_lock<std::mutex> lock(mutex_);
        done_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool isDone() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return done_ && queue_.empty();
    }

private:
    mutable std::mutex      mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::queue<T>           queue_;
    size_t                  max_size_;
    bool                    done_;
};