#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

class ThreadPool {
public:
    explicit ThreadPool(std::size_t num_threads) : stop_(false) {
        if (num_threads == 0)
            throw std::invalid_argument("ThreadPool: num_threads must be > 0");

        workers_.reserve(num_threads);
        for (std::size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] { worker_loop(); });
        }
    }

    ThreadPool(const ThreadPool&)            = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        for (auto& t : workers_)
            t.join();
    }

    template <typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>>
    {
        using ReturnType = std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<ReturnType> result = task->get_future();

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_)
                throw std::runtime_error("ThreadPool: enqueue called on stopped pool");

            tasks_.emplace([task]() { (*task)(); });
        }

        condition_.notify_one();
        return result;
    }

    std::size_t thread_count()    const noexcept { return workers_.size(); }
    std::size_t pending_tasks()   const noexcept {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return tasks_.size();
    }

private:
    void worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                condition_.wait(lock, [this] {
                    return stop_ || !tasks_.empty();
                });

                if (stop_ && tasks_.empty())
                    return;

                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();
        }
    }

    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> tasks_;

    mutable std::mutex                queue_mutex_;
    std::condition_variable           condition_;
    bool                              stop_;
};