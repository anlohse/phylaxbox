#ifndef PB_DELAYED_ACTION_H_
#define PB_DELAYED_ACTION_H_

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace pb::app {

// Runs one action after a delay on its own thread. Scheduling again replaces
// the pending action; cancel() or destruction drops it without running it.
class delayed_action {
public:
    delayed_action() : m_thread([this] { run(); }) {}
    ~delayed_action() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopping = true;
            m_action = nullptr;
        }
        m_cv.notify_one();
        if (m_thread.joinable()) m_thread.join();
    }
    delayed_action(const delayed_action&) = delete;
    delayed_action& operator=(const delayed_action&) = delete;

    void schedule(std::chrono::milliseconds delay, std::function<void()> action) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_deadline = std::chrono::steady_clock::now() + delay;
            m_action = std::move(action);
        }
        m_cv.notify_one();
    }

    void cancel() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_action = nullptr;
        m_deadline.reset();
    }

private:
    void run() {
        std::unique_lock<std::mutex> lock(m_mutex);
        while (!m_stopping) {
            if (!m_deadline) {
                m_cv.wait(lock, [this] { return m_stopping || m_deadline.has_value(); });
                continue;
            }
            const auto deadline = *m_deadline;
            if (m_cv.wait_until(lock, deadline, [this, deadline] {
                    return m_stopping || !m_deadline || *m_deadline != deadline;
                })) {
                continue; // stopped, cancelled or rescheduled
            }
            auto action = std::move(m_action);
            m_action = nullptr;
            m_deadline.reset();
            lock.unlock();
            if (action) action();
            lock.lock();
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::optional<std::chrono::steady_clock::time_point> m_deadline;
    std::function<void()> m_action;
    bool m_stopping = false;
    std::thread m_thread; // last: starts after the other members exist
};

} // namespace pb::app

#endif // PB_DELAYED_ACTION_H_
