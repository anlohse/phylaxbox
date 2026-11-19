#ifndef PB_SERIAL_WORKER_H_
#define PB_SERIAL_WORKER_H_

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

namespace pb::app {

// One background thread running jobs in order. Keeps slow work (Argon2id
// key derivation, file I/O) off the UI thread, and serializes access to the
// vault so no locking is needed inside it.
class serial_worker {
public:
    serial_worker() : m_thread([this] { run(); }) {}
    ~serial_worker() { stop(); }

    serial_worker(const serial_worker&) = delete;
    serial_worker& operator=(const serial_worker&) = delete;

    // False (and the job is dropped) once the worker is stopping.
    bool post(std::function<void()> job) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping) return false;
            m_jobs.push_back(std::move(job));
        }
        m_cv.notify_one();
        return true;
    }

    // Lets the running job finish, drops queued ones, joins the thread.
    void stop() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopping = true;
            m_jobs.clear();
        }
        m_cv.notify_one();
        if (m_thread.joinable()) m_thread.join();
    }

private:
    void run() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this] { return m_stopping || !m_jobs.empty(); });
                if (m_stopping) return;
                job = std::move(m_jobs.front());
                m_jobs.pop_front();
            }
            job();
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::function<void()>> m_jobs;
    bool m_stopping = false;
    std::thread m_thread; // last: starts after the other members exist
};

} // namespace pb::app

#endif // PB_SERIAL_WORKER_H_
