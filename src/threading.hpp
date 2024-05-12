#ifndef GDK_THREADING_HPP
#define GDK_THREADING_HPP
#pragma once

#include <mutex>

namespace green {


    // Scoped unlocker
    struct unique_unlock {
        explicit unique_unlock(std::unique_lock<std::mutex>& locker)
            : m_locker(locker)
        {
            unlock();
        }

        ~unique_unlock() { lock(); }

        unique_unlock(const unique_unlock&) = delete;
        unique_unlock(unique_unlock&&) = delete;
        unique_unlock& operator=(const unique_unlock&) = delete;
        unique_unlock& operator=(unique_unlock&&) = delete;

    private:
        void lock()
        {
            GDK_RUNTIME_ASSERT(!m_locker.owns_lock());
            m_locker.lock();
        }

        void unlock()
        {
            GDK_RUNTIME_ASSERT(m_locker.owns_lock());
            m_locker.unlock();
        }

        std::unique_lock<std::mutex>& m_locker;
    };


} // namespace green

#endif
