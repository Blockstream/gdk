#ifndef GDK_THREAD_SAFETY_HPP
#define GDK_THREAD_SAFETY_HPP
#pragma once

#include <mutex>

#if 0 // defined(__clang__) && (!defined(SWIG)) && (!defined(__FreeBSD__))
#define GDK_THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
#else
#define GDK_THREAD_ANNOTATION_ATTRIBUTE__(x) // no-op
#endif

#define GDK_CAPABILITY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(capability(x))

#define GDK_SCOPED_CAPABILITY GDK_THREAD_ANNOTATION_ATTRIBUTE__(scoped_lockable)

#define GDK_GUARDED_BY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))

#define GDK_PT_GUARDED_BY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(x))

#define GDK_ACQUIRED_BEFORE(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(acquired_before(__VA_ARGS__))

#define GDK_ACQUIRED_AFTER(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(acquired_after(__VA_ARGS__))

#define GDK_REQUIRES(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))

#define GDK_REQUIRES_SHARED(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(requires_shared_capability(__VA_ARGS__))

#define GDK_ACQUIRE(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))

#define GDK_ACQUIRE_SHARED(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(acquire_shared_capability(__VA_ARGS__))

#define GDK_RELEASE(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))

#define GDK_RELEASE_SHARED(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(release_shared_capability(__VA_ARGS__))

#define GDK_TRY_ACQUIRE(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(__VA_ARGS__))

#define GDK_TRY_ACQUIRE_SHARED(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_shared_capability(__VA_ARGS__))

#define GDK_EXCLUDES(...) GDK_THREAD_ANNOTATION_ATTRIBUTE__(locks_excluded(__VA_ARGS__))

#define GDK_ASSERT_CAPABILITY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(assert_capability(x))

#define GDK_ASSERT_SHARED_CAPABILITY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(assert_shared_capability(x))

#define GDK_RETURN_CAPABILITY(x) GDK_THREAD_ANNOTATION_ATTRIBUTE__(lock_returned(x))

#define GDK_NO_THREAD_SAFETY_ANALYSIS GDK_THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)

namespace ga {
namespace sdk {

    class GDK_CAPABILITY("mutex") annotated_mutex {
    public:
        void lock() GDK_ACQUIRE() { m_mutex.lock(); }

        void unlock() GDK_RELEASE() { m_mutex.unlock(); }

        bool try_lock() GDK_TRY_ACQUIRE(true) { return m_mutex.try_lock(); }

    private:
        std::mutex m_mutex;
    };

    template <class Mutex> class GDK_SCOPED_CAPABILITY annotated_unique_lock {
    public:
        using mutex_type = Mutex;

        explicit annotated_unique_lock(mutex_type& mutex) GDK_ACQUIRE(mutex)
            : m_lock{ mutex }
        {
        }

        explicit annotated_unique_lock(mutex_type& mutex, std::defer_lock_t t)
            : m_lock{ mutex, t }
        {
        }

        ~annotated_unique_lock() GDK_RELEASE() = default;

        void lock() GDK_ACQUIRE() { m_lock.lock(); }

        void unlock() GDK_RELEASE() { m_lock.unlock(); }

        bool owns_lock() const { return m_lock.owns_lock(); }

    private:
        std::unique_lock<mutex_type> m_lock;
    };

    // Scoped unlocker
    struct GDK_SCOPED_CAPABILITY unique_unlock {
        explicit unique_unlock(annotated_unique_lock<annotated_mutex>& locker)
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
        void lock() GDK_ACQUIRE()
        {
            GDK_RUNTIME_ASSERT(!m_locker.owns_lock());
            m_locker.lock();
        }

        void unlock() GDK_RELEASE()
        {
            GDK_RUNTIME_ASSERT(m_locker.owns_lock());
            m_locker.unlock();
        }

        annotated_unique_lock<annotated_mutex>& m_locker;
    };

} // namespace sdk
} // namespace ga

#endif
