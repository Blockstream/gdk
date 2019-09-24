#ifndef GDK_GA_TOR_HPP
#define GDK_GA_TOR_HPP
#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace ga {
namespace sdk {

    struct tor_bootstrap_phase {
        tor_bootstrap_phase();
        tor_bootstrap_phase(const tor_bootstrap_phase&) = delete;
        tor_bootstrap_phase& operator=(const tor_bootstrap_phase&) = delete;
        tor_bootstrap_phase(tor_bootstrap_phase&&) = default;
        tor_bootstrap_phase& operator=(tor_bootstrap_phase&&) = default;

        void clear();

        std::string tag;
        std::string summary;
        uint32_t progress;
    };

    struct tor_controller_impl;

    struct tor_controller {
        tor_controller();
        ~tor_controller();

        void sleep();
        void wakeup();

        std::string wait_for_socks5(
            uint32_t timeout, std::function<void(std::shared_ptr<tor_bootstrap_phase>)> phase_cb);

    private:
        std::unique_ptr<tor_controller_impl> m_ctrl;
        std::mutex m_ctrl_mutex;

        std::string m_socks5_port;
    };

} // namespace sdk
} // namespace ga

#endif
