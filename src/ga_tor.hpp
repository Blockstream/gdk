#ifndef GDK_GA_TOR_HPP
#define GDK_GA_TOR_HPP
#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace green {

    static constexpr uint32_t DEFAULT_TOR_SOCKS_WAIT = 120; // maximum timeout for the tor socks to get ready

    struct tor_bootstrap_phase {
        tor_bootstrap_phase();
        tor_bootstrap_phase(const tor_bootstrap_phase&) = delete;
        tor_bootstrap_phase& operator=(const tor_bootstrap_phase&) = delete;
        tor_bootstrap_phase(tor_bootstrap_phase&&) = default;
        tor_bootstrap_phase& operator=(tor_bootstrap_phase&&) = default;

        void clear();

        std::string tag;
        std::string summary;
        std::string control_port;
        uint32_t progress;
    };

    struct tor_controller_impl;

    struct tor_controller {
        tor_controller();
        ~tor_controller();

        void sleep();
        void wakeup();

        static std::shared_ptr<tor_controller> get_shared_ref();

        std::string wait_for_socks5(std::function<void(std::shared_ptr<tor_bootstrap_phase>)> phase_cb,
            uint32_t timeout = DEFAULT_TOR_SOCKS_WAIT);

    private:
        static std::mutex s_inst_mutex;
        static std::weak_ptr<tor_controller> s_inst;
        std::unique_ptr<tor_controller_impl> m_ctrl;
        std::mutex m_ctrl_mutex;

        std::string m_socks5_port;
    };

} // namespace green

#endif
