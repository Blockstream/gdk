// Copyright (c) 2015-2018 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ga_tor.hpp"
#include "assertion.hpp"
#include "exception.hpp"
#include "ga_wally.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "session.hpp"
#include "utils.hpp"

#include <condition_variable>
#include <cstdio>
#include <stdlib.h>
#include <string>
#include <vector>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/signals2/signal.hpp>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

extern "C" {
#include "tor_api.h"
}

using namespace std::chrono_literals;

namespace ga {
namespace sdk {
    std::mutex tor_controller::s_inst_mutex;
    std::weak_ptr<tor_controller> tor_controller::s_inst;

    static std::string read_file(std::string fname)
    {
        std::FILE* fp = std::fopen(fname.c_str(), "rb");
        std::string res;
        if (fp) {
            std::fseek(fp, 0, SEEK_END);

            size_t size = std::ftell(fp);
            res.resize(size);

            std::rewind(fp);

            size_t read = std::fread(&res[0], 1, res.size(), fp);
            GDK_RUNTIME_ASSERT(read == size);

            std::fclose(fp);
        }
        return res;
    }

    static void clear_file(std::string fname)
    {
        std::FILE* fp = std::fopen(fname.c_str(), "wb");
        if (fp) {
            std::fclose(fp);
        }
    }

    static std::pair<std::string, std::string> split_tor_reply_line(const std::string& s)
    {
        size_t ptr = 0;
        std::string type;
        while (ptr < s.size() && s[ptr] != ' ') {
            type.push_back(s[ptr]);
            ++ptr;
        }
        if (ptr < s.size())
            ++ptr; // skip ' '
        return make_pair(type, s.substr(ptr));
    }

    static std::map<std::string, std::string> parse_tor_reply_mapping(const std::string& s)
    {
        std::map<std::string, std::string> mapping;
        size_t ptr = 0;
        while (ptr < s.size()) {
            std::string key, value;
            while (ptr < s.size() && s[ptr] != '=' && s[ptr] != ' ') {
                key.push_back(s[ptr]);
                ++ptr;
            }
            if (ptr == s.size()) // unexpected end of line
                return std::map<std::string, std::string>();
            if (s[ptr] == ' ') { // The remaining string is an OptArguments
                mapping[key] = key;
                ++ptr; // skip the ' '
                continue;
            }
            ++ptr; // skip '='
            if (ptr < s.size() && s[ptr] == '"') { // Quoted string
                ++ptr; // skip opening '"'
                bool escape_next = false;
                while (ptr < s.size() && (escape_next || s[ptr] != '"')) {
                    // Repeated backslashes must be interpreted as pairs
                    escape_next = (s[ptr] == '\\' && !escape_next);
                    value.push_back(s[ptr]);
                    ++ptr;
                }
                if (ptr == s.size()) // unexpected end of line
                    return std::map<std::string, std::string>();
                ++ptr; // skip closing '"'
                /**
                 * Unescape value. Per https://spec.torproject.org/control-spec section 2.1.1:
                 *
                 *   For future-proofing, controller implementors MAY use the following
                 *   rules to be compatible with buggy Tor implementations and with
                 *   future ones that implement the spec as intended:
                 *
                 *     Read \n \t \r and \0 ... \377 as C escapes.
                 *     Treat a backslash followed by any other character as that character.
                 */
                std::string escaped_value;
                for (size_t i = 0; i < value.size(); ++i) {
                    if (value[i] == '\\') {
                        // This will always be valid, because if the QuotedString
                        // ended in an odd number of backslashes, then the parser
                        // would already have returned above, due to a missing
                        // terminating double-quote.
                        ++i;
                        if (value[i] == 'n') {
                            escaped_value.push_back('\n');
                        } else if (value[i] == 't') {
                            escaped_value.push_back('\t');
                        } else if (value[i] == 'r') {
                            escaped_value.push_back('\r');
                        } else if ('0' <= value[i] && value[i] <= '7') {
                            size_t j;
                            // Octal escape sequences have a limit of three octal digits,
                            // but terminate at the first character that is not a valid
                            // octal digit if encountered sooner.
                            for (j = 1; j < 3 && (i + j) < value.size() && '0' <= value[i + j] && value[i + j] <= '7';
                                 ++j) {
                            }
                            // Tor restricts first digit to 0-3 for three-digit octals.
                            // A leading digit of 4-7 would therefore be interpreted as
                            // a two-digit octal.
                            if (j == 3 && value[i] > '3') {
                                j--;
                            }
                            escaped_value.push_back(strtol(value.substr(i, j).c_str(), nullptr, 8));
                            // Account for automatic incrementing at loop end
                            i += j - 1;
                        } else {
                            escaped_value.push_back(value[i]);
                        }
                    } else {
                        escaped_value.push_back(value[i]);
                    }
                }
                value = escaped_value;
            } else { // Unquoted value. Note that values can contain '=' at will, just no spaces
                while (ptr < s.size() && s[ptr] != ' ') {
                    value.push_back(s[ptr]);
                    ++ptr;
                }
            }
            if (ptr < s.size() && s[ptr] == ' ')
                ++ptr; // skip ' ' after key=value
            mapping[key] = value;
        }
        return mapping;
    }

    static const int MAX_LINE_LENGTH = 100000;
    static const int TOR_NONCE_SIZE = 32;
    static const std::string TOR_SAFE_SERVERKEY = "Tor safe cookie authentication server-to-controller hash";
    static const std::string TOR_SAFE_CLIENTKEY = "Tor safe cookie authentication controller-to-server hash";
    static const std::string TOR_CONTROL_PORT_TAG("PORT=");
    static const std::string LOCALHOST_SOCKS5_UNTIL_PORT("socks5://127.0.0.1:");

    struct tor_control_reply {
        tor_control_reply();
        void clear();

        int m_code;
        std::vector<std::string> m_lines;
    };

    struct tor_control_connection {
        typedef std::function<void(tor_control_connection&)> ConnectionCB;
        typedef std::function<void(tor_control_connection&, const tor_control_reply&)> ReplyHandlerCB;

        explicit tor_control_connection(struct event_base* base, const std::string& _tor_control_port);
        ~tor_control_connection();

        bool connect(const ConnectionCB& connected, const ConnectionCB& disconnected);

        void disconnect();

        bool command(const std::string& cmd, const ReplyHandlerCB& reply_handler);

        boost::signals2::signal<void(tor_control_connection&, const tor_control_reply&)> m_async_handler;

    private:
        ConnectionCB m_connected;
        ConnectionCB m_disconnected;

        struct event_base* m_base;
        struct bufferevent* m_b_conn;
        const std::string& m_tor_control_port;

        tor_control_reply m_message;

        std::deque<ReplyHandlerCB> m_reply_handlers;

        static void readcb(struct bufferevent* bev, void* ctx);
        static void eventcb(struct bufferevent* bev, short what, void* ctx);
    };

    struct tor_controller_impl {
        tor_controller_impl(const std::string& socks5_port, const std::string& tor_datadir);
        ~tor_controller_impl();

        std::string wait_for_socks5(
            uint32_t timeout, std::function<void(std::shared_ptr<tor_bootstrap_phase>)> phase_cb);

    private:
        std::thread m_tor_run_thread;
        std::thread m_tor_control_thread;
        std::condition_variable m_init_cv;
        std::mutex m_init_mutex;
        struct event_base* m_base;
        const std::string m_tor_datadir;
        const std::string m_tor_control_file;
        std::string m_tor_control_port;
        std::unique_ptr<tor_control_connection> m_conn;
        bool m_stopping;

        std::vector<uint8_t> m_cookie;
        std::array<uint8_t, TOR_NONCE_SIZE> m_client_nonce;

        // Tor's socks5 listener, empty if not ready yet
        std::string m_socks5;

        // Latest bootstrap phase
        std::shared_ptr<tor_bootstrap_phase> m_bootstrap_phase;

        // All the callbacks used to receive asynchronous replies from Tor. The "flow" is as follows:
        //
        // We give `tor_control_connection` our `connected_cb` and `disconnected_cb`, so these are the two
        // possible "entry points" that start the chain of callbacks on our side.
        //
        // `connected_cb`: As soon as the control connection is ready, our `connected_cb` gets called: first thing it
        //     does is asking Tor which protocols it supports, and sets `protocolinfo_cb` as the handler for the reply
        // `protocolinfo_cb`: This callback reads the AUTHCOOKIE from disk and starts the authentication challenge
        //     protocol.
        // `authchallenge_cb`: This callback does all the crypto stuff (HMACs, etc) and then tries to authenticate
        // `auth_cb`: This callback receives the result of the authentication. It ensures that everything
        //     went fine, and since Tor has been running in background for all this time, it asks for the current
        //     bootstrap phase, to see whether it is already connected or not.
        // `bootstrap_phase_cb`: This callback receives the result of a bootstrap phase query. It has two possible
        //     outcomes:
        //         if the "progress" has reached 100, it asks tor for the socks5 port and sets `socks_cb` as callback
        //         otherwise it sleeps for 250ms and then asks for the bootstrap phase again
        // `socks_cb`: This is the last callback, which copies the socks5 listener into our internal field and finally
        //     completes the "chain reaction.
        //
        // There's also `disconnected_cb` which is called by `tor_control_connection` when the connection on the control
        //     port is dropped.
        // `stopped_cb` is called when the `HALT` command is acknowledged by Tor, meaning that it is shutting down

        void connected_cb(tor_control_connection& conn);
        void protocolinfo_cb(tor_control_connection& conn, const tor_control_reply& reply);
        void authchallenge_cb(tor_control_connection& conn, const tor_control_reply& reply);
        void auth_cb(tor_control_connection& conn, const tor_control_reply& reply);
        void bootstrap_phase_cb(tor_control_connection& conn, const tor_control_reply& reply);
        void socks_cb(const tor_control_reply& reply);

        void disconnected_cb();
        void stopped_cb();
    };
    tor_control_reply::tor_control_reply() { clear(); }

    void tor_control_reply::clear()
    {
        m_code = 0;
        m_lines.clear();
    }

    tor_bootstrap_phase::tor_bootstrap_phase() { clear(); }

    void tor_bootstrap_phase::clear()
    {
        tag = "";
        summary = "";
        progress = 0;
    }

    tor_control_connection::tor_control_connection(struct event_base* _base, const std::string& _tor_control_port)
        : m_base(_base)
        , m_b_conn(nullptr)
        , m_tor_control_port(_tor_control_port)
    {
    }

    tor_control_connection::~tor_control_connection()
    {
        if (m_b_conn)
            bufferevent_free(m_b_conn);
    }

    void tor_control_connection::readcb(struct bufferevent* bev, void* ctx)
    {
        tor_control_connection* self = static_cast<tor_control_connection*>(ctx);

        struct evbuffer* input = bufferevent_get_input(bev);
        assert(input);

        size_t n_read_out = 0;
        char* line;

        //  If there is not a whole line to read, evbuffer_readln returns nullptr
        while ((line = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF)) != nullptr) {
            std::string s(line, n_read_out);
            free(line);
            if (s.size() < 4) // Short line
                continue;
            // <status>(-|+| )<data><CRLF>
            self->m_message.m_code = atoi(s.substr(0, 3).c_str());
            self->m_message.m_lines.push_back(s.substr(4));
            char ch = s[3]; // '-','+' or ' '
            if (ch == ' ') {
                // Final line, dispatch reply and clean up
                if (self->m_message.m_code >= 600) {
                    // Dispatch async notifications to async handler
                    // Synchronous and asynchronous self->m_messages are never interleaved
                    self->m_async_handler(*self, self->m_message);
                } else {
                    if (!self->m_reply_handlers.empty()) {
                        // Invoke reply handler with self->m_message
                        self->m_reply_handlers.front()(*self, self->m_message);
                        self->m_reply_handlers.pop_front();
                    } else {
                        GDK_LOG_SEV(log_level::debug)
                            << "tor: Received unexpected sync reply " << self->m_message.m_code;
                    }
                }
                self->m_message.clear();
            }
        }
        //  Check for size of buffer - protect against memory exhaustion with very long lines
        //  Do this after evbuffer_readln to make sure all full lines have been
        //  removed from the buffer. Everything left is an incomplete line.
        if (evbuffer_get_length(input) > MAX_LINE_LENGTH) {
            GDK_LOG_SEV(log_level::debug) << "tor: Disconnecting because MAX_LINE_LENGTH exceeded";
            self->disconnect();
        }
    }

    void tor_control_connection::eventcb(__attribute__((unused)) struct bufferevent* bev, short what, void* ctx)
    {
        tor_control_connection* self = static_cast<tor_control_connection*>(ctx);

        if (what & BEV_EVENT_CONNECTED) {
            GDK_LOG_SEV(log_level::info) << "tor: Control successfully connected!";
            self->m_connected(*self);
        } else if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            if (what & BEV_EVENT_ERROR) {
                GDK_LOG_SEV(log_level::info) << "tor: Error connecting to Tor control socket";
            } else {
                GDK_LOG_SEV(log_level::info) << "tor: End of stream\n";
            }

            self->disconnect();
        }
    }

    bool tor_control_connection::connect(const ConnectionCB& _connected, const ConnectionCB& _disconnected)
    {
        if (m_b_conn)
            disconnect();

        // Parse target address:port
        struct sockaddr_storage connect_to_addr;
        int connect_to_addrlen = sizeof(connect_to_addr);
        if (evutil_parse_sockaddr_port(
                m_tor_control_port.c_str(), (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)
            < 0) {
            GDK_LOG_SEV(log_level::info) << "tor: Error parsing socket address " << m_tor_control_port;
            return false;
        }
        GDK_LOG_SEV(log_level::info) << "tor: connecting to controller " << m_tor_control_port;

        // Create a new socket, set up callbacks and enable notification bits
        m_b_conn = bufferevent_socket_new(m_base, -1, BEV_OPT_CLOSE_ON_FREE);
        if (!m_b_conn)
            return false;
        bufferevent_setcb(m_b_conn, tor_control_connection::readcb, nullptr, tor_control_connection::eventcb, this);
        bufferevent_enable(m_b_conn, EV_READ | EV_WRITE);
        this->m_connected = _connected;
        this->m_disconnected = _disconnected;

        // Finally, connect to target
        if (bufferevent_socket_connect(m_b_conn, (struct sockaddr*)&connect_to_addr, connect_to_addrlen) < 0) {
            GDK_LOG_SEV(log_level::info) << "tor: Error connecting to address " << m_tor_control_port;
            return false;
        }
        return true;
    }

    void tor_control_connection::disconnect()
    {
        if (m_b_conn)
            bufferevent_free(m_b_conn);
        if (m_disconnected)
            m_disconnected(*this);

        m_b_conn = nullptr;
    }

    bool tor_control_connection::command(const std::string& cmd, const ReplyHandlerCB& reply_handler)
    {
        if (!m_b_conn)
            return false;
        struct evbuffer* buf = bufferevent_get_output(m_b_conn);
        if (!buf)
            return false;
        evbuffer_add(buf, cmd.data(), cmd.size());
        evbuffer_add(buf, "\r\n", 2);
        m_reply_handlers.push_back(reply_handler);
        return true;
    }

    static struct event_base* init_eb()
    {
#ifdef WIN32
        GDK_RUNTIME_ASSERT(!evthread_use_windows_threads());
#else
        GDK_RUNTIME_ASSERT(!evthread_use_pthreads());
#endif
        return event_base_new();
    }

    static std::string get_tor_control_port(const std::string& tor_control_file)
    {
        std::string tor_control_port;
        uint32_t attempts = 10;
        do {
            GDK_RUNTIME_ASSERT(attempts);
            tor_control_port = read_file(tor_control_file);
            if (tor_control_port.empty()) {
                std::this_thread::sleep_for(100ms);
                --attempts;
            }
        } while (tor_control_port.empty());

        GDK_LOG_SEV(log_level::info) << "tor: control port " << tor_control_port;
        GDK_RUNTIME_ASSERT(tor_control_port.size() > TOR_CONTROL_PORT_TAG.size());
        tor_control_port.erase(0, TOR_CONTROL_PORT_TAG.size());
        return tor_control_port;
    }

    static std::string get_tor_control_file(const std::string& tor_datadir)
    {
        std::string tor_control_file = tor_datadir + "/.torcontrol";
        clear_file(tor_control_file);
        return tor_control_file;
    }

    tor_controller_impl::tor_controller_impl(const std::string& socks5_port, const std::string& tor_datadir)
        : m_base(init_eb())
        , m_tor_datadir(tor_datadir)
        , m_tor_control_file(get_tor_control_file(m_tor_datadir))
        , m_stopping(false)
    {
        GDK_LOG_SEV(log_level::info) << "Starting up internal Tor";

        const std::string conf_socks_port = socks5_port.empty() ? "auto" : socks5_port;

        m_tor_run_thread = std::thread([&] {
            tor_main_configuration_t* tor_conf = tor_main_configuration_new();
            GDK_RUNTIME_ASSERT(tor_conf);
            const bool quiet = gdk_config()["log_level"] == "none";
            std::vector<const char*> argv_conf;
            argv_conf.reserve(17);
            argv_conf.push_back("tor");
            if (quiet) {
                argv_conf.push_back("--quiet"); // Silence all log output
            }
            argv_conf.push_back("__DisableSignalHandlers");
            argv_conf.push_back("1");
            argv_conf.push_back("SafeSocks");
            argv_conf.push_back("1");
            argv_conf.push_back("SocksPort");
            argv_conf.push_back(conf_socks_port.c_str());
            argv_conf.push_back("NoExec");
            argv_conf.push_back("1");
            argv_conf.push_back("ControlPortWriteToFile");
            argv_conf.push_back(m_tor_control_file.c_str());
            argv_conf.push_back("CookieAuthentication");
            argv_conf.push_back("1");
            argv_conf.push_back("ControlPort");
            argv_conf.push_back("auto");
            argv_conf.push_back("DataDirectory");
            argv_conf.push_back(m_tor_datadir.c_str());
#if not defined(NDEBUG)
            if (!quiet) {
                argv_conf.push_back("Log");
                argv_conf.push_back("notice"); // debug prints out way too much stuff and we don't really need them
            }
#endif
            int conf_res
                = tor_main_configuration_set_command_line(tor_conf, argv_conf.size(), (char**)argv_conf.data());
            GDK_RUNTIME_ASSERT(!conf_res);

            GDK_LOG_SEV(log_level::info) << "tor_run_main begins";
            tor_run_main(tor_conf);
            GDK_LOG_SEV(log_level::info) << "tor_run_main exited";

            tor_main_configuration_free(tor_conf);

            m_base = nullptr;
        });

        GDK_LOG_SEV(log_level::info) << "Tor thread started";

        m_tor_control_port = get_tor_control_port(m_tor_control_file);
        m_conn = std::make_unique<tor_control_connection>(m_base, m_tor_control_port);

        m_bootstrap_phase = std::make_shared<tor_bootstrap_phase>();

        GDK_RUNTIME_ASSERT(m_conn->connect(std::bind(&tor_controller_impl::connected_cb, this, std::placeholders::_1),
            std::bind(&tor_controller_impl::disconnected_cb, this)));

        m_tor_control_thread = std::thread([_m_base = this->m_base] {
            event_base_dispatch(_m_base);
            event_base_free(_m_base);
        });
    }

    tor_controller_impl::~tor_controller_impl()
    {
        if (m_stopping) {
            return;
        }

        m_stopping = true;

        m_bootstrap_phase->progress = 0;
        m_bootstrap_phase->tag = "";
        m_bootstrap_phase->summary = "Stopping Tor...";

        no_std_exception_escape([this] {
            if (!m_conn->command("SIGNAL HALT", std::bind(&tor_controller_impl::stopped_cb, this))) {
                GDK_LOG_SEV(log_level::info) << "tor: could not send the HALT signal, is Tor already stopped?";
            }

            // This is blocking because if we return immediately the caller could try to start tor while the
            // background thread is still running, triggering an assert inside Tor's codebase

            m_tor_control_thread.join();
            m_tor_run_thread.join();
        });
    }

    void tor_controller_impl::connected_cb(tor_control_connection& _conn)
    {
        // First send a PROTOCOLINFO command to figure out what authentication is expected
        if (!_conn.command("PROTOCOLINFO 1",
                std::bind(&tor_controller_impl::protocolinfo_cb, this, std::placeholders::_1, std::placeholders::_2))) {
            this->disconnected_cb();
        }
    }

    void tor_controller_impl::protocolinfo_cb(tor_control_connection& _conn, const tor_control_reply& reply)
    {
        GDK_RUNTIME_ASSERT(reply.m_code == 250);
        std::set<std::string> methods;
        std::string cookiefile;
        /*
         * 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/x/.tor/control_auth_cookie"
         * 250-AUTH METHODS=NULL
         * 250-AUTH METHODS=HASHEDPASSWORD
         */
        for (const std::string& s : reply.m_lines) {
            std::pair<std::string, std::string> l = split_tor_reply_line(s);
            if (l.first == "AUTH") {
                std::map<std::string, std::string> m = parse_tor_reply_mapping(l.second);
                std::map<std::string, std::string>::iterator i;
                if ((i = m.find("METHODS")) != m.end())
                    boost::split(methods, i->second, boost::is_any_of(","));
                if ((i = m.find("COOKIEFILE")) != m.end())
                    cookiefile = i->second;
            }
        }
        auto status_cookie = read_file(cookiefile.c_str());
        m_cookie = std::vector<uint8_t>(status_cookie.begin(), status_cookie.end());
        this->m_client_nonce = get_random_bytes<TOR_NONCE_SIZE>();
        if (!_conn.command("AUTHCHALLENGE SAFECOOKIE " + b2h(m_client_nonce),
                std::bind(
                    &tor_controller_impl::authchallenge_cb, this, std::placeholders::_1, std::placeholders::_2))) {
            this->disconnected_cb();
        }
    }

    void tor_controller_impl::authchallenge_cb(tor_control_connection& _conn, const tor_control_reply& reply)
    {
        GDK_RUNTIME_ASSERT(reply.m_code == 250);
        GDK_LOG_SEV(log_level::info) << "tor: SAFECOOKIE authentication challenge successful";

        const auto l = split_tor_reply_line(reply.m_lines[0]);
        GDK_RUNTIME_ASSERT(l.first == "AUTHCHALLENGE");
        auto m = parse_tor_reply_mapping(l.second);
        GDK_RUNTIME_ASSERT(!m.empty());

        const auto serverHash = h2b(m["SERVERHASH"]);
        const auto serverNonce = h2b(m["SERVERNONCE"]);
        GDK_RUNTIME_ASSERT(serverNonce.size() == HMAC_SHA256_LEN);

        std::vector<uint8_t> data;
        data.reserve(m_cookie.size() + this->m_client_nonce.size() + serverNonce.size());
        data.insert(data.end(), m_cookie.begin(), m_cookie.end());
        data.insert(data.end(), this->m_client_nonce.begin(), this->m_client_nonce.end());
        data.insert(data.end(), serverNonce.begin(), serverNonce.end());

        const auto computedServerHash = hmac_sha256(ustring_span(TOR_SAFE_SERVERKEY), data);
        const auto hash_equals = std::equal(computedServerHash.begin(), computedServerHash.end(), serverHash.begin());

        GDK_RUNTIME_ASSERT(hash_equals);

        const auto computedClientHash = hmac_sha256(ustring_span(TOR_SAFE_CLIENTKEY), data);
        if (!_conn.command("AUTHENTICATE " + b2h(computedClientHash),
                std::bind(&tor_controller_impl::auth_cb, this, std::placeholders::_1, std::placeholders::_2))) {
            this->disconnected_cb();
        }
    }

    void tor_controller_impl::auth_cb(tor_control_connection& _conn, const tor_control_reply& reply)
    {
        GDK_RUNTIME_ASSERT(reply.m_code == 250);
        GDK_LOG_SEV(log_level::info) << "tor: ready, waiting for the circuit";

        if (!_conn.command("GETINFO status/bootstrap-phase",
                std::bind(
                    &tor_controller_impl::bootstrap_phase_cb, this, std::placeholders::_1, std::placeholders::_2))) {
            this->disconnected_cb();
        }
    }

    void tor_controller_impl::bootstrap_phase_cb(tor_control_connection& _conn, const tor_control_reply& reply)
    {
        GDK_RUNTIME_ASSERT(reply.m_code == 250);

        const auto l = split_tor_reply_line(reply.m_lines[0]);
        auto m = parse_tor_reply_mapping(l.second);
        GDK_RUNTIME_ASSERT(!m.empty());

        // Locking here to avoid race conditions on m_bootstrap_phase
        {
            std::lock_guard<std::mutex> _(m_init_mutex);

            m_bootstrap_phase->tag = m["TAG"];
            m_bootstrap_phase->summary = m["SUMMARY"];
            m_bootstrap_phase->progress = std::stoi(m["PROGRESS"]);
        }

        // Notify that we updated it, so that ga_session can emit a new notification
        m_init_cv.notify_all();

        if (m_bootstrap_phase->progress == 100) {
            GDK_LOG_SEV(log_level::info) << "tor: the circuit is ready, we can finally use it!";

            if (!_conn.command("GETINFO net/listeners/socks",
                    std::bind(&tor_controller_impl::socks_cb, this, std::placeholders::_2))) {
                this->disconnected_cb();
            }
        } else {
            std::this_thread::sleep_for(250ms);
            if (!_conn.command("GETINFO status/bootstrap-phase",
                    std::bind(&tor_controller_impl::bootstrap_phase_cb, this, std::placeholders::_1,
                        std::placeholders::_2))) {
                this->disconnected_cb();
            }
        }
    }

    void tor_controller_impl::socks_cb(const tor_control_reply& reply)
    {
        GDK_RUNTIME_ASSERT(reply.m_code == 250);
        GDK_LOG_SEV(log_level::info) << "tor: SOCKSPORT ready";

        auto m = parse_tor_reply_mapping(reply.m_lines[0]);
        GDK_RUNTIME_ASSERT(!m.empty());

        GDK_LOG_SEV(log_level::info) << "tor: settings socks5 to " << m["net/listeners/socks"];
        std::lock_guard<std::mutex> _(m_init_mutex);
        m_socks5 = "socks5://" + m["net/listeners/socks"];
        m_init_cv.notify_all();
    }

    void tor_controller_impl::disconnected_cb()
    {
        if (m_stopping) {
            return;
        }

        // This is bad, Tor has probably crashed. We can't restart it because its internal state is compromised,
        // so throw an exception to crash
        throw reconnect_error();
    }

    void tor_controller_impl::stopped_cb() { GDK_LOG_SEV(log_level::info) << "tor: halt command received"; }

    std::string tor_controller_impl::wait_for_socks5(
        uint32_t timeout, std::function<void(std::shared_ptr<tor_bootstrap_phase>)> phase_cb)
    {
        uint32_t last_progress = -1;

        auto now = std::chrono::steady_clock::now();
        auto tstop = now + 1000ms * timeout;

        // Lock used to read m_bootstrap_phase and m_socks5
        std::unique_lock<std::mutex> lock(m_init_mutex);
        while (m_socks5.empty() && now < tstop) {
            if (phase_cb != nullptr && m_bootstrap_phase->progress != last_progress) {
                last_progress = m_bootstrap_phase->progress;
                phase_cb(m_bootstrap_phase);
            }

            // This will wake up either when tstop is reached (timeout) or when we got a notification
            // The notification could come from an updated boostrap phase or when socks5 is set
            m_init_cv.wait_until(lock, tstop);

            // update the timestamp
            now = std::chrono::steady_clock::now();
        }

        return m_socks5;
    }

    static std::unique_ptr<tor_controller_impl> make_controller(const std::string& socks5_port)
    {
        const std::string tor_datadir = gdk_config()["tordir"];
        GDK_LOG_SEV(log_level::info) << "tor: using '" << tor_datadir << "' as tor datadir";
        return std::make_unique<tor_controller_impl>(socks5_port, tor_datadir);
    }

    tor_controller::tor_controller()
        : m_ctrl(make_controller(std::string()))
    {
    }

    tor_controller::~tor_controller() = default;

    void tor_controller::sleep()
    {
        std::lock_guard<std::mutex> _(m_ctrl_mutex);

        if (!m_ctrl) {
            return;
        }

        const std::string socks5_str = m_ctrl->wait_for_socks5(0, nullptr);
        m_socks5_port = socks5_str.empty() ? std::string{} : socks5_str.substr(LOCALHOST_SOCKS5_UNTIL_PORT.size());

        m_ctrl.reset();
    }

    void tor_controller::wakeup()
    {
        std::lock_guard<std::mutex> _(m_ctrl_mutex);

        if (!m_ctrl) {
            m_ctrl = make_controller(m_socks5_port);
        }
    }

    std::shared_ptr<tor_controller> tor_controller::get_shared_ref()
    {
        std::unique_lock<std::mutex> _{ s_inst_mutex };
        std::shared_ptr<tor_controller> shared = s_inst.lock();

        if (!shared) {
            GDK_RUNTIME_ASSERT(!json_get_value(gdk_config(), "tordir").empty());
            s_inst = shared = std::make_shared<tor_controller>();
        }

        return shared;
    }

    std::string tor_controller::wait_for_socks5(
        std::function<void(std::shared_ptr<tor_bootstrap_phase>)> phase_cb, uint32_t timeout)
    {
        // TODO: call phase_cb when sleeping (m_ctrl == null) to report it?

        std::lock_guard<std::mutex> _(m_ctrl_mutex);

        return m_ctrl.get() ? m_ctrl->wait_for_socks5(timeout, phase_cb) : std::string();
    }

} // namespace sdk
} // namespace ga
