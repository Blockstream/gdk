#include "exception.hpp"
#include "autobahn_wrapper.hpp"
#include "ga_strings.hpp"
#include "logging.hpp"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>

namespace ga {
namespace sdk {
    namespace {
        static bool is_prevout_missing(const std::string& msg)
        {
            return boost::algorithm::starts_with(msg, "Missing prevout:");
        }
    } // namespace

    std::pair<std::string, std::string> get_error_details(const autobahn::call_error& e)
    {
        std::string message;
        const auto& args = e.get_args();
        if (args.size() >= 2) {
            std::string uri;
            args[0].convert(uri);
            if (boost::algorithm::starts_with(uri, "http://greenaddressit.com/error#")) {
                std::vector<std::string> ss;
                boost::algorithm::split(ss, uri, boost::is_any_of("#"));
                args[1].convert(message);
                return std::make_pair(ss.at(1), message);
            }
        }
        return std::make_pair(std::string(), std::string());
    }

    std::pair<std::string, std::string> remap_ga_server_error(const std::pair<std::string, std::string>& details)
    {
        if (is_prevout_missing(details.second)) {
            // Missing prevout indicates that a tx being bumped has been
            // confirmed and therefore the bump tx's previous output cannot
            // be found. Remap this to a more friendly error message.
            GDK_LOG_SEV(log_level::debug) << details.second;
            return std::make_pair(details.first, res::id_transaction_already_confirmed);
        } else if (details.second == "User not found or invalid password") {
            return std::make_pair(details.first, res::id_user_not_found_or_invalid);
        } else if (details.second == "Invalid PGP key") {
            return std::make_pair(details.first, res::id_invalid_pgp_key);
        }
        return details;
    }

} // namespace sdk
} // namespace ga
