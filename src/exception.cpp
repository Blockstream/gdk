#include "exception.hpp"
#include "boost_wrapper.hpp"

namespace ga {
namespace sdk {

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
} // namespace sdk
} // namespace ga
