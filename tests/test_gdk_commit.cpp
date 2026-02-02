#include "assertion.hpp"
#include "version.h"

#include <algorithm>
#include <functional>
#include <locale>
#include <string>

int main()
{
    std::string sha = GDK_COMMIT;
    GDK_RUNTIME_ASSERT(sha.length() == 8);
    std::locale loc;
    std::function<bool(char)> isalnum = std::bind(std::isalnum<char>, std::placeholders::_1, loc);
    GDK_RUNTIME_ASSERT(std::all_of(sha.cbegin(), sha.cend(), isalnum));
}
