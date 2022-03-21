#include "include/gdk.h"
#include "src/assertion.hpp"
#include <nlohmann/json.hpp>
#include <string.h>

// Tests for gdk exposed JSON functions
static const char* SAMPLE_JSON = "{"
                                 "    \"string_key\": \"string value\""
                                 "}";

int main()
{
    GA_json* json = NULL;
    char* str_out;

    GDK_RUNTIME_ASSERT(GA_convert_string_to_json(SAMPLE_JSON, &json) == GA_OK);

    str_out = nullptr;
    GDK_RUNTIME_ASSERT(GA_convert_json_value_to_string(json, "string_key", &str_out) == GA_OK);
    GDK_RUNTIME_ASSERT(str_out && !strcmp(str_out, "string value"));
    GA_destroy_string(str_out);

    str_out = nullptr;
    GDK_RUNTIME_ASSERT(GA_convert_json_value_to_string(json, "bad_key", &str_out) == GA_OK);
    GDK_RUNTIME_ASSERT(str_out && !*str_out);
    GA_destroy_string(str_out);

    GDK_RUNTIME_ASSERT(GA_destroy_json(json) == GA_OK);

    // Default-constructed JSON is both empty and null
    GDK_RUNTIME_ASSERT(nlohmann::json().empty());
    GDK_RUNTIME_ASSERT(nlohmann::json().is_null());

    // Empty init list constructed JSON is both empty but *not* null
    GDK_RUNTIME_ASSERT(nlohmann::json({}).empty());
    GDK_RUNTIME_ASSERT(!nlohmann::json({}).is_null());

    // JSON constructed from an empty object is empty but *not* null
    GDK_RUNTIME_ASSERT(nlohmann::json(nlohmann::json::object()).empty());
    GDK_RUNTIME_ASSERT(!nlohmann::json(nlohmann::json::object()).is_null());

    // Default-constructed JSON Object is empty but *not* null
    GDK_RUNTIME_ASSERT(nlohmann::json::object().empty());
    GDK_RUNTIME_ASSERT(!nlohmann::json::object().is_null());

    // Verify that an object with its keys erased is empty but *not* null
    auto obj = nlohmann::json::object();
    obj["foo"] = "bar";
    obj.erase("foo");
    GDK_RUNTIME_ASSERT(obj.empty());
    GDK_RUNTIME_ASSERT(!obj.is_null());

    // References to blank string values are not empty() and have a size() of 1
    // This is because the reference is to the holding json object, not the
    // string directly (you must convert to the string to check emptyness).
    const nlohmann::json string_test = { { "empty", std::string() } };
    GDK_RUNTIME_ASSERT(!string_test.at("empty").empty());
    GDK_RUNTIME_ASSERT(string_test.at("empty").size() == 1);
    // Operator [] is the same as at() in this regard
    GDK_RUNTIME_ASSERT(!string_test["empty"].empty());
    GDK_RUNTIME_ASSERT(string_test["empty"].size() == 1);

    // In contrast, references to arrays *are* empty, and of zero size
    const nlohmann::json array_test = { { "empty", nlohmann::json::array() } };
    GDK_RUNTIME_ASSERT(array_test.at("empty").empty());
    GDK_RUNTIME_ASSERT(array_test.at("empty").size() == 0);
    GDK_RUNTIME_ASSERT(array_test["empty"].empty());
    GDK_RUNTIME_ASSERT(array_test["empty"].size() == 0);

    return 0;
}
