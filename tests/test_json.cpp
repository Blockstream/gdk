#include "include/gdk.h"
#include "src/assertion.hpp"
#include <string.h>

// Tests for gdk exposed JSON functions
static const char *SAMPLE_JSON = "{"
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

    return 0;
}
