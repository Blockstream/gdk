
#include <assert.h>
#include <stdio.h>
#include "gdk_rust.h"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	GDKRUST_json *example;
	GDKRUST_json *networks;
	char *str;

	GDKRUST_convert_string_to_json("{\"key\": \"value\"}", &example);
	GDKRUST_convert_json_to_string(example, &str);
	GDKRUST_destroy_json(example);

	printf("%s\n", str);
	GDKRUST_destroy_string(str);

	GDKRUST_get_networks(&networks);
	GDKRUST_convert_json_to_string(networks, &str);
	GDKRUST_destroy_json(networks);
	printf("%s\n", str);
	GDKRUST_destroy_string(str);

	return 0;
}

