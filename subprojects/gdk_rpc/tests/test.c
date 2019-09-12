
#include <assert.h>
#include <stdio.h>
#include "gdk_rpc.h"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	GDKRPC_json *example;
	GDKRPC_json *networks;
	char *str;

	GDKRPC_convert_string_to_json("{\"key\": \"value\"}", &example);
	GDKRPC_convert_json_to_string(example, &str);
	GDKRPC_destroy_json(example);

	printf("%s\n", str);
	GDKRPC_destroy_string(str);

	GDKRPC_get_networks(&networks);
	GDKRPC_convert_json_to_string(networks, &str);
	GDKRPC_destroy_json(networks);
	printf("%s\n", str);
	GDKRPC_destroy_string(str);

	return 0;
}

