#ifndef GDK_GDK_RPC_H
#define GDK_GDK_RPC_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#ifdef GDK_BUILD
#define GDK_API __declspec(dllexport)
#else
#define GDK_API
#endif
#elif defined(__GNUC__) && defined(GDK_BUILD)
#define GDK_API __attribute__((visibility("default")))
#else
#define GDK_API
#endif

/** A server session */
typedef void* GDKRUST_session;

/** A notification handler */
typedef void (*GDKRUST_notification_handler)(void *self_context, char *details);

/**
 * Create a new session.
 *
 * :param session: Destination for the resulting session.
 *|     Returned session should be freed using `GDKRUST_destroy_session`.
 */
GDK_API int GDKRUST_create_session(GDKRUST_session* session, const char* network);

GDK_API int GDKRUST_call_session(GDKRUST_session session, const char *method, const char *input, char** output);

GDK_API int GDKRUST_spv_verify_tx(const char *input);

/**
 * A collection of stateless functions
 *
 * :param method: The function name.
 * :param input: The json input to pass to the function.
 * :param output: The json output, should be freed using `GDKRUST_destroy_string`.
 */
GDK_API int GDKRUST_call(const char *method, const char *input, char** output);

#ifndef SWIG
/**
 * Set a handler to be called when notifications arrive.
 */
GDK_API int GDKRUST_set_notification_handler(GDKRUST_session session, GDKRUST_notification_handler handler, void *self_context);

/**
 * Free a string returned by the api.
 *
 * :param str: The string to free.
 */
GDK_API void GDKRUST_destroy_string(char* str);

/**
 * Free a session created by the api.
 *
 * :param session: The session to free.
 */
GDK_API void GDKRUST_destroy_session(GDKRUST_session session);

#endif /* SWIG */


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GDK_RPC_H */
