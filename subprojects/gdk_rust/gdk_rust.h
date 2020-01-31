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
typedef struct GDKRUST_session GDKRUST_session;

/** A Parsed JSON object */
typedef struct GDKRUST_json GDKRUST_json;

/** A notification handler */
typedef void (*GDKRUST_notification_handler)(void *self_context, GDKRUST_json* details);

/**
 * Create a new session.
 *
 * :param session: Destination for the resulting session.
 *|     Returned session should be freed using `GA_destroy_session`.
 */
GDK_API int GDKRUST_create_session(struct GDKRUST_session** session, GDKRUST_json *networks);

GDK_API int GDKRUST_call_session(struct GDKRUST_session* session, const char *method, const GDKRUST_json* input, GDKRUST_json** output);

#ifndef SWIG
/**
 * Set a handler to be called when notifications arrive.
 *
 * :param session: The server session to receive notifications for.
 * :param handler: The handler to receive notifications.
 * :param context: A context pointer to be passed to the handler.
 *
 * This must be called before GA_connect/GA_connect_with_proxy.
 * Notifications may arrive on different threads so the caller must ensure
 * that shared data is correctly locked within the handler.
 * The GDKRUST_json object passed to the caller must be destroyed by the caller
 * using GA_destroy_json. Failing to do so will result in memory leaks.
 * When the session is disconnected/destroyed, a final call will be made to
 * the handler with a :ref:`session-event` notification.
 *
 */

GDK_API int GDKRUST_set_notification_handler(struct GDKRUST_session* session, GDKRUST_notification_handler handler, void *self_context);

GDK_API int GDKRUST_convert_json_to_string(const GDKRUST_json* json, char** output);

GDK_API int GDKRUST_convert_string_to_json(const char* input, GDKRUST_json** output);
/**
 * Free a GDKRUST_json object.
 *
 * :param json: GDKRUST_json object to free.
 */
GDK_API int GDKRUST_destroy_json(GDKRUST_json* json);

/**
 * Free a string returned by the api.
 *
 * :param str: The string to free.
 */
GDK_API void GDKRUST_destroy_string(char* str);

#endif /* SWIG */


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GDK_RPC_H */
