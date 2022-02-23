#ifndef GDK_GDK_RUST_H
#define GDK_GDK_RUST_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** A notification handler */
typedef void (*GDKRUST_notification_handler)(void *self_context, char *details);

/**
 * Create a new session.
 *
 * :param session: Destination for the resulting session.
 *|     Returned session should be freed using `GDKRUST_destroy_session`.
 */
int GDKRUST_create_session(void* session, const char* network);

int GDKRUST_call_session(void* session, const char *method, const char *input, char** output);

/**
 * A collection of stateless functions
 *
 * :param method: The function name.
 * :param input: The json input to pass to the function.
 * :param output: The json output, should be freed using `GDKRUST_destroy_string`.
 */
int GDKRUST_call(const char *method, const char *input, char** output);

/**
 * Set a handler to be called when notifications arrive.
 */
int GDKRUST_set_notification_handler(void* session, GDKRUST_notification_handler handler, void *self_context);

/**
 * Free a string returned by the api.
 *
 * :param str: The string to free.
 */
void GDKRUST_destroy_string(char* str);

/**
 * Free a session created by the api.
 *
 * :param session: The session to free.
 */
void GDKRUST_destroy_session(void* session);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GDK_RUST_H */
