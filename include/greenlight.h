#ifndef GDK_GREENLIGHT_H
#define GDK_GREENLIGHT_H
#pragma once

#include "gdk.h"

#ifdef __cplusplus
extern "C" {
#endif

GDK_API int GA_gl_call(struct GA_session* session, const char* method, const GA_json* params, GA_json** output);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GREENLIGHT_H */
