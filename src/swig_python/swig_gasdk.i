/*
  The automatic module importing varies between Swig3 and Swig4.
  Make explicit so should work for both versions.
  (Basically the swig3 version).

  NOTE:
  The behaviour of pybuffer_binary varies wrt a Py_None argument between Swig3
  (raises TypeError) and Swig4 (passes through as NULL) - we don't seem to use
  it here so shouldn't be a problem, but if we need it in future there are
  explicit implementations of 'nullable' and 'non-null' macros in libwally-core
  providing consistent behaviour across swig versions - copy those if required.
*/
%define MODULEIMPORT
"
def swig_import_helper():
    import importlib
    pkg = __name__.rpartition('.')[0]
    mname = '.'.join((pkg, '$module')).lstrip('.')
    try:
        return importlib.import_module(mname)
    except ImportError:
        return importlib.import_module('$module')
$module = swig_import_helper()
del swig_import_helper
"
%enddef
%module(moduleimport=MODULEIMPORT) greenaddress
%{
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#define SWIG_FILE_WITH_INIT
#include "../../include/gdk.h"
#include <limits.h>

static int gdk_throw(int result, const char* default_message)
{
    GA_json *details = NULL;
    char *text = NULL;

    /* TODO: We could create a custom exception here with all details */
    if (GA_get_thread_error_details(&details) == GA_OK) {
        GA_convert_json_value_to_string(details, "details", &text);
    }
    PyErr_SetString(PyExc_RuntimeError, text && *text ? text : default_message);
    GA_destroy_json(details);
    GA_destroy_string(text);
    return result;
}

static int check_result(int result)
{
    switch (result) {
    case GA_OK:
        break;
    case GA_ERROR:
        return gdk_throw(result, "Failed");
    case GA_RECONNECT:
        return gdk_throw(result, "Connection Error");
    case GA_SESSION_LOST:
        return gdk_throw(result, "Session Lost");
    case GA_TIMEOUT:
        return gdk_throw(result, "Operation Timed Out");
    case GA_NOT_AUTHORIZED:
        return gdk_throw(result, "Not Authorized");
    default:
        return gdk_throw(result, "Internal Error");
    }
    return result;
}

static int python_string_to_GA_json(PyObject* in, struct GA_json** out)
{
    *out = NULL;

#if PY_MAJOR_VERSION >= 3
    if (!PyUnicode_Check(in)) {
        PyErr_SetString(PyExc_TypeError, "Expected unicode argument for GA_json");
        return GA_ERROR;
    }

    PyObject* utf8_encoded = PyUnicode_AsEncodedString(in, "utf-8", "strict");
    if (!utf8_encoded) {
        PyErr_SetString(PyExc_UnicodeEncodeError, "Failed to encode GA_json string as utf-8");
        return GA_ERROR;
    }

    const char* utf8_ntbs = PyBytes_AsString(utf8_encoded);
#else
    if (!PyString_Check(in)) {
        PyErr_SetString(PyExc_TypeError, "Expected string argument for GA_json");
        return GA_ERROR;
    }

    const char* utf8_ntbs = PyString_AsString(in);
#endif

    const int result = check_result(GA_convert_string_to_json(utf8_ntbs, out));

#if PY_MAJOR_VERSION >= 3
    Py_DECREF(utf8_encoded);
#endif

    return result;
}

static void notification_handler(void* context_p, GA_json* details)
{
    PyObject* session_capsule = (PyObject*) context_p;
    PyObject* handler = NULL;
    char* json_cstring = NULL;

    if (!session_capsule)
        return;

    if (details) {
        if (GA_convert_json_to_string(details, &json_cstring) != GA_OK)
            return;
        GA_destroy_json(details);
    }

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    struct GA_session *p = (struct GA_session *)PyCapsule_GetPointer(session_capsule, "struct GA_session *");
    if (!p)
        goto end;

    if (!details) {
        /* Un-registering */
        GA_set_notification_handler(p, NULL, NULL);
        goto end;
    }

    handler = (PyObject *)PyCapsule_GetContext(session_capsule);
    if (!handler)
        goto end;

    PyObject *args = Py_BuildValue("(Os)", session_capsule, json_cstring);
    if (!args)
        goto end;

    PyEval_CallObject(handler, args);
    Py_DecRef(args);

end:
    SWIG_PYTHON_THREAD_END_BLOCK;

    if (json_cstring)
        GA_destroy_string(json_cstring);
}

static int _python_set_callback_handler(PyObject* obj, PyObject* arg)
{
    struct GA_session *p = (struct GA_session *)PyCapsule_GetPointer(obj, "struct GA_session *");
    if (!p)
        return GA_ERROR;

    if (PyCapsule_SetContext(obj, arg))
        return GA_ERROR;

    Py_IncRef(arg);
    if (GA_set_notification_handler(p, notification_handler, obj) != GA_OK)
        return GA_ERROR;

    Py_IncRef(obj);
    return GA_OK;
}

#define capsule_dtor(name, fn) static void destroy_##name(PyObject *obj) { \
    struct name *p = obj == Py_None ? NULL : (struct name *)PyCapsule_GetPointer(obj, "struct " #name " *"); \
    if (p) fn(p); }

capsule_dtor(GA_session, GA_destroy_session)
capsule_dtor(GA_auth_handler, GA_destroy_auth_handler)
%}

%include pybuffer.i
%include exception.i

/* Raise an exception whenever a function fails */
%exception{
    $action
    if (check_result(result))
        SWIG_fail;
};

/* Return None if we didn't throw instead of 0 */
%typemap(out) int %{
    Py_IncRef(Py_None);
    $result = Py_None;
%}

/* Output strings are converted to native python strings and returned */
%typemap(in, numinputs=0) char** (char* txt) {
   txt = NULL;
   $1 = ($1_ltype)&txt;
}
%typemap(argout) char** {
   if (*$1 != NULL) {
       Py_DecRef($result);
       $result = PyString_FromString(*$1);
       GA_destroy_string(*$1);
   }
}

/* Opaque types are passed along as capsules */
%define %py_struct(NAME)
%typemap(in, numinputs=0) struct NAME ** (struct NAME * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap (in) const struct NAME * {
    $1 = $input == Py_None ? NULL : PyCapsule_GetPointer($input, "struct NAME *");
}
%typemap (in) struct  NAME * {
    $1 = $input == Py_None ? NULL : PyCapsule_GetPointer($input, "struct NAME *");
}
%typemap(argout) struct NAME ** {
   if (*$1 != NULL) {
       Py_DecRef($result);
       $result = PyCapsule_New(*$1, "struct NAME *", destroy_ ## NAME);
   }
}
%enddef

%py_struct(GA_session);
%py_struct(GA_auth_handler);

/* GA_json is auto converted to/from python strings */
%typemap(in, numinputs=0) GA_json ** (GA_json * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap (in) const GA_json * {
    if (python_string_to_GA_json($input, &$1) != GA_OK)
        SWIG_fail;
}
%typemap (in) GA_json * {
    if (python_string_to_GA_json($input, &$1) != GA_OK)
        SWIG_fail;
}
%typemap (freearg) GA_json * {
    GA_destroy_json($1);
}
%typemap(argout) GA_json ** {
    if (*$1 != NULL) {
        Py_DecRef($result);
        char* str = NULL;
        if (check_result(GA_convert_json_to_string(*$1, &str)) != GA_OK) {
            SWIG_fail;
        }
        $result = PyString_FromString(str);
        GA_destroy_string(str);
        GA_destroy_json(*$1);
    }
}
%typemap(in, numinputs=0) uint32_t * (uint32_t temp) {
   $1 = &temp;
}
%typemap(argout) uint32_t* {
    Py_DecRef($result);
    $result = PyInt_FromLong(*$1);
}

/* Tell swig about uin32_t */
typedef unsigned int uint32_t;

%pybuffer_mutable_binary(unsigned char *output_bytes, size_t len)

%rename("%(regex:/^GA_(.+)/\\1/)s", %$isfunction) "";

%include "../include/gdk.h"

int _python_set_callback_handler(PyObject* obj, PyObject* arg);
