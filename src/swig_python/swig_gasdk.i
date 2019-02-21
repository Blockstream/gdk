%module greenaddress
%{
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#define SWIG_FILE_WITH_INIT
#include "../../include/gdk.h"
#include <limits.h>

static int check_result(int result)
{
    switch (result) {
    case GA_OK:
        break;
    case GA_ERROR:
        PyErr_SetString(PyExc_RuntimeError, "Failed");
        break;
    case GA_NOT_AUTHORIZED:
        PyErr_SetString(PyExc_RuntimeError, "Not Authorized");
        break;
    default: /* FIXME */
        PyErr_SetString(PyExc_RuntimeError, "Connection Error");
        break;
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

static void notification_handler(void* context_p, const GA_json* details)
{
    PyObject* session_capsule = (PyObject*) context_p;
    PyObject* handler = NULL;
    char* json_cstring = NULL;

    if (!session_capsule)
        return;

    if (details) {
        if (GA_convert_json_to_string(details, &json_cstring) != GA_OK)
            return;
        GA_destroy_json((GA_json*) details);
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

%define %pybuffer_nullable_binary(TYPEMAP, SIZE)
%typemap(in) (TYPEMAP, SIZE)
  (int res, Py_ssize_t size = 0, const void *buf = 0) {
  if ($input == Py_None)
    $2 = 0;
  else {
    res = PyObject_AsReadBuffer($input, &buf, &size);
    if (res<0) {
      PyErr_Clear();
      %argument_fail(res, "(TYPEMAP, SIZE)", $symname, $argnum);
    }
    $1 = ($1_ltype) buf;
    $2 = ($2_ltype) (size / sizeof($*1_type));
  }
}
%enddef

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
