%module GDK
%{
#include "../../include/gdk.h"
#include "../../include/greenlight.h"
#include <limits.h>

/* Make local functions visible to the O/S for better JVM stack traces */
#ifdef NDEBUG
#define LOCALFUNC SWIGEXPORT
#else
#define LOCALFUNC static
#endif

static const char* SDK_CLASS  = "com/blockstream/libgreenaddress/GDK";
static const char* TO_OBJECT_METHOD_NAME = "toJSONObject";
static const char* TO_OBJECT_METHOD_ARGS = "(Ljava/lang/String;)Ljava/lang/Object;";
static const char* TO_STRING_METHOD_NAME = "toJSONString";
static const char* TO_STRING_METHOD_ARGS = "(Ljava/lang/Object;)Ljava/lang/String;";
static const char* NOTIFY_METHOD_NAME = "callNotificationHandler";
static const char* NOTIFY_METHOD_ARGS = "(Ljava/lang/Object;Ljava/lang/Object;)V";
static const char* OBJ_CLASS  = "com/blockstream/libgreenaddress/GDK$Obj";

static JavaVM* g_jvm;

static jclass g_gasdk;
static jmethodID g_gasdk_toJSONObject;
static jmethodID g_gasdk_toJSONString;
static jmethodID g_gasdk_callNotificationHandler;

static jclass g_gasdk_obj;
static jmethodID g_gasdk_obj_ctor;
static jmethodID g_gasdk_obj_get_id;
static jmethodID g_gasdk_obj_get;

LOCALFUNC jclass jni_get_class(JNIEnv *jenv, const char* name) {
    jclass cls;
    jobject obj = NULL;

    cls = (*jenv)->FindClass(jenv, name);
    if (!(*jenv)->ExceptionOccurred(jenv) && cls)
        obj = (*jenv)->NewGlobalRef(jenv, cls);
    return (jclass) obj;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* jvm, void* reserved)
{
    JNIEnv* jenv;
    (void)reserved;

    if ((*jvm)->GetEnv(jvm, (void**) &jenv, JNI_VERSION_1_6))
        return -1;

    /* Cache our objects/methods for callbacks/calling */
    if (!(g_gasdk = jni_get_class(jenv, SDK_CLASS)))
        return -1;

    if (!(g_gasdk_obj = jni_get_class(jenv, OBJ_CLASS)))
        return -1;

    g_gasdk_toJSONObject = (*jenv)->GetStaticMethodID(jenv, g_gasdk, TO_OBJECT_METHOD_NAME, TO_OBJECT_METHOD_ARGS);
    g_gasdk_toJSONString = (*jenv)->GetStaticMethodID(jenv, g_gasdk, TO_STRING_METHOD_NAME, TO_STRING_METHOD_ARGS);
    g_gasdk_callNotificationHandler = (*jenv)->GetStaticMethodID(jenv, g_gasdk, NOTIFY_METHOD_NAME, NOTIFY_METHOD_ARGS);
    g_gasdk_obj_ctor = (*jenv)->GetMethodID(jenv, g_gasdk_obj, "<init>", "(JI)V");
    g_gasdk_obj_get_id = (*jenv)->GetMethodID(jenv, g_gasdk_obj, "get_id", "()I");
    g_gasdk_obj_get = (*jenv)->GetMethodID(jenv, g_gasdk_obj, "get", "()J");

    g_jvm = jvm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM* jvm, void* reserved)
{
    JNIEnv* jenv;
    (void)reserved;

    if (!g_jvm || (*jvm)->GetEnv(jvm, (void**) &jenv, JNI_VERSION_1_6))
        return;

    (*jenv)->DeleteGlobalRef(jenv, g_gasdk);
    (*jenv)->DeleteGlobalRef(jenv, g_gasdk_obj);
    g_jvm = NULL;
}

#define GDK_SWIG_SESSION_ID 1
#define GDK_SWIG_AUTH_HANDLER_ID 2

LOCALFUNC unsigned char* malloc_or_throw(JNIEnv *jenv, size_t len) {
    unsigned char *p = (unsigned char *)malloc(len);
    if (!p) {
        SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "Out of memory");
    }
    return p;
}

LOCALFUNC int check_result(JNIEnv *jenv, int result, const char* msg)
{
    char buffer[60];
    GA_json *details = NULL;
    char *text = NULL;

    if (result != GA_OK) {
        /* TODO: We could create a custom exception here with all details */
        if (GA_get_thread_error_details(&details) == GA_OK) {
            GA_convert_json_value_to_string(details, "details", &text);
        }
        if (!text || !*text) {
            snprintf(buffer, sizeof(buffer), "GDK_ERROR_CODE %d %s", result, msg);
        }
        SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException,
                                text && *text ? text : buffer);
        GA_destroy_json(details);
        GA_destroy_string(text);
    }
    return result;
}

LOCALFUNC uint32_t uint32_cast(JNIEnv *jenv, jlong value) {
    if (value < 0 || value > UINT_MAX)
        SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Invalid uint32_t");
    return (uint32_t)value;
}

/* Create and return a native json object from GA_json */
LOCALFUNC jobject create_json(JNIEnv *jenv, void *p) {
    char* json_cstring = NULL;
    jstring json_string = NULL;
    jobject json_obj = NULL;

    if (!g_jvm)
        return NULL;

    if (!(*jenv)->ExceptionOccurred(jenv)) {
        if (GA_convert_json_to_string((GA_json *)p, &json_cstring) != GA_OK) {
            SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, "GA_json");
            return NULL;
        }

        json_string = (*jenv)->NewStringUTF(jenv, json_cstring);
        GA_destroy_string(json_cstring);
        if (!(*jenv)->ExceptionOccurred(jenv) && json_string) {
            json_obj = (*jenv)->CallStaticObjectMethod(jenv, g_gasdk, g_gasdk_toJSONObject, json_string);
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionDescribe(jenv);
        }
    }

    GA_destroy_json((GA_json *)p);
    return json_obj;
}

/* Create and return a GA_json from a native json object */
LOCALFUNC void* get_json_or_throw(JNIEnv *jenv, jobject json_obj) {
    const char* json_cstring;
    GA_json* json = NULL;
    jstring json_string;

    if (!g_jvm)
        return NULL;

    json_string = (*jenv)->CallStaticObjectMethod(jenv, g_gasdk, g_gasdk_toJSONString, json_obj);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        return NULL;
    }
    if (!(json_cstring = (*jenv)->GetStringUTFChars(jenv, json_string, NULL)))
        return NULL;
    GA_convert_string_to_json(json_cstring, &json);
    (*jenv)->ReleaseStringUTFChars(jenv, json_string, json_cstring);
    if (!json)
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, "GA_json");
    return json;
}

typedef struct notification_context
{
    struct GA_session* m_session;
    jobject m_session_obj;
} notify_t;

/* Call any registered notification handler */
LOCALFUNC void notification_handler(void* context_p, GA_json* details)
{
    JNIEnv *jenv;
    notify_t* n = (notify_t*) context_p;
    jobject json_obj;
    int status;

    if (!g_jvm || !context_p || !n->m_session)
        return; /* Called after un-registering */

    status = (*g_jvm)->GetEnv(g_jvm, (void**) &jenv, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, (void**) &jenv, NULL))
            return;
    } else if (status != JNI_OK)
        return;

    if (!details) {
        /* Un-registering */
        (*jenv)->DeleteGlobalRef(jenv, n->m_session_obj);
        memset(n, 0, sizeof(*n));
        free(n);
        goto end;
    }

    json_obj = create_json(jenv, (void *)details);
    if (!(*jenv)->ExceptionOccurred(jenv) && json_obj)
        (*jenv)->CallStaticVoidMethod(jenv, g_gasdk, g_gasdk_callNotificationHandler, n->m_session_obj, json_obj);

end:
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }
    if (status == JNI_EDETACHED)
        (*g_jvm)->DetachCurrentThread(g_jvm);
}

/* Create and return a java object to hold an opaque pointer */
LOCALFUNC jobject create_obj(JNIEnv *jenv, void *p, int id) {
    jobject obj = 0;

    if (!g_jvm)
        return NULL;

    if (!(obj = (*jenv)->NewObject(jenv, g_gasdk_obj, g_gasdk_obj_ctor, (jlong)(uintptr_t)p, id)))
        return NULL;

    if (id == GDK_SWIG_SESSION_ID) {
        /* Set the notification handler for the session after creating it */
        notify_t* n = (notify_t*)malloc_or_throw(jenv, sizeof(notify_t));
        if (!n)
            return NULL;
        n->m_session = (struct GA_session*) p;
        n->m_session_obj = (*jenv)->NewGlobalRef(jenv, obj);
        if (!n->m_session_obj) {
            free(n);
            return NULL;
        }
        /* FIXME: Error handling if this call fails */
        GA_set_notification_handler(n->m_session, notification_handler, n);
        return n->m_session_obj;
    }
    return obj;
}

/* Fetch an opaque pointer from a java object */
LOCALFUNC void *get_obj(JNIEnv *jenv, jobject obj, int id) {
    void *ret;

    if (!g_jvm || !obj)
        return NULL;

    if ((*jenv)->CallIntMethod(jenv, obj, g_gasdk_obj_get_id) != id ||
        (*jenv)->ExceptionOccurred(jenv))
        return NULL;
    ret = (void *)(uintptr_t)((*jenv)->CallLongMethod(jenv, obj, g_gasdk_obj_get));
    return (*jenv)->ExceptionOccurred(jenv) ? NULL : ret;
}

LOCALFUNC void* get_obj_or_throw(JNIEnv *jenv, jobject obj, int id, const char *name) {
    void *ret = get_obj(jenv, obj, id);
    if (!ret)
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, name);
    return ret;
}

LOCALFUNC jbyteArray create_array(JNIEnv *jenv, const unsigned char* p, size_t len) {
    jbyteArray ret = (*jenv)->NewByteArray(jenv, len);
    if (ret) {
        (*jenv)->SetByteArrayRegion(jenv, ret, 0, len, (const jbyte*)p);
    }
    return ret;
}

%}

%javaconst(1);
%ignore GA_destroy_string;

%pragma(java) jniclasscode=%{
    private static boolean loadLibrary() {
        try {
            System.loadLibrary("greenaddress");
            return true;
        } catch (final UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            return false;
        }
    }

    private static final boolean enabled = loadLibrary();
    public static boolean isEnabled() {
        return enabled;
    }

    // JSON conversion
    public interface JSONConverter {
       Object toJSONObject(final String jsonString);
       String toJSONString(final Object jsonObject);
    }

    private static JSONConverter mJSONConverter = null;

    private static Object toJSONObject(final String jsonString) {
        return mJSONConverter.toJSONObject(jsonString);
    }

    private static String toJSONString(final Object jsonObject) {
        return mJSONConverter.toJSONString(jsonObject);
    }

    public static void init(JSONConverter _JSONConverter, final Object config) {
        mJSONConverter = _JSONConverter;
        _internal_GA_init(config);
    }

    // Notifications
    public interface NotificationHandler {
       void onNewNotification(final Object session, final Object jsonObject);
    }

    private static NotificationHandler mNotificationHandler = null;

    public static void setNotificationHandler(final NotificationHandler notificationHandler) {
        mNotificationHandler = notificationHandler;
    }

    private static void callNotificationHandler(final Object session, final Object jsonObject) {
        if (mNotificationHandler != null)
            mNotificationHandler.onNewNotification(session, jsonObject);
    }

    static final class Obj {
        private final transient long ptr;
        private final int id;
        private Obj(final long ptr, final int id) { this.ptr = ptr; this.id = id; }
        private long get() { return ptr; }
        private int get_id() { return id; }
    }
%}

/* Raise an exception whenever a function fails */
%exception {
    $action
    check_result(jenv, result, "$name");
}

/* Don't use our int return value except for exception checking */
%typemap(out) int %{
%}
%typemap(in,noblock=1,numinputs=0) char** output(char* temp = 0) {
      $1 = &temp;
}
%typemap(argout, noblock=1) (char** output) {
    if ($1) {
        if (!(*jenv)->ExceptionOccurred(jenv))
            $result = (*jenv)->NewStringUTF(jenv, *$1);
        else
            $result = NULL;
        GA_destroy_string(*$1);
    } else {
        $result = NULL;
    }
}
/* Output strings are converted to native Java strings and returned */
%typemap(in,noblock=1,numinputs=0) char **(char *temp = 0) {
    $1 = &temp;
}
%typemap(argout,noblock=1) (char **) {
    if ($1) {
        if (!(*jenv)->ExceptionOccurred(jenv))
            $result = (*jenv)->NewStringUTF(jenv, *$1);
        else
            $result = NULL;
        GA_destroy_string(*$1);
    } else
        $result = NULL;
}
/* uint32_t input arguments are taken as longs and cast with range checking */
%typemap(in) uint32_t {
    $1 = uint32_cast(jenv, $input);
}

/* uint32_t output pointer arguments are returned as the function return value */
%typemap(in,noblock=1,numinputs=0) uint32_t* (uint32_t val32_out = 0) {
    $1 = ($1_ltype)&val32_out;
}
%typemap(argout,noblock=1) (uint32_t*) {
    if (!(*jenv)->ExceptionOccurred(jenv)) {
        $result = *$1;
    }
}

/* uint64_t input arguments are taken as longs and cast unchecked. This means
 * callers need to take care with treating negative values correctly */
%typemap(in) uint64_t {
    $1 = (uint64_t)($input);
}

/* JSON */
%typemap(in, numinputs=0) GA_json** (GA_json* w) {
    w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) GA_json** {
    if (*$1) {
        $result = create_json(jenv, *$1);
    }
}
%typemap(in) GA_json* {
    $1 = (GA_json*) get_json_or_throw(jenv, $input);
    if (!$1) {
        return $null;
    }
}
%typemap(jtype) GA_json* "Object"
%typemap(jni) GA_json* "jobject"

/* Opaque structures */
%define %java_struct(NAME, ID)
%typemap(in, numinputs=0) NAME** (NAME* w) {
    w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) NAME** {
    if (*$1) {
        $result = create_obj(jenv, *$1, ID);
    }
}
%typemap(in) NAME* {
    $1 = (NAME*) get_obj_or_throw(jenv, $input, ID, "NAME");
    if (!$1) {
        return $null;
    }
}
%typemap(jtype) NAME* "Object"
%typemap(jni) NAME* "jobject"
%enddef

%define %java_opaque_struct(NAME, ID)
%java_struct(struct NAME, ID)
%enddef

/* Change a functions return type to match its output type mapping */
%define %return_decls(FUNC, JTYPE, JNITYPE)
%typemap(jstype) int FUNC "JTYPE"
%typemap(jtype) int FUNC "JTYPE"
%typemap(jni) int FUNC "JNITYPE"
%rename("%(strip:[GA_])s") FUNC;
%enddef

%define %internal_returns_void__(FUNC)
%return_decls(FUNC, void, void)
%rename("_internal_%s") FUNC;
%enddef

%define %returns_void__(FUNC)
%return_decls(FUNC, void, void)
%enddef
%define %returns_uint32(FUNC)
%return_decls(FUNC, long, jlong)
%enddef
%define %returns_struct(FUNC, STRUCT)
%return_decls(FUNC, Object, jobject)
%enddef
%define %returns_string(FUNC)
%return_decls(FUNC, String, jstring)
%enddef
%define %returns_array_(FUNC, ARRAYARG, LENARG, LEN)
%return_decls(FUNC, byte[], jbyteArray)
%exception FUNC {
    int skip = 0;
    jresult = NULL;
    if (!jarg ## ARRAYARG) {
        arg ## LENARG = LEN;
        arg ## ARRAYARG = malloc_or_throw(jenv, LEN);
        if (!arg ## ARRAYARG) {
            skip = 1; /* Exception set by malloc_or_throw */
        }
    }
    if (!skip) {
        $action
        if (check_result(jenv, result, "$name") == GA_OK && !jarg ## ARRAYARG) {
            jresult = create_array(jenv, arg ## ARRAYARG, LEN);
        }
        if (!jarg ## ARRAYARG) {
            /* wally_bzero(arg ## ARRAYARG, LEN); */
            free(arg ## ARRAYARG);
        }
    }
}
%enddef

%java_opaque_struct(GA_session, GDK_SWIG_SESSION_ID)
%java_opaque_struct(GA_auth_handler, GDK_SWIG_AUTH_HANDLER_ID)

%internal_returns_void__(GA_init)
%returns_struct(GA_ack_system_message, GA_auth_handler)
%returns_string(GA_broadcast_transaction)
%returns_void__(GA_connect)
%returns_struct(GA_convert_amount, GA_json)
%returns_string(GA_convert_json_to_string)
%returns_string(GA_convert_json_value_to_string)
%returns_struct(GA_convert_string_to_json, GA_json)
%returns_struct(GA_create_session, GA_session)
%returns_struct(GA_create_transaction, GA_auth_handler)
%returns_struct(GA_create_swap_transaction, GA_auth_handler)
%returns_struct(GA_create_subaccount, GA_auth_handler)
%returns_struct(GA_complete_swap_transaction, GA_auth_handler)
%returns_struct(GA_decrypt_with_pin, GA_auth_handler)
%returns_void__(GA_destroy_session)
%returns_void__(GA_destroy_auth_handler)
%returns_void__(GA_destroy_json)
%returns_struct(GA_encrypt_with_pin, GA_auth_handler)
%returns_void__(GA_reconnect_hint)
%returns_struct(GA_get_proxy_settings, GA_json)
%returns_struct(GA_get_wallet_identifier, GA_json)
%returns_struct(GA_http_request, GA_json)
%returns_void__(GA_refresh_assets)
%returns_struct(GA_get_assets, GA_json)
%returns_struct(GA_validate_asset_domain_name, GA_json)
%returns_string(GA_generate_mnemonic)
%returns_string(GA_generate_mnemonic_12)
%returns_struct(GA_get_available_currencies, GA_json)
%returns_struct(GA_get_balance, GA_auth_handler)
%returns_struct(GA_get_credentials, GA_auth_handler)
%returns_struct(GA_get_fee_estimates, GA_json)
%returns_struct(GA_get_networks, GA_json)
%returns_struct(GA_get_previous_addresses, GA_auth_handler)
%returns_array_(GA_get_random_bytes, 2, 3, jarg1)
%returns_uint32(GA_get_uniform_uint32_t)
%returns_struct(GA_get_transaction_details, GA_json)
%returns_struct(GA_get_subaccounts, GA_auth_handler)
%returns_struct(GA_get_subaccount, GA_auth_handler)
%returns_void__(GA_rename_subaccount)
%returns_struct(GA_update_subaccount, GA_auth_handler)
%returns_string(GA_get_system_message)
%returns_struct(GA_get_transactions, GA_auth_handler)
%returns_struct(GA_get_twofactor_config, GA_json)
%returns_struct(GA_get_unspent_outputs, GA_auth_handler)
%returns_struct(GA_get_unspent_outputs_for_private_key, GA_json)
%returns_struct(GA_set_unspent_outputs_status, GA_auth_handler)
%returns_struct(GA_get_receive_address, GA_auth_handler)
%returns_struct(GA_login_user, GA_auth_handler)
%returns_void__(GA_register_network)
%returns_struct(GA_register_user, GA_auth_handler)
%returns_struct(GA_remove_account, GA_auth_handler)
%returns_void__(GA_send_nlocktimes)
%returns_struct(GA_set_csvtime, GA_auth_handler)
%returns_struct(GA_set_nlocktime, GA_auth_handler)
%returns_struct(GA_send_transaction, GA_auth_handler)
%returns_void__(GA_disable_all_pin_logins)
%returns_void__(GA_set_transaction_memo)
%returns_void__(GA_set_watch_only)
%returns_string(GA_get_watch_only_username)
%returns_struct(GA_sign_transaction, GA_auth_handler)
%returns_struct(GA_psbt_sign, GA_auth_handler)
%returns_struct(GA_psbt_get_details, GA_auth_handler)
%returns_void__(GA_auth_handler_call)
%returns_struct(GA_twofactor_cancel_reset, GA_auth_handler)
%returns_struct(GA_twofactor_reset, GA_auth_handler)
%returns_struct(GA_twofactor_undo_reset, GA_auth_handler)
%returns_struct(GA_twofactor_change_limits, GA_auth_handler)
%returns_struct(GA_change_settings_twofactor, GA_auth_handler)
%returns_struct(GA_auth_handler_get_status, GA_json)
%returns_struct(GA_change_settings, GA_auth_handler)
%returns_struct(GA_get_settings, GA_json)
%returns_void__(GA_auth_handler_request_code)
%returns_void__(GA_auth_handler_resolve_code)
%returns_uint32(GA_validate_mnemonic)
%returns_struct(GA_validate, GA_auth_handler)

%returns_struct(GA_gl_call, GA_json)

/* TODO
GA_convert_json_value_to_bool
GA_convert_json_value_to_uint32
GA_convert_json_value_to_uint64
GA_destroy_string
GA_subscribe_to_topic_as_json
*/

%include "../include/gdk.h"
