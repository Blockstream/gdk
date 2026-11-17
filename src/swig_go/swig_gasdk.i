%module greenaddress

%typemap(gotype) (void* handler) "unsafe.Pointer";

%{
#include "../../include/gdk.h"

    void debug_print_chars(const char* in)
    {
        printf("%s\n", in);
        fflush(stdout);
    }

    void debug_print_GA_json(const GA_json* in)
    {
        printf("%p\n", in);
        fflush(stdout);
    }

    static int destroy_json(GA_json * json) { return GA_destroy_json(json); }

    static int string_to_json(char* in, struct GA_json** out) { return GA_convert_string_to_json(in, out); }
    
    static int json_to_string(const GA_json* json, char** out) { return GA_convert_json_to_string(json, out); }

    static int set_notification_handler(struct GA_session* session, void* handler, void* context)
    {
        return GA_set_notification_handler(session, handler, context);
    }
%}

/* strip GA from funciton names */
%rename("%(regex:/^GA_(.+)/\\1/)s", %$isfunction) "";

/* get strings of correct len back */
%typemap(argout) char** output
{
    if ($1 && *$1) {
        $input->n = strlen(*$1);
    }
}

%inline %{
extern void go_handler(void*, char*);

void handler_cgo(void* context, GA_json* details) {
    char* out = (char*) 0;
    int result;

    if (details) {
      result = json_to_string(details, &out);
      if (result != GA_OK) {
          return;
      }
    }
  
    go_handler(context, out);
    GA_destroy_json(details);
    GA_destroy_string(out);
}
%}

%ignore go_handler(void*, char**);
%ignore handler_cgo(void*, GA_json*);

extern int destroy_json(GA_json* json);
extern int string_to_json(char* in, struct GA_json** out);
extern int json_to_string(const GA_json* json, char** output);
extern int set_notification_handler(struct GA_session* session, void* handler, void* context);

%insert(cgo_comment_typedefs) %{
#cgo CFLAGS : -I ./src -I ./ -I ../../include
#cgo LDFLAGS: -L../../build-gcc/src -lgreenaddress -Wl,-rpath=../../build-gcc/src

typedef struct GA_json GA_json;
extern void handler_cgo(void*, GA_json*);
%}

%go_import("fmt")
%insert(go_wrapper) %{
func GenerateMnemonic() (string, error) {
    var mnemonic string
    r := Generate_mnemonic((*string)(unsafe.Pointer(&mnemonic)))
    if r != 0 {
        // should never be called
        return "", fmt.Errorf("could not genenerate mnemonic: %d", r)
    }
    return mnemonic, nil
}

func GenerateMnemonic12() (string, error) {
    var mnemonic string
    r := Generate_mnemonic_12((*string)(unsafe.Pointer(&mnemonic)))
    if r != 0 {
        return "", fmt.Errorf("could not genenerate mnemonic: %d", r)
    }
    return mnemonic, nil
}

func CreateSession() (Struct_SS_GA_session, error) {
    var p uintptr
    r := Create_session(SwigcptrStruct_SS_GA_session((uintptr)(unsafe.Pointer(&p))))
	if r != 0 {
		return nil, fmt.Errorf("could not convert json to string: %d", r)
	}
	return SwigcptrStruct_SS_GA_session(p), nil
}
%}

/* string/json converter */
%insert(go_wrapper) %{
type Destroyable_Struct_GA_json interface {
	Struct_SS_GA_json
	Destroy() int
}

type GAJson struct {
	s Struct_SS_GA_json
}

func (p GAJson) Swigcptr() uintptr {
	return p.s.Swigcptr()
}

func (p GAJson) Destroy() int {
	return Destroy_json(p)
}

func ConvertStringToJson(str string) (Destroyable_Struct_GA_json, error) {
    var p uintptr
	r := String_to_json(str, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&p))))
	if r != 0 {
		return nil, fmt.Errorf("could not convert string to json: %d", r)
	}
	return GAJson{s: SwigcptrStruct_SS_GA_json(p)}, nil
}

func ConvertJsonToString(json Struct_SS_GA_json) (string, error) {
    var s string
	r := Json_to_string(json, (*string)(unsafe.Pointer(&s)))
	if r != 0 {
		return "", fmt.Errorf("could not convert json to string: %d", r)
	}
	return s, nil
}

func RegisterUser()
%}

/* add simple notification handler */
%insert(go_wrapper) %{
//export go_handler
func go_handler(context unsafe.Pointer, details *C.char) {
    d := C.GoString(details)
    fmt.Printf("details: %s\n", d)
    fmt.Printf("context: %s\n", *(*string)(context))
}

func SetSampleNotificationHandler(session Struct_SS_GA_session, context uintptr) int {
    return Set_notification_handler(session, C.handler_cgo, context)
}
%}

%include "../../include/gdk.h"
%include "exception.i"
%exception
{
    try {
        $action;
    } catch (std::runtime_error& e) {
        _swig_gopanic(e.what());
    }
}