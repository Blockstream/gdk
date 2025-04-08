package greenaddress

import (
	"encoding/json"
	"fmt"
	"log"
	"unsafe"
)

func ExampleGenerateMnemonic() {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		return
	}
	log.Printf("mnemnonic: %s", mnemonic)

	var rptr uintptr
	Validate_mnemonic(mnemonic, SwigcptrUint32_t((uintptr)(unsafe.Pointer(&rptr))))
	r := (int)(SwigcptrUint32_t(rptr))
	if r != GA_TRUE {
		return
	}

	mnemonic12, err := GenerateMnemonic12()
	if err != nil {
		return
	}
	log.Printf("mnemnonic12: %s", mnemonic12)

	var rptr12 uintptr
	Validate_mnemonic(mnemonic12, SwigcptrUint32_t((uintptr)(unsafe.Pointer(&rptr12))))
	r12 := (int)(SwigcptrUint32_t(rptr12))
	if r12 != GA_TRUE {
		return
	}
}

func ExampleConvertStringToJson() {
	jsonstr := `{"a":"b","c":{"d":["e","f"]}}`
	jsonobj, err := ConvertStringToJson(jsonstr)
	if err != nil {
		return
	}
	defer jsonobj.Destroy()

	comparestr, err := ConvertJsonToString(jsonobj)
	if err != nil {
		return
	}

	fmt.Printf("%s", comparestr)
}

func ExampleRegister_user() {
	// init, create session and connect
	jinit, err := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	if err != nil {
		return
	}
	defer jinit.Destroy()

	ok := Init(jinit)
	if ok != 0 {
		return
	}

	session, err := CreateSession()
	if err != nil {
		return
	}
	defer Destroy_session(session)

	jconn, err := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	if err != nil {
		return
	}
	defer jconn.Destroy()

	ok = Connect(session, jconn)
	if ok != 0 {
		return
	}
	defer Disconnect(session)

	hwjson, err := ConvertStringToJson("{}")
	if err != nil {
		return
	}
	defer hwjson.Destroy()

	var authhptr uintptr
	ok = Register_user(session, hwjson, "set mnemonic here", SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authhptr))))
	if ok != 0 {
		return
	}
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authhptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseString, _ := ConvertJsonToString(SwigcptrStruct_SS_GA_json(response))

	fmt.Println(responseString)
}

func ExampleGetBalance() {
	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jrequest, _ := ConvertStringToJson("{\"subaccount\":0,\"num_confs\":0}")
	defer jrequest.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, err := CreateSession()
	defer Destroy_session(session)
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	defer jconn.Destroy()
	ok := Connect(session, jconn)
	if ok != 0 {
		return
	}
	defer Disconnect(session)

	var loginptr uintptr
	_ = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&loginptr))))
	loginhandler := SwigcptrStruct_SS_GA_auth_handler(loginptr)
	defer Destroy_auth_handler(loginhandler)

	var authptr uintptr
	_ = Get_balance(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptr))))
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	_ = Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseJSON := SwigcptrStruct_SS_GA_json(response)
	defer Destroy_json(responseJSON)
	responseString, err := ConvertJsonToString(responseJSON)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleGetReceiveAddress() {
	// init, create session and connect
	jinit, err := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	if err != nil {
		return
	}
	defer jinit.Destroy()

	ok := Init(jinit)
	if ok != 0 {
		return
	}

	session, err := CreateSession()
	if err != nil {
		return
	}
	defer Destroy_session(session)

	jconn, err := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	if err != nil {
		return
	}
	defer jconn.Destroy()

	ok = Connect(session, jconn)
	if ok != 0 {
		return
	}
	defer Disconnect(session)

	jrequest, err := ConvertStringToJson("{\"subaccount\":0}")
	if err != nil {
		return
	}
	defer jrequest.Destroy()

	hwjson, err := ConvertStringToJson("{}")
	if err != nil {
		return
	}
	defer hwjson.Destroy()
	credjson, err := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	if err != nil {
		return
	}
	defer credjson.Destroy()

	var authptrLogin uintptr
	ok = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	if ok != 0 {
		return
	}
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var authptrGetaddr, returnptr uintptr
	ok = Get_receive_address(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrGetaddr))))
	if ok != 0 {
		return
	}
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptrGetaddr)
	defer Destroy_auth_handler(authhandler)

	status := SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&returnptr)))
	ok = Auth_handler_get_status(authhandler, &status)
	if ok != 0 {
		return
	}
	returnobj := SwigcptrStruct_SS_GA_json(returnptr)
	defer Destroy_json(returnobj)
	returnstr, err := ConvertJsonToString(returnobj)
	if err != nil {
		return
	}

	fmt.Println(returnstr)
}

func ExampleGet_transactions() {
	// init, create session and connect
	jinit, err := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	if err != nil {
		return
	}
	defer jinit.Destroy()

	ok := Init(jinit)
	if ok != 0 {
		return
	}
	session, err := CreateSession()
	if err != nil {
		return
	}
	defer Destroy_session(session)

	jconn, err := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	if err != nil {
		return
	}
	defer jconn.Destroy()

	ok = Connect(session, jconn)
	if ok != 0 {
		return
	}
	defer Disconnect(session)

	jrequest, err := ConvertStringToJson("{\"subaccount\":0,\"first\":0,\"count\":30}")
	if err != nil {
		return
	}
	defer jrequest.Destroy()

	hwjson, err := ConvertStringToJson("{}")
	if err != nil {
		return
	}
	defer hwjson.Destroy()
	credjson, err := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	if err != nil {
		return
	}
	defer credjson.Destroy()

	var authptrLogin uintptr
	ok = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	if ok != 0 {
		return
	}
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var authptrGetaddr, returnptr uintptr
	ok = Get_transactions(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrGetaddr))))
	if ok != 0 {
		return
	}
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptrGetaddr)
	defer Destroy_auth_handler(authhandler)

	status := SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&returnptr)))
	ok = Auth_handler_get_status(authhandler, &status)
	if ok != 0 {
		return
	}
	returnobj := SwigcptrStruct_SS_GA_json(returnptr)
	defer Destroy_json(returnobj)
	responseString, err := ConvertJsonToString(returnobj)
	if err != nil {
		return
	}

	fmt.Println(responseString)
}

func ExampleGet_transaction_details() {
	// init, create session and connect
	jinit, err := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	if err != nil {
		return
	}
	defer jinit.Destroy()

	ok := Init(jinit)
	if ok != 0 {
		return
	}
	session, err := CreateSession()
	if err != nil {
		return
	}
	defer Destroy_session(session)

	jconn, err := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	if err != nil {
		return
	}
	defer jconn.Destroy()

	ok = Connect(session, jconn)
	if ok != 0 {
		return
	}
	defer Disconnect(session)

	jrequest, err := ConvertStringToJson("{\"subaccount\":0,\"first\":0,\"count\":30}")
	if err != nil {
		return
	}
	defer jrequest.Destroy()

	hwjson, err := ConvertStringToJson("{}")
	if err != nil {
		return
	}
	defer hwjson.Destroy()
	credjson, err := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	if err != nil {
		return
	}
	defer credjson.Destroy()

	var authptrLogin uintptr
	ok = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	if ok != 0 {
		return
	}
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var txjsonptr uintptr
	ok = Get_transaction_details(session, "c0cdaefefdf895e8de509924fb7fe4b8eb8063126193869fd91154717c321a4c", SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&txjsonptr))))
	if ok != 0 {
		return
	}
	txjson := SwigcptrStruct_SS_GA_auth_handler(txjsonptr)
	defer Destroy_json(txjson)
	txstr, err := ConvertJsonToString(txjson)
	if err != nil {
		return
	}

	fmt.Println(txstr)
}

func ExampleGetSubaccounts() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, err := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	if err != nil {
		log.Println("got error")
		return
	}
	defer jinit.Destroy()

	ok := Init(jinit)
	if ok != 0 {
		log.Println("not ok")
		return
	}

	session, err := CreateSession()
	if err != nil {
		log.Println("got error")
		return
	}
	defer Destroy_session(session)

	jconn, err := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	if err != nil {
		log.Println("got error")
		return
	}
	defer jconn.Destroy()

	ok = Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

	hwjson, _ := ConvertStringToJson("{}")
	if err != nil {
		log.Println("got error")
		return
	}
	defer hwjson.Destroy()
	credjson, err := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	if err != nil {
		log.Println("got error")
		return
	}
	defer credjson.Destroy()

	var authptrLogin uintptr
	ok = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	if ok != 0 {
		log.Println("not ok")
		return
	}
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var authptrGetaddr, returnptr uintptr
	ok = Get_subaccounts(session, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrGetaddr))))
	if ok != 0 {
		log.Println("not ok")
		return
	}
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptrGetaddr)
	defer Destroy_auth_handler(authhandler)

	status := SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&returnptr)))
	ok = Auth_handler_get_status(authhandler, &status)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	returnobj := SwigcptrStruct_SS_GA_json(returnptr)
	defer Destroy_json(returnobj)
	responseString, err := ConvertJsonToString(returnobj)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleGet_unspent_outputs() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jrequest, _ := ConvertStringToJson("{\"subaccount\":0,\"num_confs\":0}")
	defer jrequest.Destroy()
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	defer jconn.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, _ := CreateSession()
	defer Destroy_session(session)
	ok := Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

	var authptrLogin uintptr
	_ = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var authptr uintptr
	_ = Get_unspent_outputs(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptr))))
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	_ = Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseJSON := SwigcptrStruct_SS_GA_json(response)
	defer Destroy_json(responseJSON)
	responseString, err := ConvertJsonToString(responseJSON)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleCreate_transaction() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	defer jconn.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, _ := CreateSession()
	defer Destroy_session(session)
	ok := Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

	var authptrLogin uintptr
	_ = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	// get utxos
	jrequest, _ := ConvertStringToJson("{\"subaccount\":0,\"num_confs\":0}")
	var utxosp uintptr
	_ = Get_unspent_outputs(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&utxosp))))
	utxoauth := SwigcptrStruct_SS_GA_auth_handler(utxosp)
	defer Destroy_auth_handler(utxoauth)

	var utxoresp uintptr
	_ = Auth_handler_get_status(utxoauth, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&utxoresp))))
	defer Destroy_json(SwigcptrStruct_SS_GA_json(utxoresp))
	utxoss, err := ConvertJsonToString(SwigcptrStruct_SS_GA_json(utxoresp))
	defer jrequest.Destroy()

	utxomap := struct {
		Result struct {
			UnspentOutputs map[string]interface{} `json:"unspent_outputs"`
		}
	}{
		Result: struct {
			UnspentOutputs map[string]interface{} `json:"unspent_outputs"`
		}{
			UnspentOutputs: make(map[string]interface{})}}
	json.Unmarshal([]byte(utxoss), &utxomap)
	unspents, _ := json.Marshal(utxomap.Result.UnspentOutputs)

	jrequest, err = ConvertStringToJson(fmt.Sprintf(`
	{
		"subaccount": 0,
		"addressees": [{
			"address": "tex1qqum8v25az86e4004e9rjg8xp7vxd6psc37x2f42rdlz3q5rhs3vs6gm7kj",
			"satoshi": 10,
			"asset_id": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"
		}],
		"utxos": %s
	}`, string(unspents)))
	if err != nil {
		log.Printf("error: %v", err)
		return
	}
	defer jrequest.Destroy()

	var authptr uintptr
	_ = Create_transaction(session, jrequest, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptr))))
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	_ = Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseJSON := SwigcptrStruct_SS_GA_json(response)
	defer Destroy_json(responseJSON)
	responseString, err := ConvertJsonToString(responseJSON)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleGet_subaccount() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	defer jconn.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, _ := CreateSession()
	defer Destroy_session(session)
	ok := Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

	var authptrLogin uintptr
	_ = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	subaccount := 0
	var authptr uintptr
	_ = Get_subaccount(session, SwigcptrUint32_t((uintptr)(unsafe.Pointer(&subaccount))), SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptr))))
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	_ = Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseJSON := SwigcptrStruct_SS_GA_json(response)
	defer Destroy_json(responseJSON)
	responseString, err := ConvertJsonToString(responseJSON)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleSet_notification_handler() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":false,"user_agent":""}`)
	defer jconn.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "own 24 word mnemonic","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, _ := CreateSession()
	defer Destroy_session(session)

	// this could be any context, handle the context by changing the go_handler func
	ctx := "ctx"
	ok := SetSampleNotificationHandler(session, (uintptr)(unsafe.Pointer(&ctx)))
	if ok != 0 {
		log.Println("not ok")
		return
	}

	ok = Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

}

func ExampleGet_subaccounts() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// init, create session and connect
	jinit, _ := ConvertStringToJson(`{"datadir": "/tmp/gdk"}`)
	defer jinit.Destroy()
	jconn, _ := ConvertStringToJson(`{"name":"testnet-liquid","log_level":"debug","use_tor":true,"user_agent":""}`)
	defer jconn.Destroy()
	hwjson, _ := ConvertStringToJson("{}")
	defer hwjson.Destroy()
	credjson, _ := ConvertStringToJson(`{"mnemonic": "set mnemonic here","password": ""}`)
	defer credjson.Destroy()

	_ = Init(jinit)
	session, _ := CreateSession()
	defer Destroy_session(session)
	ok := Connect(session, jconn)
	if ok != 0 {
		log.Println("not ok")
		return
	}
	defer Disconnect(session)

	var authptrLogin uintptr
	_ = Login_user(session, hwjson, credjson, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptrLogin))))
	authhandlerLogin := SwigcptrStruct_SS_GA_auth_handler(authptrLogin)
	defer Destroy_auth_handler(authhandlerLogin)

	var authptr uintptr
	_ = Get_subaccounts(session, SwigcptrStruct_SS_GA_auth_handler((uintptr)(unsafe.Pointer(&authptr))))
	authhandler := SwigcptrStruct_SS_GA_auth_handler(authptr)
	defer Destroy_auth_handler(authhandler)

	var response uintptr
	_ = Auth_handler_get_status(authhandler, SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&response))))
	responseJSON := SwigcptrStruct_SS_GA_json(response)
	defer Destroy_json(responseJSON)
	responseString, err := ConvertJsonToString(responseJSON)
	if err != nil {
		log.Println("got error")
		return
	}

	fmt.Println(responseString)
}

func ExampleGet_networks() {
	var output uintptr
	Get_networks(SwigcptrStruct_SS_GA_json((uintptr)(unsafe.Pointer(&output))))
	outputJSON := SwigcptrStruct_SS_GA_json(output)
	defer Destroy_json(outputJSON)
}
