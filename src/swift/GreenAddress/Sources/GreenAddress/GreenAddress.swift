import Dispatch
import Foundation

import PromiseKit

import ga.sdk
import ga.wally

public enum GaError: Error {
    case GenericError
    case ReconnectError
    case SessionLost
    case TimeoutError
}

public enum Network: String {
    case MainNet = "mainnet"
    case TestNet = "testnet"
    case LocalTest = "localtest"
    case RegTest = "regtest"
}

fileprivate func errorWrapper(_ r: Int32) throws {
    guard r == GA_OK else {
        switch r {
            case GA_RECONNECT:
                throw GaError.ReconnectError
            case GA_SESSION_LOST:
                throw GaError.SessionLost
            case GA_TIMEOUT:
                throw GaError.TimeoutError
            default:
                throw GaError.GenericError
        }
    }
}

fileprivate func callWrapper(fun call: @autoclosure () -> Int32) throws {
    try errorWrapper(call())
}

fileprivate func convertJSONBytesToDict(_ input_bytes: UnsafeMutablePointer<Int8>) -> [String: Any]? {
    var dict: Any?
    let json = String(cString: input_bytes)
    if let data = json.data(using: .utf8) {
        do {
            dict = try JSONSerialization.jsonObject(with: data, options: [])
            if let object = dict as? [String: Any] {
                // json is a dictionary
                return object
            } else if let object = dict as? [Any] {
                // json is an array
                return ["array" : object]
            }
        }
        catch {
            return nil
        }
    }
    return dict as? [String: Any]
}

fileprivate func convertDictToJSON(dict: [String: Any]) throws -> OpaquePointer {
    let utf8_bytes = try JSONSerialization.data(withJSONObject: dict)
    var result: OpaquePointer? = nil
    let input = String(data: utf8_bytes, encoding: String.Encoding.utf8)!
    try callWrapper(fun: GA_convert_string_to_json(input, &result))
    return result!
}

fileprivate func convertOpaqueJsonToDict(o: OpaquePointer) throws -> [String: Any]? {
    var buff: UnsafeMutablePointer<Int8>? = nil
    defer {
        GA_destroy_string(buff)
        GA_destroy_json(o)
    }
    try callWrapper(fun: GA_convert_json_to_string(o, &buff))
    return convertJSONBytesToDict(buff!)
}

public func completion<Result>(onResult: @escaping (Result) -> Void, onError: @escaping (Error) -> Void) -> ((Result?, Error?) -> Void) {
    return { (maybeResult, maybeError) in
        if let result = maybeResult {
            onResult(result)
        } else if let error = maybeError {
            onError(error)
        } else {
            onError(GaError.GenericError)
        }
    }
}

// Dummy resolver for Hardware calls
public func DummyResolve(call: TwoFactorCall) throws -> [String : Any] {
    while true {
        let json = try call.getStatus()
        let status = json!["status"] as! String
        if status == "call" {
            try call.call()
        } else if status == "done" {
            return json!
        } else {
            // FIXME: if status == "error", return the error message in "error"
            throw GaError.GenericError
        }
    }
}

// An operation that potentially requires authentication and multiple
// iterations to complete, e.g. setting and then activating email notifications
public class TwoFactorCall {
    private var optr: OpaquePointer? = nil

    public init(optr: OpaquePointer) {
        self.optr = optr
    }

    deinit {
        GA_destroy_auth_handler(optr);
    }

    public func getStatus() throws -> [String: Any]? {
        var status: OpaquePointer? = nil
        try callWrapper(fun: GA_auth_handler_get_status(self.optr, &status))
        return try convertOpaqueJsonToDict(o: status!)
    }

    // Request that the backend sends a 2fa code
    public func requestCode(method: String?) throws -> Promise<Void> {
        if (method != nil) {
            try callWrapper(fun: GA_auth_handler_request_code(self.optr, method))
        }
        return Promise<Void> { seal in seal.fulfill(()) }
    }

    // Provide the 2fa code sent by the server
    public func resolveCode(code: String?) throws -> Promise<Void> {
        if (code != nil) {
            try callWrapper(fun: GA_auth_handler_resolve_code(self.optr, code))
        }
        return Promise<Void> { seal in seal.fulfill(()) }
    }

    // Call the 2fa operation
    // Returns the next 2fa operation in the chain
    public func call() throws -> Promise<Void> {
        try callWrapper(fun: GA_auth_handler_call(self.optr))
        return Promise<Void> { seal in seal.fulfill(()) }
    }
}

fileprivate class NotificationContext {
    private var session: OpaquePointer

    init(session: OpaquePointer) {
        self.session = session
    }
}

protocol SessionNotificationDelegate: class {
    func newNotification(notification: [String: Any]?)
}

public class Session {
    private typealias NotificationHandler = @convention(c) (UnsafeMutableRawPointer?, OpaquePointer?) -> Void
    static var delegate: SessionNotificationDelegate? = nil

    // TODO: ADD SUPPORT FOR MULTIPLE SESSIONS
    private let notificationHandler : NotificationHandler = { (context: UnsafeMutableRawPointer?, details: OpaquePointer?) -> Void in
        let context : NotificationContext = Unmanaged.fromOpaque(context!).takeUnretainedValue()
        if let jsonDetails = details {
            if let dict = try? convertOpaqueJsonToDict(o: jsonDetails) {
                delegate?.newNotification(notification: dict)
            }
        }
    }

    private var session: OpaquePointer? = nil
    private var notificationContext: NotificationContext? = nil

    private func setNotificationHandler() throws {
        notificationContext = NotificationContext(session: session!)
        let context = UnsafeMutableRawPointer(Unmanaged.passUnretained(self.notificationContext!).toOpaque())
        try callWrapper(fun: GA_set_notification_handler(session, notificationHandler, context))
    }

    public init() throws {
        try callWrapper(fun: GA_create_session(&session))
        try setNotificationHandler()
    }

    deinit {
        GA_destroy_session(session)
    }

    public func connect(network: Network, debug: Bool = false) throws {
        try callWrapper(fun: GA_connect(session, network.rawValue, UInt32(debug ? GA_TRUE : GA_FALSE)))
    }

    public func connectWithProxy(network: Network, proxy_uri: String, use_tor: Bool, debug: Bool = false) throws {
        try callWrapper(fun: GA_connect_with_proxy(session, network.rawValue, proxy_uri, UInt32(use_tor ? GA_TRUE : GA_FALSE),
                                                    UInt32(debug ? GA_TRUE : GA_FALSE)))
    }

    public func disconnect() throws {
        try callWrapper(fun: GA_disconnect(session))
    }

    public func registerUser(mnemonic: String) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var hw_device: OpaquePointer? = nil
        try callWrapper(fun: GA_convert_string_to_json("{}", &hw_device))
        try callWrapper(fun: GA_register_user(session, hw_device, mnemonic, &optr))
        defer {
            GA_destroy_json(hw_device)
        }
        return TwoFactorCall(optr: optr!);
    }

    public func login(mnemonic: String, password: String = "") throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var hw_device: OpaquePointer? = nil
        try callWrapper(fun: GA_convert_string_to_json("{}", &hw_device))
        try callWrapper(fun: GA_login(session, hw_device, mnemonic, password, &optr))
        defer {
            GA_destroy_json(hw_device)
        }
        return TwoFactorCall(optr: optr!);
    }

    public func loginWithPin(pin: String, pin_data:String) throws {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_convert_string_to_json(pin_data, &result))
        try callWrapper(fun: GA_login_with_pin(session, pin, result))
        defer {
            GA_destroy_json(result)
        }
    }

    public func loginWatchOnly(username: String, password: String) throws {
        try callWrapper(fun: GA_login_watch_only(session, username, password))
    }

    public func setWatchOnly(username: String, password: String) throws {
        try callWrapper(fun: GA_set_watch_only(session, username, password))
    }

    public func removeAccount() throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        try callWrapper(fun: GA_remove_account(session, &optr));
        return TwoFactorCall(optr: optr!);
    }

    public func createSubaccount(details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_create_subaccount(session, details_json, &optr))
        return TwoFactorCall(optr: optr!);
    }

    public func getSubaccounts() throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_subaccounts(session, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getTransactions(subaccount: UInt32, page: UInt32) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_transactions(session, subaccount, page, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getUnspentOutputs(subaccount: UInt32, num_confs: UInt32) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_unspent_outputs(session, subaccount, num_confs, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getUnspentOutputsForPrivateKey(private_key: String, password: String, unused: UInt32) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_unspent_outputs_for_private_key(session, private_key, password, unused, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getReceiveAddress(subaccount: UInt32) throws -> String {
        var buff: UnsafeMutablePointer<Int8>? = nil
        try callWrapper(fun: GA_get_receive_address(session, subaccount, &buff))
        defer {
            GA_destroy_string(buff)
        }
        return String(cString: buff!)
    }

    public func getBalance(subaccount: UInt32, numConfs: UInt32) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_balance(session, subaccount, numConfs, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getAvailableCurrencies() throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_available_currencies(session, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func setPin(mnemonic: String, pin: String, device: String) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_set_pin(session, mnemonic, pin, device, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getTwoFactorConfig() throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_twofactor_config(session, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    fileprivate func jsonFuncToJsonWrapper(input: [String: Any], fun call: (_: OpaquePointer, _: OpaquePointer, _: UnsafeMutablePointer<OpaquePointer?>) -> Int32) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        var input_json: OpaquePointer = try convertDictToJSON(dict: input)
        defer {
            GA_destroy_json(input_json)
        }
        try callWrapper(fun: call(session!, input_json, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func convertAmount(input: [String: Any]) throws -> [String: Any]? {
        return try jsonFuncToJsonWrapper(input: input, fun: GA_convert_amount)
    }

    public func encrypt(input: [String: Any]) throws -> [String: Any]? {
        return try jsonFuncToJsonWrapper(input: input, fun: GA_encrypt)
    }

    public func decrypt(input: [String: Any]) throws -> [String: Any]? {
        return try jsonFuncToJsonWrapper(input: input, fun: GA_decrypt)
    }

    public func createTransaction(details: [String: Any]) throws -> [String: Any]? {
        return try jsonFuncToJsonWrapper(input: details, fun: GA_create_transaction)
    }

    public func signTransaction(details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_sign_transaction(session, details_json, &optr))
        return TwoFactorCall(optr: optr!);
    }

    public func sendTransaction(details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_send_transaction(session, details_json, &optr));
        return TwoFactorCall(optr: optr!);
    }

    public func broadcastTransaction(tx_hex: String) throws -> String {
        var buff: UnsafeMutablePointer<Int8>? = nil
        try callWrapper(fun: GA_broadcast_transaction(session, tx_hex, &buff))
        defer {
            GA_destroy_string(buff)
        }
        return String(cString: buff!)
     }

    public func sendNlocktimes() throws -> Void {
        try callWrapper(fun: GA_send_nlocktimes(session))
    }

    public func setTransactionMemo(txhash_hex: String, memo: String, memo_type: UInt32) throws -> Void {
        try callWrapper(fun: GA_set_transaction_memo(session, txhash_hex, memo, memo_type))
    }


    public func getSystemMessage() throws -> String {
        var buff: UnsafeMutablePointer<Int8>? = nil
        try callWrapper(fun: GA_get_system_message(session, &buff))
        defer {
            GA_destroy_string(buff)
        }
        return String(cString: buff!)
    }

    public func ackSystemMessage(message: String) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        try callWrapper(fun: GA_ack_system_message(session, message, &optr))
        return TwoFactorCall(optr: optr!);
    }

    public func changeSettings(details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_change_settings(session, details_json, &optr));
        return TwoFactorCall(optr: optr!);
    }

    public func changeSettingsTwoFactor(method: String, details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_change_settings_twofactor(session, method, details_json, &optr));
        return TwoFactorCall(optr: optr!);
    }

    public func setTwoFactorLimit(details: [String: Any]) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        var details_json: OpaquePointer = try convertDictToJSON(dict: details)
        defer {
            GA_destroy_json(details_json)
        }
        try callWrapper(fun: GA_twofactor_change_limits(session, details_json, &optr))
        return TwoFactorCall(optr: optr!)
    }

    public func resetTwoFactor(email: String, isDispute: Bool) throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        try callWrapper(fun: GA_twofactor_reset(session, email, UInt32(isDispute ? GA_TRUE : GA_FALSE), &optr))
        return TwoFactorCall(optr: optr!);
    }

    public func cancelTwoFactorReset() throws -> TwoFactorCall {
        var optr: OpaquePointer? = nil;
        try callWrapper(fun: GA_twofactor_cancel_reset(session, &optr));
        return TwoFactorCall(optr: optr!);
    }

    public func getTransactionDetails(txhash: String) throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_transaction_details(session, txhash, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getFeeEstimates() throws -> [String: Any]? {
        var result: OpaquePointer? = nil
        try callWrapper(fun: GA_get_fee_estimates(session, &result))
        return try convertOpaqueJsonToDict(o: result!)
    }

    public func getMnemmonicPassphrase(password: String) throws -> String {
        var buff: UnsafeMutablePointer<Int8>? = nil
        try callWrapper(fun: GA_get_mnemonic_passphrase(session, password, &buff))
        defer {
            GA_destroy_string(buff)
        }
        return String(cString: buff!)
    }
}

public func generateMnemonic() throws -> String {
    var buff : UnsafeMutablePointer<Int8>? = nil
    guard GA_generate_mnemonic(&buff) == GA_OK else {
        throw GaError.GenericError
    }
    defer {
        GA_destroy_string(buff)
    }
    return String(cString: buff!)
}

public func validateMnemonic(mnemonic: String) -> Bool {
    return GA_validate_mnemonic(mnemonic) == GA_TRUE
}

public func registerNetwork(name: String, details: [String: Any]) throws -> Void {
    var details_json: OpaquePointer = try convertDictToJSON(dict: details)
    defer {
        GA_destroy_json(details_json)
    }
    try callWrapper(fun: GA_register_network(name, details_json));
}

public func getNetworks() throws -> [String: Any]? {
    var result: OpaquePointer? = nil
    try callWrapper(fun: GA_get_networks(&result))
    return try convertOpaqueJsonToDict(o: result!)
}

public func getUniformUInt32(upper_bound: UInt32) throws -> UInt32 {
    var result: UInt32 = 0
    try callWrapper(fun: GA_get_uniform_uint32_t(upper_bound, &result))
    return result
}

public func getBIP39WordList() -> [String] {
    var words: [String] = []
    var WL: OpaquePointer?
    precondition(bip39_get_wordlist(nil, &WL) == WALLY_OK)
    for i in 0..<BIP39_WORDLIST_LEN {
        var word: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(word)
        }
        precondition(bip39_get_word(WL, Int(i), &word) == WALLY_OK)
        words.append(String(cString: word!))
    }
    return words
}

public func retry<T>(session: Session,
                     network: Network,
                     maxRetryCount: UInt = 3,
                     delay: DispatchTimeInterval = .seconds(2),
                     on: DispatchQueue = DispatchQueue.global(qos : .background),
                     mnemonic: String? = nil,
                     _ fun: @escaping () -> Promise<T>) -> Promise<T> {
    var attempts = 0
    func retry_() -> Promise<T> {
        attempts += 1
        return fun().recover { error -> Promise<T> in
            guard attempts < maxRetryCount && error as! GaError == GaError.ReconnectError else { throw error }
            return after(delay).then(on: on) {
                return retry(session: session, network: network, on: on) { wrap { try session.connect(network: network, debug: true) } }
            }.then(on: on, retry_)
        }
    }
    return retry_()
}

public func wrap<T>(_ fun: @escaping () throws -> T) -> Promise<T> {
    return Promise<T> { seal in
        do {
            seal.fulfill(try fun())
        } catch GaError.ReconnectError {
            seal.reject(GaError.ReconnectError)
        } catch GaError.TimeoutError {
            seal.reject(GaError.TimeoutError)
        } catch {
            seal.reject(GaError.GenericError)
        }
    }
}
