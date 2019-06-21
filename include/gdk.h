#ifndef GDK_GDK_H
#define GDK_GDK_H
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

/** Error codes for API calls */
#define GA_OK 0
#define GA_ERROR (-1)
#define GA_RECONNECT (-2)
#define GA_SESSION_LOST (-3)
#define GA_TIMEOUT (-4)
#define GA_NOT_AUTHORIZED (-5)

/** Logging levels */
#define GA_NONE 0
#define GA_INFO 1
#define GA_DEBUG 2

/** Boolean values */
#define GA_TRUE 1
#define GA_FALSE 0

/** A server session */
struct GA_session;

/** A Parsed JSON object */
typedef struct GA_json GA_json;

/** An api method call that potentially requires two factor authentication to complete */
struct GA_auth_handler;

/** A notification handler */
typedef void (*GA_notification_handler)(void* context, const GA_json* details);

/** Values for transaction memo type */
#define GA_MEMO_USER 0
#define GA_MEMO_BIP70 1

/**
 * Set the global configuration and run one-time initialization code. This function must
 * be called once and only once before calling any other functions. When used in a
 * multi-threaded context this function should be called before starting any other
 * threads that call other gdk functions.
 *
 * :param config: Configuration object
 */
GDK_API int GA_init(const GA_json* config);

/**
 * Create a new session.
 *
 * :param session: Destination for the resulting session.
 *|     Returned session should be freed using `GA_destroy_session`.
 */
GDK_API int GA_create_session(struct GA_session** session);

/**
 * Free a session allocated by `GA_create_session`.
 *
 * :param session: Session to free.
 */
GDK_API int GA_destroy_session(struct GA_session* session);

/**
 * Connect to a remote server using the specified network.
 *
 * :param session: The session to use.
 * :param net_params: The :ref:`net-params` of the network to connect to.
 */
GDK_API int GA_connect(struct GA_session* session, const GA_json* net_params);

/**
 * Disconnect from a connected remote server.
 *
 * :param session: The session to use.
 */
GDK_API int GA_disconnect(struct GA_session* session);

/**
 * Configure networking behaviour when reconnecting.
 *
 * :param session: The session to use.
 * :param hint: the :ref:`hint` to configure.
 */
GDK_API int GA_reconnect_hint(struct GA_session* session, const GA_json* hint);

/**
 * Check if server can be reached via the proxy.
 *
 * :param params: the :ref:`params-proxy` of the server to connect to.
 */
GDK_API int GA_check_proxy_connectivity(const GA_json* params);

/**
 * Get JSON data from an https server.
 *
 * :param session: The session to use.
 * :param params: the :ref:`params-data` of the server to connect to.
 * :param output: Destination for the output JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_http_get(struct GA_session* session, const GA_json* params, GA_json** output);

/**
 *
 * Refresh the internal cache asset information.
 *
 * :param session: The session to use.
 * :param output: Destination for the assets JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_refresh_assets(struct GA_session* session, GA_json** output);

/**
 * Validate asset domain name.
 * (This is a interface stub)
 *
 */
GDK_API int GA_validate_asset_domain_name(struct GA_session* session, const GA_json* params, GA_json** output);

/**
 * Create a new user account using a hardware wallet/HSM/TPM.
 *
 * :param session: The session to use.
 * :param hw_device: Details about the :ref:`hw-device` being used to register.
 * :param mnemonic: The user's mnemonic passphrase.
 * :param call: Destination for the resulting GA_auth_handler to perform the registration.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_register_user(
    struct GA_session* session, const GA_json* hw_device, const char* mnemonic, struct GA_auth_handler** call);

/**
 * Authenticate a user using a hardware wallet/HSM/TPM.
 *
 * :param session: The session to use.
 * :param hw_device: Details about the :ref:`hw-device` being used to login.
 * :param mnemonic: The user's mnemonic passphrase.
 * :param password: The user's password to decrypt a 27 word mnemonic, or a blank string if none.
 * :param call: Destination for the resulting GA_auth_handler to perform the login.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_login(struct GA_session* session, const GA_json* hw_device, const char* mnemonic, const char* password,
    struct GA_auth_handler** call);

/**
 * Authenticate a user.
 *
 * :param session: The session to use.
 * :param pin: The user PIN.
 * :param pin_data: The :ref:`pin-data` returned by `GA_set_pin`.
 */
GDK_API int GA_login_with_pin(struct GA_session* session, const char* pin, const GA_json* pin_data);

/**
 * Set a watch-only login for the wallet.
 *
 * :param session: The session to use.
 * :param username: The username.
 * :param password: The password.
 */
GDK_API int GA_set_watch_only(struct GA_session* session, const char* username, const char* password);

/**
 * Get the current watch-only login for the wallet, if any.
 *
 * :param session: The session to use.
 * :param username: Destination for the watch-only username. Empty string if not set.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_get_watch_only_username(struct GA_session* session, char** username);

/**
 * Authenticate a user in watch only mode.
 *
 * :param session: The session to use.
 * :param username: The username.
 * :param password: The password.
 */
GDK_API int GA_login_watch_only(struct GA_session* session, const char* username, const char* password);

/**
 * Remove an account.
 *
 * :param session: The session to use.
 * :param call: Destination for the resulting GA_auth_handler to perform the removal.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_remove_account(struct GA_session* session, struct GA_auth_handler** call);

/**
 * Create a subaccount.
 *
 * :param session: The session to use.
 * :param details: The :ref:`subaccount`. "name" (which must not be already used in
 *|     the wallet) and "type" (either "2of2" or "2of3") must be populated. For
 *|     type "2of3" the caller may provide either "recovery_mnemonic" or "recovery_xpub"
 *|     if they do not wish to have a mnemonic passphrase generated automatically.
 *|     All other fields are ignored.
 * :param subaccount: Destination for the created subaccount details. For 2of3
 *|     subaccounts the field "recovery_xpub" will be populated, and "recovery_mnemonic"
 *|     will contain the recovery mnemonic passphrase if one was generated. These
 *|     values should be stored safely by the caller as they will not be returned again
 *|     by any GDK call such as GA_get_subaccounts.
 * :param call: Destination for the resulting GA_auth_handler to perform the creation.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_create_subaccount(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get the user's subaccount details.
 *
 * :param session: The session to use.
 * :param subaccounts: Destination for the user's :ref:`subaccount-list`.
 *|      Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_subaccounts(struct GA_session* session, GA_json** subaccounts);

/**
 * Get subaccount details.
 *
 * :param session: The session to use.
 * :param subaccount: The value of "pointer" from :ref:`subaccount-list` for the subaccount.
 * :param output: Destination for the :ref:`subaccount-detail`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_subaccount(struct GA_session* session, uint32_t subaccount, GA_json** output);

/**
 * Rename a subaccount.
 *
 * :param session: The session to use.
 * :param subaccount: The value of "pointer" from :ref:`subaccount-list` or
 *|                   :ref:`subaccount-detail` for the subaccount to rename.
 * :param new_name: New name for the subaccount.
 */
GDK_API int GA_rename_subaccount(struct GA_session* session, uint32_t subaccount, const char* new_name);

/**
 * Get a page of the user's transaction history.
 *
 * :param session: The session to use.
 * :param details: :ref:`transactions-details` giving the details to get the transactions for.
 * :param txs: The :ref:`tx-list`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * .. note:: Transactions are returned from newest to oldest with up to 30 transactions per page.
 */
GDK_API int GA_get_transactions(struct GA_session* session, const GA_json* details, GA_json** txs);

/**
 * Get a new address to receive coins to.
 *
 * :param session: The session to use.
 * :param details: :ref:`receive-address-details`.
 * :param output: Destination for the generated address :ref:`receive-address`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_receive_address(struct GA_session* session, const GA_json* details, GA_json** output);

/**
 * Get the user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-utxos-details` to get the unspent transaction outputs for.
 * :param utxos: Destination for the returned utxos (same format as :ref:`tx-list`).
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_unspent_outputs(struct GA_session* session, const GA_json* details, GA_json** utxos);

/**
 * Get the unspent transaction outputs associated with a non-wallet private key.
 *
 * :param session: The session to use.
 * :param key: The private key in WIF or BIP 38 format.
 * :param password: The password the key is encrypted with, if any.
 * :param unused: unused, must be 0
 * :param utxos: Destination for the returned utxos (same format as :ref:`tx-list`).
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * .. note:: Neither the private key or its derived public key are transmitted.
 */
GDK_API int GA_get_unspent_outputs_for_private_key(
    struct GA_session* session, const char* private_key, const char* password, uint32_t unused, GA_json** utxos);

/**
 * Get a transaction's details.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash of the transaction to fetch.
 * :param transaction: Destination for the :ref:`tx-detail`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_transaction_details(struct GA_session* session, const char* txhash_hex, GA_json** transaction);

/**
 * The sum of unspent outputs destined to user's wallet.
 *
 * :param session: The session to use.
 * :param details: :ref:`balance-details` giving the subaccount details to get the balance for.
 * :param balance: The returned :ref:`balance-data`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_balance(struct GA_session* session, const GA_json* details, GA_json** balance);

/**
 * The list of allowed currencies for all available pricing sources.
 *
 * :param session: The session to use.
 * :param currencies: The returned list of :ref:`currencies`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_available_currencies(struct GA_session* session, GA_json** currencies);

/**
 * Convert Fiat to BTC and vice-versa.
 *
 * :param session: The session to use.
 * :param value_details: :ref:`convert` giving the value to convert.
 * :param output: Destination for the converted values :ref:`balance-data`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_convert_amount(struct GA_session* session, const GA_json* value_details, GA_json** output);

/**
 * Set a PIN for the user wallet.
 *
 * :param session: The session to use.
 * :param mnemonic: The user's mnemonic passphrase.
 * :param pin: The user PIN.
 * :param device_id: The user device identifier.
 * :param pin_data: The returned :ref:`pin-data` containing the user's encrypted mnemonic passphrase.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_set_pin(
    struct GA_session* session, const char* mnemonic, const char* pin, const char* device_id, GA_json** pin_data);

/**
 * Construct a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`transaction-details` for constructing.
 * :param transaction: Destination for the resulting transaction's details.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_create_transaction(
    struct GA_session* session, const GA_json* transaction_details, GA_json** transaction);

/**
 * Sign the user's inputs to a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`sign-tx-details` for signing, previously returned from GA_create_transaction.
 * :param call: Destination for the resulting GA_auth_handler to perform the signing.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_sign_transaction(
    struct GA_session* session, const GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Broadcast a non-Green signed transaction to the P2P network.
 *
 * :param session: The session to use.
 * :param transaction_hex: The signed transaction in hex to broadcast.
 * :param tx_hash: Destination for the resulting transactions hash.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_broadcast_transaction(struct GA_session* session, const char* transaction_hex, char** tx_hash);

/**
 * Send a transaction created by GA_create_transaction and signed by GA_sign_transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`send-tx-details` for sending.
 * :param call: Destination for the resulting GA_auth_handler to perform the send.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_send_transaction(
    struct GA_session* session, const GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Request an email containing the user's nLockTime transactions.
 *
 * :param session: The session to use.
 */
GDK_API int GA_send_nlocktimes(struct GA_session* session);

/**
 * Add a transaction memo to a user's GreenAddress transaction.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash to associate the memo with.
 * :param memo: The memo to set.
 * :param memo_type: The type of memo to set, either GA_MEMO_USER or GA_MEMO_BIP70.
 */
GDK_API int GA_set_transaction_memo(
    struct GA_session* session, const char* txhash_hex, const char* memo, uint32_t memo_type);

/**
 * Get the current network's fee estimates.
 *
 * :param session: The session to use.
 * :param estimates: Destination for the returned :ref:`estimates`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * The estimates are returned as an array of 25 elements. Each element is
 * an integer representing the fee estimate expressed as satoshi per 1000
 * bytes. The first element is the minimum relay fee as returned by the
 * network, while the remaining elements are the current estimates to use
 * for a transaction to confirm from 1 to 24 blocks.
 *
 */
GDK_API int GA_get_fee_estimates(struct GA_session* session, GA_json** estimates);

/**
 * Get the user's mnemonic passphrase.
 *
 * :param session: The session to use.
 * :param password: Optional password to encrypt the user's mnemonic passphrase with.
 * :param mnemonic: Destination for the user's 24 word mnemonic passphrase. if a
 *|     non-empty password is given, the returned mnemonic passphrase will be
 *|     27 words long and will require the password to use for logging in.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_get_mnemonic_passphrase(struct GA_session* session, const char* password, char** mnemonic);

/**
 * Get the latest un-acknowledged system message.
 *
 * :param session: The session to use.
 * :param message_text: The returned UTF-8 encoded message text.
 *|     Returned string should be freed using `GA_destroy_string`.
 *
 * .. note:: If all current messages are acknowledged, an empty string is returned.
 */
GDK_API int GA_get_system_message(struct GA_session* session, char** message_text);

/**
 * Sign and acknowledge a system message.
 *
 * The message text will be signed with a key derived from the wallet master key and the signature
 * sent to the server.
 *
 * :param session: The session to use.
 * :param message_text: UTF-8 encoded message text being acknowledged.
 * :param call: Destination for the resulting GA_auth_handler to acknowledge the message.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_ack_system_message(struct GA_session* session, const char* message_text, struct GA_auth_handler** call);

/**
 * Get the two factor configuration for the current user.
 *
 * :param session: The session to use.
 * :param config: Destination for the returned :ref:`configuration`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_twofactor_config(struct GA_session* session, GA_json** config);

/**
 * Encrypt data.
 *
 * :param session: The session to use.
 * :param input: The data to encrypt.
 * :param output: Destination for the encrypted data.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * If no key is given, the data is encrypted using a key derived from the user's mnemonics.
 * This will fail to decrypt the data correctly if the user is logged in in watch-only
 * mode. For watch only users a key must be provided by the caller.
 *
 */
GDK_API int GA_encrypt(struct GA_session* session, const GA_json* input, GA_json** output);

/**
 * Decrypt data.
 *
 * :param session: The session to use.
 * :param input: The data to decrypt.
 * :param output: Destination for the decrypted data.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * See GA_encrypt.
 *
 */
GDK_API int GA_decrypt(struct GA_session* session, const GA_json* input, GA_json** output);

/**
 * Change settings
 *
 * :param session: The session to use.
 * :param settings: The new :ref:`settings` values.
 * :param call: Destination for the resulting GA_auth_handler.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_change_settings(struct GA_session* session, const GA_json* settings, struct GA_auth_handler** call);

/**
 * Get settings
 *
 * :param session: The session to use.
 * :param settings: Destination for the current :ref:`settings`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_settings(struct GA_session* session, GA_json** settings);

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
 * The GA_json object passed to the caller must be destroyed by the caller
 * using GA_destroy_json. Failing to do so will result in memory leaks.
 * When the session is disconnected/destroyed, a final call will be made to
 * the handler with a :ref:`session-event` notification.
 *
 */
GDK_API int GA_set_notification_handler(struct GA_session* session, GA_notification_handler handler, void* context);

GDK_API int GA_convert_json_to_string(const GA_json* json, char** output);

GDK_API int GA_convert_string_to_json(const char* input, GA_json** output);

GDK_API int GA_convert_json_value_to_string(const GA_json* json, const char* path, char** output);

GDK_API int GA_convert_json_value_to_uint32(const GA_json* json, const char* path, uint32_t* output);

GDK_API int GA_convert_json_value_to_uint64(const GA_json* json, const char* path, uint64_t* output);

GDK_API int GA_convert_json_value_to_bool(const GA_json* json, const char* path, uint32_t* output);

GDK_API int GA_convert_json_value_to_json(const GA_json* json, const char* path, GA_json** output);

/**
 * Free a GA_json object.
 *
 * :param json: GA_json object to free.
 */
GDK_API int GA_destroy_json(GA_json* json);

#endif /* SWIG */

/**
 * Get the status/result of an action requiring authorization.
 *
 * :param call: The auth_handler whose status is to be queried.
 * :param output: Destination for the resulting :ref:`twofactor-status`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 *
 * Methods in the api that may require two factor or hardware authentication
 * to complete return a GA_auth_handler object. This object encapsulates the
 * process of determining whether authentication is required and handling
 * conditions such as re-prompting and re-trying after an incorrect two
 * factor code is entered.
 *
 * The object acts as a state machine which is stepped through by the caller
 * until the desired action is completed. At each step, the current state can
 * be determined and used to perform the next action required.
 *
 * Some actions require a sequence of codes and decisions; these are hidden
 * behind the state machine interface so that callers do not need to handle
 * special cases or program their own logic to handle any lower level API
 * differences.
 *
 * The state machine has the following states, which are returned in the
 * "status" element from GA_auth_handler_get_status():
 *
 * * "done": The action has been completed successfully. Any data returned
 *|  from the action is present in the "result" element of the status JSON.
 *
 * * "error": A non-recoverable error occurred performing the action. The
 *| associated error message is given in the status element "error". The
 *| auth_handler object should be destroyed and the action restarted from
 *| scratch if this state is returned.
 *
 * * "request_code": Two factor authorization is required. The caller should
 *| prompt the user to choose a two factor method from the "methods" element
 *| and call GA_auth_handler_request_code() with the selected method.
 *
 * * "resolve_code": The caller should prompt the user to enter the code from
 *| the twofactor method chosen in the "request_code" step, and pass this
 *| code to GA_auth_handler_resolve_code().
 *
 * * "call": Twofactor or hardwre authorization is complete and the caller
 *| should call GA_auth_handler_call() to perform the action.
 *
 */
GDK_API int GA_auth_handler_get_status(struct GA_auth_handler* call, GA_json** output);

/**
 * Request a two factor authentication code to authorize an action.
 *
 * :param call: The auth_handler representing the action to perform.
 * :param method: The selected two factor method to use
 */
GDK_API int GA_auth_handler_request_code(struct GA_auth_handler* call, const char* method);

/**
 * Authorize an action by providing its previously requested two factor authentication code.
 *
 * :param call: The auth_handler representing the action to perform.
 * :param code: The two factor authentication code received by the user.
 */
GDK_API int GA_auth_handler_resolve_code(struct GA_auth_handler* call, const char* code);

/**
 * Perform an action following the completion of authorization.
 *
 * :param call: The auth_handler representing the action to perform.
 */
GDK_API int GA_auth_handler_call(struct GA_auth_handler* call);

/**
 * Free an auth_handler after use.
 *
 * :param call: The auth_handler to free.
 */
GDK_API int GA_destroy_auth_handler(struct GA_auth_handler* call);

/**
 * Enable or disable a two factor authentication method.
 *
 * :param session: The session to use
 * :param method: The two factor method to enable/disable, i.e. "email", "sms", "phone", "gauth"
 * :param twofactor_details: The two factor method and associated data such as an email address. :ref:`twofactor-detail`
 * :param call: Destination for the resulting GA_auth_handler to perform the action
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_change_settings_twofactor(
    struct GA_session* session, const char* method, const GA_json* twofactor_details, struct GA_auth_handler** call);

/**
 * Request to begin the two factor authentication reset process.
 *
 * :param session: The session to use.
 * :param email: The new email address to enable once the reset waiting period expires.
 * :param is_dispute: GA_TRUE if the reset request is disputed, GA_FALSE otherwise.
 * :param call: Destination for the resulting GA_auth_handler to request the reset.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_twofactor_reset(
    struct GA_session* session, const char* email, uint32_t is_dispute, struct GA_auth_handler** call);

/**
 * Cancel all outstanding two factor resets and unlock the wallet for normal operation.
 *
 * :param session: The session to use.
 * :param call: Destination for the resulting GA_auth_handler to cancel the reset.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_twofactor_cancel_reset(struct GA_session* session, struct GA_auth_handler** call);

/**
 * Change twofactor limits settings.
 *
 * :param session: The session to use.
 * :param limit_details: Details of the new :ref:`transaction-limits`
 * :param call: Destination for the resulting GA_auth_handler to perform the change.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_twofactor_change_limits(
    struct GA_session* session, const GA_json* limit_details, struct GA_auth_handler** call);

#ifndef SWIG
/**
 * Free a string returned by the api.
 *
 * :param str: The string to free.
 */
GDK_API void GA_destroy_string(char* str);
#endif /* SWIG */

/**
 * Get up to 32 random bytes.
 *
 * Generate up to 32 random bytes using the same strategy as Bitcoin Core code.
 *
 * :param output_bytes: bytes output buffer
 * :param siz: Number of bytes to return (max. 32)
 */
GDK_API int GA_get_random_bytes(size_t num_bytes, unsigned char* output_bytes, size_t len);

/**
 * Generate a new random BIP 39 mnemonic.
 *
 * :param output: The generated mnemonic phrase.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_generate_mnemonic(char** output);

/**
 * Validate a BIP 39 mnemonic.
 *
 * :param mnemonic: The mnemonic phrase
 * :param valid: Destination for the result: GA_TRUE if the mnemonic is valid else GA_FALSE
 */
GDK_API int GA_validate_mnemonic(const char* mnemonic, uint32_t* valid);

/**
 * Register a network configuration
 *
 * :param name: The name of the network to register
 * :param network_details: The :ref:`network` configuration to register
 *
 * Any existing configuration with the same name is overwritten.
 * If the provided JSON is empty, any existing configuration for
 * the network is removed.
 *
 */
GDK_API int GA_register_network(const char* name, const GA_json* network_details);

/**
 * Get the available network configurations
 *
 * :param output: Destination for the :ref:`networks-list`
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_networks(GA_json** output);

/**
 * Get a uint32_t in the range 0 to (upper_bound - 1) without bias
 *
 * :param output: Destination for the generated uint32_t.
 */
GDK_API int GA_get_uniform_uint32_t(uint32_t upper_bound, uint32_t* output);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GDK_H */
