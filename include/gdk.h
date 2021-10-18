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
typedef void (*GA_notification_handler)(void* context, GA_json* details);

/**
 * Set the global configuration and run one-time initialization code. This function must
 * be called once and only once before calling any other functions. When used in a
 * multi-threaded context this function should be called before starting any other
 * threads that call other gdk functions.
 *
 * :param config: The :ref:`init-config-arg`.
 */
GDK_API int GA_init(const GA_json* config);

#ifndef SWIG
/**
 * Get the error details associated with the last error on the current thread, if any.
 *
 * :param output: Destination for the output :ref:`error-details` JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_thread_error_details(GA_json** output);
#endif

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
 * Get the current SOCKS5 url for the embedded Tor daemon, if any.
 *
 * :param session: The session to use.
 * :param socks5: Destination for the SOCKS5 url (host:port). Empty string if not set.
 *|     Returned string should be freed using `GA_destroy_string`.
 */

GDK_API int GA_get_tor_socks5(struct GA_session* session, char** socks5);

/**
 * Compute a hashed wallet identifier from a BIP32 xpub or mnemonic.
 *
 * The identifier returned is computed from the network combined with the
 * master chain code and public key of the xpub/mnemonic. It can be used
 * as a unique wallet identifier to mitigate privacy risks associated with
 * storing the wallet's xpub.
 *
 * :param net_params: The :ref:`net-params` of the network to compute an identifier for.
 * :param params: The :ref:`wallet-id-request` to compute an identifier for.
 * :param output: Destination for the output JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_wallet_identifier(const GA_json* net_params, const GA_json* params, GA_json** output);

/**
 * Make a request to an http server.
 *
 * :param session: The session to use.
 * :param params: the :ref:`http-params` of the server to connect to.
 * :param output: Destination for the output JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_http_request(struct GA_session* session, const GA_json* params, GA_json** output);

/**
 *
 * Refresh the internal cache asset information.
 *
 * :param session: The session to use.
 * :param params: the :ref:`assets-params-data` of the server to connect to.
 * :param output: Destination for the assets JSON.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_refresh_assets(struct GA_session* session, const GA_json* params, GA_json** output);

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
 * :param hw_device: :ref:`hw-device` or empty JSON for software wallet registration.
 * :param mnemonic: The user's mnemonic passphrase for software wallet registration.
 * :param call: Destination for the resulting GA_auth_handler to perform the registration.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_register_user(
    struct GA_session* session, const GA_json* hw_device, const char* mnemonic, struct GA_auth_handler** call);

/**
 * Authenticate a user.
 *
 * :param session: The session to use.
 * :param hw_device: :ref:`hw-device` or empty JSON for software wallet login.
 * :param details: The :ref:`login-credentials` for authenticating the user.
 * :param call: Destination for the resulting GA_auth_handler to perform the login.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_login_user(
    struct GA_session* session, const GA_json* hw_device, const GA_json* details, struct GA_auth_handler** call);

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
 * :param details: The subaccount ``"name"`` (which must not be already used in
 *|     the wallet) and ``"type"`` (either ``"2of2"``, ``"2of2_no_recovery"`` or ``"2of3"``) must be
 *|     populated. Type ``"2of2_no_recovery"`` is available only for Liquid networks and
 *|     always requires both keys for spending. For type ``"2of3"`` the caller may provide
 *|     either ``"recovery_mnemonic"`` or ``"recovery_xpub"`` if they do not wish to have a
 *|     mnemonic passphrase generated automatically.
 *|     All other fields are ignored.
 * :param call: Destination for the resulting GA_auth_handler to perform the creation.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *|     Details of the created subaccount are returned in the ``"result"`` element of
 *|     the GA_auth_handler. For 2of3 subaccounts the field ``"recovery_xpub"`` will
 *|     be populated, and ``"recovery_mnemonic"`` will contain the recovery mnemonic
 *|     passphrase if one was generated. These values must be stored safely by the
 *|     caller as they will not be returned again by any call such as `GA_get_subaccounts`.
 */
GDK_API int GA_create_subaccount(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get the user's subaccount details.
 *
 * :param session: The session to use.
 * :param call: Destination for the resulting GA_auth_handler to perform the creation.
 *|     The call handlers result is :ref:`subaccount-list`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_subaccounts(struct GA_session* session, struct GA_auth_handler** call);

/**
 * Get subaccount details.
 *
 * :param session: The session to use.
 * :param subaccount: The value of ``"pointer"`` from :ref:`subaccount-list` for the subaccount.
 * :param call: Destination for the resulting GA_auth_handler to perform the creation.
 *|     The call handlers result is :ref:`subaccount-detail`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_subaccount(struct GA_session* session, uint32_t subaccount, struct GA_auth_handler** call);

/**
 * Rename a subaccount.
 *
 * :param session: The session to use.
 * :param subaccount: The value of ``"pointer"`` from :ref:`subaccount-list` or
 *|                   :ref:`subaccount-detail` for the subaccount to rename.
 * :param new_name: New name for the subaccount.
 *
 * .. note:: This call is deprecated and will be removed in a future release. Use
 *|          `GA_update_subaccount` to rename subaccounts.
 */
GDK_API int GA_rename_subaccount(struct GA_session* session, uint32_t subaccount, const char* new_name);

/**
 * Update subaccount information.
 *
 * :param session: The session to use.
 * :param details: :ref:`subaccount-update` giving the details to update.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_update_subaccount(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get a page of the user's transaction history.
 *
 * :param session: The session to use.
 * :param details: :ref:`transactions-details` giving the details to get the transactions for.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: Transactions are returned from newest to oldest with up to 30 transactions per page.
 */
GDK_API int GA_get_transactions(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get a new address to receive coins to.
 *
 * :param session: The session to use.
 * :param details: :ref:`receive-address-details`.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_receive_address(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get a page of addresses previously generated for a subaccount.
 *
 * :param session: The session to use.
 * :param details: :ref:`previous-addresses-request` detailing the previous addresses to fetch.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`previous-addresses`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: Iteration of all addresses is complete when the results 'last_pointer'
 *|     value equals 1.
 */
GDK_API int GA_get_previous_addresses(
    struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get the user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-request` detailing the unspent transaction outputs to fetch.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_unspent_outputs(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

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
 * Change the status of a user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-status` detailing the unspent transaction outputs status to set.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_set_unspent_outputs_status(
    struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

/**
 * Get a transaction's details.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash of the transaction to fetch.
 * :param transaction: Destination for the :ref:`external-tx-detail`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_transaction_details(struct GA_session* session, const char* txhash_hex, GA_json** transaction);

/**
 * The sum of unspent outputs destined to user's wallet.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-request` detailing the unspent transaction outputs to
 *|    compute the balance from.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_balance(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

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
 * :param value_details: :ref:`convert-amount` giving the value to convert.
 * :param output: Destination for the converted values :ref:`amount-data`.
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
 * Disable all PIN logins previously set. After calling this method, user will not be able to
 *|    login with PIN from any device he previously paired.
 */
GDK_API int GA_disable_all_pin_logins(struct GA_session* session);

/**
 * Construct a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`create-tx-details` for constructing.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_create_transaction(
    struct GA_session* session, const GA_json* transaction_details, struct GA_auth_handler** call);

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
 * Create a PSETv2 filling UTXO details and receive/change outputs.
 *
 * :param session: The session to use.
 * :param pset_details: PSET :ref:`create-pset-details` for constructing.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_create_pset(
    struct GA_session* session, const GA_json* pset_details, struct GA_auth_handler** call);

/**
 * Blind PSETv2 outputs and sign the user's inputs.
 *
 * :param session: The session to use.
 * :param pset_details: PSET PSET :ref:`sign-pset-details` used for constructing.
 * :param call: Destination for the resulting GA_auth_handler to perform the blinding and signing.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_sign_pset(
    struct GA_session* session, const GA_json* pset_details, struct GA_auth_handler** call);

/**
 * Request an email containing the user's nLockTime transactions.
 *
 * :param session: The session to use.
 */
GDK_API int GA_send_nlocktimes(struct GA_session* session);

/**
 * Set the number of blocks after which CSV transactions become spendable without two factor authentication.
 *
 * :param session: The session to use.
 * :param locktime_details: The :ref:`set-locktime-details` for setting the block value.
 * :param call: Destination for the resulting GA_auth_handler to change the locktime.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_set_csvtime(struct GA_session* session, const GA_json* locktime_details, struct GA_auth_handler** call);

/**
 * Set the number of blocks after which nLockTime transactions become
 *|    spendable without two factor authentication. When this function
 *|    succeeds, if the user has an email address associated with the
 *|    wallet, an updated nlocktimes.zip file will be sent via email.
 *
 * :param session: The session to use.
 * :param locktime_details: The :ref:`set-locktime-details` for setting the block value.
 * :param call: Destination for the resulting GA_auth_handler to change the locktime.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_set_nlocktime(
    struct GA_session* session, const GA_json* locktime_details, struct GA_auth_handler** call);

/**
 * Add a transaction memo to a user's GreenAddress transaction.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash to associate the memo with.
 * :param memo: The memo to set.
 * :param memo_type: Unused, pass 0.
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
 * This function must be called before `GA_connect`.
 * Notifications may arrive on different threads so the caller must ensure
 * that shared data is correctly locked within the handler.
 * The GA_json object passed to the caller must be destroyed by the caller
 * using `GA_destroy_json`. Failing to do so will result in memory leaks.
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
 * :param output: Destination for the resulting :ref:`auth-handler-status`.
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
 * ``"status"`` element from `GA_auth_handler_get_status`:
 *
 * * ``"done"``: The action has been completed successfully. Any data returned
 *|  from the action is present in the ``"result"`` element of the status JSON.
 *| The auth_handler object should be destroyed using `GA_destroy_auth_handler`
 *| after receiving this status.
 *
 * * ``"error"``: A non-recoverable error occurred performing the action. The
 *| associated error message is given in the status element ``"error"``. The
 *| auth_handler object should be destroyed using `GA_destroy_auth_handler` and
 *| the action restarted from scratch if this state is returned.
 *
 * * ``"request_code"``: Two factor authorization is required. The caller should
 *| prompt the user to choose a two factor method from the ``"methods"`` element
 *| and call `GA_auth_handler_request_code` with the selected method.
 *
 * * ``"resolve_code"``: A twofactor code from the ``"request_code"`` step, or
 *| data from a hardware device is required. If the status JSON contains
 *| :ref:`hw-required-data`, then see :ref:`hw-resolve-overview` for details.
 *| Otherwise, to resolve a twofactor code, the caller should prompt the user
 *| to enter the code from the twofactor method chosen in the ``"request_code"``
 *| step, and pass this code to `GA_auth_handler_resolve_code`.
 *
 * * ``"call"``: Twofactor or hardware authorization is complete and the caller
 *| should call `GA_auth_handler_call` to perform the action.
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
 * :param code: The two factor authentication code received by the user, or
 *|    the serialised JSON response for hardware interaction (see :ref:`hw-resolve-overview`).
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
 * :param method: The two factor method to enable/disable, i.e. ``"email"``, ``"sms"``, ``"phone"``, ``"gauth"``
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
 * Undo a request to begin the two factor authentication reset process.
 *
 * :param session: The session to use.
 * :param email: The email address to cancel the reset request for. Must be
 *|     the email previously passed to `GA_twofactor_reset`.
 * :param call: Destination for the resulting GA_auth_handler to request the reset.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: Unlike`GA_twofactor_cancel_reset`, this call only removes the reset
 *|     request associated with the given email. If other emails have requested
 *|     a reset, the wallet will still remain locked following this call.
 */
GDK_API int GA_twofactor_undo_reset(struct GA_session* session, const char* email, struct GA_auth_handler** call);

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
 * Generate a new random 12 word BIP 39 mnemonic.
 *
 * :param output: The generated mnemonic phrase.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_generate_mnemonic_12(char** output);

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
