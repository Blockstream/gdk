#ifndef GDK_GDK_RPC_H
#define GDK_GDK_RPC_H
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

/** A server session */
typedef struct GDKRPC_session GDKRPC_session;

/** A Parsed JSON object */
typedef struct GDKRPC_json GDKRPC_json;

/** A notification handler */
typedef void (*GDKRPC_notification_handler)(void *self_context, GDKRPC_json* details);

/**
 * Create a new session.
 *
 * :param session: Destination for the resulting session.
 *|     Returned session should be freed using `GA_destroy_session`.
 */
GDK_API int GDKRPC_create_session(struct GDKRPC_session** session, GDKRPC_json *networks);

/**
 * Free a session allocated by `GA_create_session`.
 *
 * :param session: Session to free.
 */
GDK_API int GDKRPC_destroy_session(struct GDKRPC_session* session);

/**
 * Connect to a remote server using the specified network.
 *
 * :param session: The session to use.
 * :param net_params: The :ref:`net-params` of the network to connect to.
 */
GDK_API int GDKRPC_connect(struct GDKRPC_session* session, const GDKRPC_json* net_params);

/**
 * Disconnect from a connected remote server.
 *
 * :param session: The session to use.
 */
GDK_API int GDKRPC_disconnect(struct GDKRPC_session* session);

/**
 * Check if server can be reached via the proxy.
 *
 * :param params: the :ref:`params-proxy` of the server to connect to.
 */
GDK_API int GDKRPC_check_proxy_connectivity(const GDKRPC_json* params);

/**
 * Create a new user account using a hardware wallet/HSM/TPM.
 *
 * :param session: The session to use.
 * :param hw_device: Details about the :ref:`hw-device` being used to register.
 * :param mnemonic: The user's mnemonic passphrase.
 * :param call: Destination for the resulting GA_auth_handler to perform the registration.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GDKRPC_register_user(
    struct GDKRPC_session* session, const GDKRPC_json* hw_device, const char* mnemonic, struct GA_auth_handler** call);

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
GDK_API int GDKRPC_login(struct GDKRPC_session* session, const GDKRPC_json* hw_device, const char* mnemonic, const char* password);

/**
 * Authenticate a user.
 *
 * :param session: The session to use.
 * :param pin: The user PIN.
 * :param pin_data: The :ref:`pin-data` returned by `GA_set_pin`.
 */
GDK_API int GDKRPC_login_with_pin(struct GDKRPC_session* session, const char* pin, const GDKRPC_json* pin_data);

/**
 * Get a page of the user's transaction history.
 *
 * :param session: The session to use.
 * :param details: :ref:`transactions-details` giving the details to get the transactions for.
 * :param txs: The :ref:`tx-list`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 *
 * .. note:: Transactions are returned from newest to oldest with up to 30 transactions per page.
 */
GDK_API int GDKRPC_get_transactions(struct GDKRPC_session* session, const GDKRPC_json* details, GDKRPC_json** txs);

/**
 * Get a new address to receive coins to.
 *
 * :param session: The session to use.
 * :param details: :ref:`receive-address-details`.
 * :param output: Destination for the generated address :ref:`receive-address`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_receive_address(struct GDKRPC_session* session, const GDKRPC_json* details, GDKRPC_json** output);

/**
 * Get the user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-utxos-details` to get the unspent transaction outputs for.
 * :param utxos: Destination for the returned utxos (same format as :ref:`tx-list`).
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_unspent_outputs(struct GDKRPC_session* session, const GDKRPC_json* details, GDKRPC_json** utxos);

/**
 * Get the unspent transaction outputs associated with a non-wallet private key.
 *
 * :param session: The session to use.
 * :param key: The private key in WIF or BIP 38 format.
 * :param password: The password the key is encrypted with, if any.
 * :param unused: unused, must be 0
 * :param utxos: Destination for the returned utxos (same format as :ref:`tx-list`).
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 *
 * .. note:: Neither the private key or its derived public key are transmitted.
 */
GDK_API int GDKRPC_get_unspent_outputs_for_private_key(
    struct GDKRPC_session* session, const char* private_key, const char* password, uint32_t unused, GDKRPC_json** utxos);

/**
 * Get a transaction's details.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash of the transaction to fetch.
 * :param transaction: Destination for the :ref:`tx-detail`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_transaction_details(struct GDKRPC_session* session, const char* txhash_hex, GDKRPC_json** transaction);

/**
 * The sum of unspent outputs destined to user's wallet.
 *
 * :param session: The session to use.
 * :param details: :ref:`balance-details` giving the subaccount details to get the balance for.
 * :param balance: The returned :ref:`balance-data`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_balance(struct GDKRPC_session* session, const GDKRPC_json* details, GDKRPC_json** balance);

/**
 * The list of allowed currencies for all available pricing sources.
 *
 * :param session: The session to use.
 * :param currencies: The returned list of :ref:`currencies`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_available_currencies(struct GDKRPC_session* session, GDKRPC_json** currencies);

/**
 * Convert Fiat to BTC and vice-versa.
 *
 * :param session: The session to use.
 * :param value_details: :ref:`convert` giving the value to convert.
 * :param output: Destination for the converted values :ref:`balance-data`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_convert_amount(struct GDKRPC_session* session, const GDKRPC_json* value_details, GDKRPC_json** output);

/**
 * Set a PIN for the user wallet.
 *
 * :param session: The session to use.
 * :param mnemonic: The user's mnemonic passphrase.
 * :param pin: The user PIN.
 * :param device_id: The user device identifier.
 * :param pin_data: The returned :ref:`pin-data` containing the user's encrypted mnemonic passphrase.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_set_pin(
    struct GDKRPC_session* session, const char* mnemonic, const char* pin, const char* device_id, GDKRPC_json** pin_data);

/**
 * Construct a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`transaction-details` for constructing.
 * :param transaction: Destination for the resulting transaction's details.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_create_transaction(
    struct GDKRPC_session* session, const GDKRPC_json* transaction_details, GDKRPC_json** transaction);

/**
 * Sign the user's inputs to a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`sign-tx-details` for signing, previously returned from GA_create_transaction.
 * :param call: Destination for the resulting GA_auth_handler to perform the signing.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GDKRPC_sign_transaction(
    struct GDKRPC_session* session, const GDKRPC_json* transaction_details, GDKRPC_json** signed_tx);

/**
 * Broadcast a non-Green signed transaction to the P2P network.
 *
 * :param session: The session to use.
 * :param transaction_hex: The signed transaction in hex to broadcast.
 * :param tx_hash: Destination for the resulting transactions hash.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GDKRPC_broadcast_transaction(struct GDKRPC_session* session, const char* transaction_hex, char** tx_hash);

/**
 * Send a transaction created by GA_create_transaction and signed by GA_sign_transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`send-tx-details` for sending.
 * :param call: Destination for the resulting GA_auth_handler to perform the send.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GDKRPC_send_transaction(
    struct GDKRPC_session* session, const GDKRPC_json* transaction_details, GDKRPC_json** res);

/**
 * Request an email containing the user's nLockTime transactions.
 *
 * :param session: The session to use.
 */
GDK_API int GDKRPC_send_nlocktimes(struct GDKRPC_session* session);

/**
 * Add a transaction memo to a user's GreenAddress transaction.
 *
 * :param session: The session to use.
 * :param txhash_hex: The transaction hash to associate the memo with.
 * :param memo: The memo to set.
 * :param memo_type: The type of memo to set, either GA_MEMO_USER or GA_MEMO_BIP70.
 */
GDK_API int GDKRPC_set_transaction_memo(
    struct GDKRPC_session* session, const char* txhash_hex, const char* memo, uint32_t memo_type);

/**
 * Get the current network's fee estimates.
 *
 * :param session: The session to use.
 * :param estimates: Destination for the returned :ref:`estimates`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 *
 * The estimates are returned as an array of 25 elements. Each element is
 * an integer representing the fee estimate expressed as satoshi per 1000
 * bytes. The first element is the minimum relay fee as returned by the
 * network, while the remaining elements are the current estimates to use
 * for a transaction to confirm from 1 to 24 blocks.
 *
 */
GDK_API int GDKRPC_get_fee_estimates(struct GDKRPC_session* session, GDKRPC_json** estimates);

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
GDK_API int GDKRPC_get_mnemonic_passphrase(struct GDKRPC_session* session, const char* password, char** mnemonic);

/**
 * Get the two factor configuration for the current user.
 *
 * :param session: The session to use.
 * :param config: Destination for the returned :ref:`configuration`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_twofactor_config(struct GDKRPC_session* session, GDKRPC_json** config);

/**
 * Change settings
 *
 * :param session: The session to use.
 * :param settings: The new :ref:`settings` values.
 * :param call: Destination for the resulting GA_auth_handler.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GDKRPC_change_settings(struct GDKRPC_session* session, const GDKRPC_json* settings, struct GA_auth_handler** call);

/**
 * Get settings
 *
 * :param session: The session to use.
 * :param settings: Destination for the current :ref:`settings`.
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_settings(struct GDKRPC_session* session, GDKRPC_json** settings);

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
 * The GDKRPC_json object passed to the caller must be destroyed by the caller
 * using GA_destroy_json. Failing to do so will result in memory leaks.
 * When the session is disconnected/destroyed, a final call will be made to
 * the handler with a :ref:`session-event` notification.
 *
 */

GDK_API int GDKRPC_set_notification_handler(struct GDKRPC_session* session, GDKRPC_notification_handler handler, void *self_context);

GDK_API int GDKRPC_convert_json_to_string(const GDKRPC_json* json, char** output);

GDK_API int GDKRPC_convert_string_to_json(const char* input, GDKRPC_json** output);

GDK_API int GDKRPC_convert_json_value_to_string(const GDKRPC_json* json, const char* path, char** output);

GDK_API int GDKRPC_convert_json_value_to_uint32(const GDKRPC_json* json, const char* path, uint32_t* output);

GDK_API int GDKRPC_convert_json_value_to_uint64(const GDKRPC_json* json, const char* path, uint64_t* output);

GDK_API int GDKRPC_convert_json_value_to_bool(const GDKRPC_json* json, const char* path, uint32_t* output);

GDK_API int GDKRPC_convert_json_value_to_json(const GDKRPC_json* json, const char* path, GDKRPC_json** output);

GDK_API int GDKRPC_get_subaccounts(struct GDKRPC_session* session, GDKRPC_json** balance);

GDK_API int GDKRPC_get_subaccount(struct GDKRPC_session* session, uint32_t index, GDKRPC_json** balance);

/**
 * Free a GDKRPC_json object.
 *
 * :param json: GDKRPC_json object to free.
 */
GDK_API int GDKRPC_destroy_json(GDKRPC_json* json);

/**
 * Free a string returned by the api.
 *
 * :param str: The string to free.
 */
GDK_API void GDKRPC_destroy_string(char* str);

#endif /* SWIG */
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
GDK_API int GDKRPC_register_network(const char* name, const GDKRPC_json* network_details);

/**
 * Get the available network configurations
 *
 * :param output: Destination for the :ref:`networks-list`
 *|     Returned GDKRPC_json should be freed using `GA_destroy_json`.
 */
GDK_API int GDKRPC_get_networks(struct GDKRPC_session* session, GDKRPC_json** output);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GDK_GDK_RPC_H */
