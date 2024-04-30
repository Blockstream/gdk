#ifndef GDK_GDK_H
#define GDK_GDK_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

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

#ifdef __cplusplus
extern "C" {
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
 * Perform one-time initialization of the library. This call must be made once
 * only before calling any other GDK functions, including any functions called
 * from other threads.
 *
 * :param config: The :ref:`init-config-arg`.
 */
GDK_API int GA_init(const GA_json* config);

#ifndef SWIG
/**
 * Get any error details associated with the last error on the current thread.
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
 *|     The returned session should be freed using `GA_destroy_session`.
 *
 * Once created, the caller should set a handler for notifications using
 * `GA_set_notification_handler`, before calling `GA_connect` to connect the
 * session to the network for use.
 */
GDK_API int GA_create_session(struct GA_session** session);

#ifndef SWIG
/**
 * Set a handler to be called when notifications arrive for a session.
 *
 * :param session: The session to receive notifications for.
 * :param handler: The handler to receive notifications.
 * :param context: A context pointer to be passed to the handler.
 *
 * This call must be initially made on a session before `GA_connect`.
 * :ref:`ntf-notifications` may arrive on different threads, so the caller
 * must ensure that shared data is correctly locked within the handler.
 * The ``GA_json`` object passed to the caller must be destroyed by the
 * caller using `GA_destroy_json`. Failing to do so will result in
 * memory leaks.
 *
 * Once a session has been connected, this call can be made only with null
 * values for ``handler`` and ``context``. Once this returns, no further
 * notifications will be delivered for the lifetime of the session.
 *
 * The caller should not call session functions from within the callback
 * handler as this may block the application.
 */
GDK_API int GA_set_notification_handler(struct GA_session* session, GA_notification_handler handler, void* context);
#endif

/**
 * Free a session allocated by `GA_create_session`.
 *
 * :param session: The session to free.
 *
 * If the session was connected using `GA_connect` then this call will
 * disconnect it it before destroying it.
 */
GDK_API int GA_destroy_session(struct GA_session* session);

/**
 * Connect the session to the specified network.
 *
 * :param session: The session to connect.
 * :param net_params: The :ref:`net-params` of the network to connect to.
 *
 * This call connects to the remote network services that the session
 * requires, for example the Green servers or Electrum servers.
 * `GA_connect` must be called only once per session lifetime, after
 * `GA_create_session` and before `GA_destroy_session` respectively.
 * Once connected, the underlying network connection of the
 * session can be controlled using `GA_reconnect_hint`.
 *
 * Once the session is connected, use `GA_register_user` to create a new
 * wallet for the session, or `GA_login_user` to open an existing wallet.
 */
GDK_API int GA_connect(struct GA_session* session, const GA_json* net_params);

/**
 * Connect or disconnect a sessions underlying network connection.
 *
 * :param session: The session to use.
 * :param hint: the :ref:`reconnect` describing the desired reconnection behaviour.
 */
GDK_API int GA_reconnect_hint(struct GA_session* session, const GA_json* hint);

/**
 * Get the current proxy settings for the given session.
 *
 * :param session: The session to use.
 * :param output: Destination for the output :ref:`proxy-info`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_proxy_settings(struct GA_session* session, GA_json** output);

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
 *|     The call handlers result is :ref:`login-result`.
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
 * Refresh the sessions internal cache of Liquid asset information.
 *
 * Each release of GDK comes with a partial list of Liquid assets built-in.
 * This call is used to update it to include all the registered Liquid assets
 * or any new assets that have been registered since the last update.
 *
 * :param session: The session to use.
 * :param params: the :ref:`assets-params-data` of the server to connect to.
 */
GDK_API int GA_refresh_assets(struct GA_session* session, const GA_json* params);

/**
 *
 * Query the Liquid asset registry.
 *
 * This call is used to retrieve informations about a set of Liquid assets
 * specified by their asset id.
 *
 * :param session: The session to use.
 * :param params: the :ref:`get-assets-params` specifying the assets to query.
 * :param output: Destination for the output :ref:`asset-details`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_assets(struct GA_session* session, const GA_json* params, GA_json** output);

/**
 * Validate asset domain name.
 * (This is a interface stub)
 *
 */
GDK_API int GA_validate_asset_domain_name(struct GA_session* session, const GA_json* params, GA_json** output);

/**
 * Validate a gdk format JSON document.
 *
 * :param session: The session to use.
 * :param details: The :ref:`validate-details` to validate.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`validate-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call
 *completes.
 */
GDK_API int GA_validate(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Create a new user wallet.
 *
 * :param session: The session to use.
 * :param hw_device: :ref:`hw-device` or empty JSON for software wallet registration.
 * :param details: The :ref:`login-credentials` for software wallet registration.
 * :param call: Destination for the resulting GA_auth_handler to perform the registration.
 *|     The call handlers result is :ref:`login-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameters ``hw_device`` and ``details`` will be emptied when the call
 *completes.
 */
GDK_API int GA_register_user(
    struct GA_session* session, GA_json* hw_device, GA_json* details, struct GA_auth_handler** call);

/**
 * Authenticate to a user's wallet.
 *
 * :param session: The session to use.
 * :param hw_device: :ref:`hw-device` or empty JSON for software wallet login.
 * :param details: The :ref:`login-credentials` for authenticating the user.
 * :param call: Destination for the resulting GA_auth_handler to perform the login.
 *|     The call handlers result is :ref:`login-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * If a sessions underlying network connection has disconnected and
 * reconnected, the user will need to login again using this function. In
 * this case, the caller can pass empty JSON for both ``hw_device`` and
 * ``details`` to login using the previously passed credentials and device.
 *
 * .. note:: When calling from C/C++, the parameters ``hw_device`` and ``details`` will be emptied when the call
 *completes.
 */
GDK_API int GA_login_user(
    struct GA_session* session, GA_json* hw_device, GA_json* details, struct GA_auth_handler** call);

/**
 * Set or disable a watch-only login for a logged-in user wallet.
 *
 * :param session: The session to use.
 * :param username: The watch-only username to login with, or a blank string to disable.
 * :param password: The watch-only password to login with, or a blank string to disable.
 */
GDK_API int GA_set_watch_only(struct GA_session* session, const char* username, const char* password);

/**
 * Get the current watch-only login for a logged-in user wallet, if any.
 *
 * :param session: The session to use.
 * :param username: Destination for the watch-only username. Empty string if not set.
 *|     Returned string should be freed using `GA_destroy_string`.
 */
GDK_API int GA_get_watch_only_username(struct GA_session* session, char** username);

/**
 * Remove and delete the server history of a wallet.
 *
 * :param session: The session to use.
 * :param call: Destination for the resulting GA_auth_handler to perform the removal.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * For multisig Green sessions, removing a wallet removes all history and
 * data associated with the wallet on the server. This operation cannot be
 * undone, and re-registering the wallet will not bring back the wallet's
 * history. For this reason, only empty wallets can be deleted.
 *
 * For singlesig sessions, removing a wallet removes the locally persisted cache.
 * The actual removal will happen after `GA_destroy_session` is called.
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
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_create_subaccount(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get the user's subaccount details.
 *
 * :param session: The session to use.
 * :param details: the :ref:`get-subaccounts-params-data` controlling the request.
 * :param call: Destination for the resulting GA_auth_handler to perform the creation.
 *|     The call handlers result is :ref:`subaccount-list`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_get_subaccounts(struct GA_session* session, const GA_json* details, struct GA_auth_handler** call);

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
 * Update subaccount information.
 *
 * :param session: The session to use.
 * :param details: :ref:`subaccount-update` giving the details to update.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes
 */
GDK_API int GA_update_subaccount(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get a page of the user's transaction history.
 *
 * :param session: The session to use.
 * :param details: :ref:`transactions-details` giving the details to get the transactions for.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 *
 * .. note:: Transactions are returned as :ref:`tx-list` from newest to oldest with up to 30 transactions per page.
 */
GDK_API int GA_get_transactions(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get a new address to receive coins to.
 *
 * :param session: The session to use.
 * :param details: :ref:`receive-address-request`.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`receive-address-details`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_get_receive_address(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get a page of addresses previously generated for a subaccount.
 *
 * :param session: The session to use.
 * :param details: :ref:`previous-addresses-request` detailing the previous addresses to fetch.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`previous-addresses`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 *
 * .. note:: Iteration of all addresses is complete when 'last_pointer' is not
 *|     present in the results.
 */
GDK_API int GA_get_previous_addresses(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get the user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-request` detailing the unspent transaction outputs to fetch.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`unspent-outputs`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_get_unspent_outputs(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get the unspent transaction outputs associated with a non-wallet private key.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-private-request` detailing the private key to check.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`unspent-outputs`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: Neither the private key or its derived public key are sent to any third party for this call.
 */
GDK_API int GA_get_unspent_outputs_for_private_key(
    struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Change the status of a user's unspent transaction outputs.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-status` detailing the unspent transaction outputs status to set.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_set_unspent_outputs_status(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

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
 * Get the sum of unspent outputs paying to a subaccount.
 *
 * :param session: The session to use.
 * :param details: :ref:`unspent-outputs-request` detailing the unspent transaction outputs to
 *|    compute the balance from.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_get_balance(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get the list of allowed currencies for all available pricing sources.
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
 * Encrypt JSON with a server provided key protected by a PIN.
 *
 * :param session: The session to use.
 * :param details: The :ref:`encrypt-with-pin-details` to encrypt.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`encrypt-with-pin-result` which the caller should persist.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_encrypt_with_pin(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Decrypt JSON with a server provided key protected by a PIN.
 *
 * :param session: The session to use.
 * :param details: The :ref:`decrypt-with-pin-details` to decrypt.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is the decrypted JSON.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_decrypt_with_pin(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Disable all PIN logins previously set.
 *
 * After calling this method, the user will not be able to login with PIN
 *| from any device that was previously enabled using `GA_encrypt_with_pin`.
 *
 * :param session: The session to use.
 */
GDK_API int GA_disable_all_pin_logins(struct GA_session* session);

/**
 * Construct a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`create-tx-details` for constructing.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``transaction_details`` will be emptied when the call completes.
 */
GDK_API int GA_create_transaction(
    struct GA_session* session, GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Blind a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`create-tx-details` for blinding.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``transaction_details`` will be emptied when the call completes.
 */
GDK_API int GA_blind_transaction(
    struct GA_session* session, GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Sign the user's inputs to a transaction.
 *
 * :param session: The session to use.
 * :param transaction_details: The :ref:`sign-tx-details` for signing, as previously
 *|     returned from `GA_create_transaction` or (for Liquid) `GA_blind_transaction`.
 * :param call: Destination for the resulting GA_auth_handler to perform the signing.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``transaction_details`` will be emptied when the call completes.
 */
GDK_API int GA_sign_transaction(
    struct GA_session* session, GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Construct the initiators side of a swap transaction.
 *
 * :param session: The session to use.
 * :param swap_details: The :ref:`create-swap-tx-details` for constructing.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`create-swap-tx-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_create_swap_transaction(
    struct GA_session* session, const GA_json* swap_details, struct GA_auth_handler** call);

/**
 * Complete construction of the callers side of a swap transaction.
 *
 * :param session: The session to use.
 * :param swap_details: The :ref:`complete-swap-tx-details` for completing.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`complete-swap-tx-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 */
GDK_API int GA_complete_swap_transaction(
    struct GA_session* session, const GA_json* swap_details, struct GA_auth_handler** call);

/**
 * Sign one or more of a user's inputs in a PSBT or PSET.
 *
 * :param session: The session to use.
 * :param details: The :ref:`sign-psbt-details` for signing.
 * :param call: Destination for the resulting GA_auth_handler to perform the signing.
 *|     The call handlers result is :ref:`sign-psbt-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 *
 * .. note:: EXPERIMENTAL warning: this call may be changed in future releases.
 */
GDK_API int GA_psbt_sign(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/* Experimental API: not for public use */
GDK_API int GA_psbt_from_json(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Get wallet details of a PSBT or PSET.
 *
 * :param session: The session to use.
 * :param details: The :ref:`psbt-wallet-details` for getting the wallet details.
 * :param call: Destination for the resulting GA_auth_handler to get the wallet details.
 *|     The call handlers result is :ref:`psbt-get-details-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 *
 * .. note:: EXPERIMENTAL warning: this call may be changed in future releases.
 */
GDK_API int GA_psbt_get_details(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Broadcast a fully signed transaction to the P2P network.
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
 *
 * .. note:: When calling from C/C++, the parameter ``transaction_details`` will be emptied when the call completes.
 */
GDK_API int GA_send_transaction(
    struct GA_session* session, GA_json* transaction_details, struct GA_auth_handler** call);

/**
 * Sign a message with the private key of an address.
 *
 * :param session: The session to use.
 * :param details: The :ref:`sign-message-request` detailing the message to sign and how to sign it.
 * :param call: Destination for the resulting GA_auth_handler to perform the signing.
 *|     The call handlers result is :ref:`sign-message-result`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_sign_message(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

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
 *
 * .. note:: When calling from C/C++, the parameter ``locktime_details`` will be emptied when the call completes.
 */
GDK_API int GA_set_csvtime(struct GA_session* session, GA_json* locktime_details, struct GA_auth_handler** call);

/**
 * Set the number of blocks after which nLockTime transactions become
 *|    spendable without two factor authentication. When this call
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
 * Get the user's credentials.
 *
 * :param session: The session to use.
 * :param details: The :ref:`get-credentials-details` to get the credentials.
 * :param call: Destination for the resulting GA_auth_handler to get the user's credentials.
 *|     The call handlers result is :ref:`login-credentials`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_get_credentials(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

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
 * :param config: Destination for the returned :ref:`twofactor_configuration`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_twofactor_config(struct GA_session* session, GA_json** config);

/**
 * Change wallet settings.
 *
 * :param session: The session to use.
 * :param settings: The new :ref:`settings` values.
 * :param call: Destination for the resulting GA_auth_handler.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``settings`` will be emptied when the call completes.
 */
GDK_API int GA_change_settings(struct GA_session* session, GA_json* settings, struct GA_auth_handler** call);

/**
 * Get current wallet settings.
 *
 * :param session: The session to use.
 * :param settings: Destination for the current :ref:`settings`.
 *|     Returned GA_json should be freed using `GA_destroy_json`.
 */
GDK_API int GA_get_settings(struct GA_session* session, GA_json** settings);

#ifndef SWIG
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
 * :param method: The two factor method to enable/disable, e.g. ``"email"``, ``"sms"``, ``"phone"``, ``"gauth"``
 * :param twofactor_details: :ref:`twofactor-detail` giving the two factor method and associated data.
 * :param call: Destination for the resulting GA_auth_handler to perform the action
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``twofactor_details`` will be emptied when the call completes.
 */
GDK_API int GA_change_settings_twofactor(
    struct GA_session* session, const char* method, GA_json* twofactor_details, struct GA_auth_handler** call);

/**
 * Request to begin the two factor authentication reset process.
 *
 * Returns the ``"twofactor_reset"`` portion of :ref:`twofactor_configuration` in
 * the GA_auth_handler result.
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
 * Returns the ``"twofactor_reset"`` portion of :ref:`twofactor_configuration` in
 * the GA_auth_handler result.
 *
 * :param session: The session to use.
 * :param email: The email address to cancel the reset request for. Must be
 *|     the email previously passed to `GA_twofactor_reset`.
 * :param call: Destination for the resulting GA_auth_handler to request the reset.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: Unlike `GA_twofactor_cancel_reset`, this call only removes the reset
 *|     request associated with the given email. If other emails have requested
 *|     a reset, the wallet will still remain locked following this call.
 */
GDK_API int GA_twofactor_undo_reset(struct GA_session* session, const char* email, struct GA_auth_handler** call);

/**
 * Cancel all two factor reset requests and unlock the wallet for normal operation.
 *
 * This call requires authentication using an existing wallet twofactor method.
 *
 * Returns the ``"twofactor_reset"`` portion of :ref:`twofactor_configuration` in
 * the GA_auth_handler result.
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
 * :param limit_details: :ref:`transaction-limits` containing the new limits to set.
 * :param call: Destination for the resulting GA_auth_handler to perform the change.
 *|     The call handlers result is :ref:`transaction-limits`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``limit_details`` will be emptied when the call completes.
 */
GDK_API int GA_twofactor_change_limits(
    struct GA_session* session, GA_json* limit_details, struct GA_auth_handler** call);

/**
 * Encode CBOR into (potentially multi-part) UR-encoding.
 *
 * :param session: The session to use.
 * :param details: :ref:`bcur-encode` containing the CBOR data to encode.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`bcur-encoded`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_bcur_encode(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

/**
 * Decode (potentially multi-part) UR-encoded data to CBOR.
 *
 * :param session: The session to use.
 * :param details: :ref:`bcur-decode` containing the the first URI to decode.
 * :param call: Destination for the resulting GA_auth_handler to complete the action.
 *|     The call handlers result is :ref:`bcur-decoded`.
 *|     Returned GA_auth_handler should be freed using `GA_destroy_auth_handler`.
 *
 * For multi-part data, the call hander will request further parts using
 * ``"request_code"`` with a method of ``"data"``. see: `auth-handler-status` for
 * details on the general mechanism and `bcur-decode-auth-handler-status` for
 * details on the data passed to and expected from the auth handler.
 *
 * .. note:: When calling from C/C++, the parameter ``details`` will be emptied when the call completes.
 */
GDK_API int GA_bcur_decode(struct GA_session* session, GA_json* details, struct GA_auth_handler** call);

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
