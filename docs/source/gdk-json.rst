GDK JSON
========

This section describes the various JSON formats used by the library.

.. _init-config-arg:

Initialization config JSON
--------------------------

Passed to `GA_init` when initializing the library.

.. code-block:: json

   {
      "datadir": "/path/to/store/data",
      "tordir": "/path/to/store/tor/data",
      "registrydir": "/path/to/store/registry/data",
      "log_level": "info",
      "with_shutdown": true
   }

:datadir: Mandatory. A directory which gdk will use to store encrypted data
          relating to sessions.
:tordir: Optional. The directory for tor state data, used when the internal tor
         implementation is enabled in :ref:`net-params`. Note that each process
         using the library at the same time requires its own distinct directory.
         If not given, a sub-directory ``"tor"`` inside ``"datadir"`` is used.
:registrydir: Optional. The directory for the registry data, used when the network
         is liquid based. Note that each process using the library at the same
         time requires its own distinct directory. If not given, a
         sub-directory ``"registry"`` inside ``"datadir"`` is used.
:log_level: Optional. The library logging level, one of ``"debug"``, ``"info"``, ``"warn"``,
           ``"error"``, or ``"none"``. Default: ``"none"``.
:with_shutdown: Optional. If ``true``, the caller will call `GA_shutdown` before
                the application exits. This enables sessions that use tor to be closed
                and re-opened repeatedly. If ``false``, `GA_shutdown` has no
                effect and does not need to be called. Default: ``false``.

.. _net-params:

Connection parameters JSON
--------------------------

.. code-block:: json

   {
      "name": "testnet",
      "proxy": "localhost:9150",
      "use_tor": true,
      "user_agent": "green_android v2.33",
      "spv_enabled": false,
      "min_fee_rate": 1000,
      "cert_expiry_threshold": 1
      "gap_limit": 20,
      "electrum_url": "blockstream.info:993",
      "electrum_onion_url": "explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:143",
      "electrum_tls": true,
   }

:name: The name of the network to connect to. Must match a key from :ref:`networks-list`.
:proxy: The proxy connection to pass network traffic through, if any.
:use_tor: ``true`` to enable Tor connections, ``false`` otherwise. If enabled
          and a proxy is not given, a Tor connection will be started internally.
          If a proxy is given and Tor is enabled, the proxy must support
          resolving ``".onion"`` domains.
:user_agent: The user agent string to pass to the server for multisig connections.
:spv_enabled: ``true`` to enable SPV verification for the session, ``false`` otherwise.
:min_fee_rate: ``null`` to use the default minimum fee (which can change according to
    the network conditions), or an integer giving the fee rate in satoshis per 1000 bytes.
    Note that overriding the default fee rate only affects transaction construction; the
    rates returned by fee notifications remain those of the underlying network.
:cert_expiry_threshold: Ignore certificates expiring within this many days from today. Used to pre-empt problems with expiring embedded certificates.
:gap_limit: Optional, singlesig only. Number of consecutive empty scripts/addresses to monitor. Defaults to 20.
:electrum_url: Optional. For singlesig the Electrum server used to fetch blockchain data. For multisig the Electrum server used for SPV verification. Default value depends on the network.
:electrum_onion_url: Optional. If ``"use_tor"`` is ``true``, this value is used instead of ``"electrum_url"``. Default value depends on the network.
:electrum_tls: Optional. Use TLS to connect to the Electrum server. Default value depends on the network (``false`` for local networks, ``true`` otherwise).

.. note:: When ``"use_tor"`` is ``true``, the caller should pass ``"with_shutdown"`` as ``true`` in
   the :ref:`init-config-arg` passed to `GA_init`, and call `GA_shutdown` on application
   exit if more than one session will be created, or if sessions may be created/destroyed repeatedly.

 .. _proxy-info:

Proxy Settings JSON
-------------------

Contains the proxy settings in use by a session.

.. code-block:: json

   {
      "proxy": "localhost:9150",
      "use_tor": true
   }

:proxy: The proxy connection being used to pass network traffic through, or an empty string.
:use_tor: ``true`` if Tor is enabled, ``false`` otherwise.


 .. _login-credentials:

Login credentials JSON
----------------------

Contains the authentication details used to create and login to a wallet
via `GA_register_user` or `GA_login_user`. Also returned from `GA_get_credentials`
where it contains the credentials used to login, and for Liquid sessions, the
element ``"master_blinding_key"`` will be present and hold the
wallets `SLIP 77 <https://github.com/satoshilabs/slips/blob/master/slip-0077.md>`_
master blinding key if it is available.

To authenticate with a hardware wallet, pass empty JSON and provide :ref:`hw-device`.

To authenticate with a mnemonic and optional password:

.. code-block:: json

   {
      "mnemonic": "moral lonely ability sail balance simple kid girl inhale master dismiss round about aerobic purpose shiver silly happy kitten track kind pattern nose noise",
      "password": ""
   }

Or, with a mnemonic and optional BIP39 passphrase:

.. code-block:: json

   {
      "mnemonic": "moral lonely ability sail balance simple kid girl inhale master dismiss round about aerobic purpose shiver silly happy kitten track kind pattern nose noise",
      "bip39_passphrase": ""
   }

To authenticate with a PIN:

.. code-block:: json

   {
      "pin": "123456",
      "pin_data": {
          "encrypted_data": "0b39c1e90ca6adce9ff35d1780de74b91d46261a7cbf2b8d2fdc21528c068c8e2b26e3bf3f6a2a992e0e1ecfad0220343b9659495e7f4b21ff95c32cee1b2dd6b0f44b3828ccdc73d68d9e4142a25437b0c6b53a056e2415ca23442dd18d11fb5f62ef9155703c36a5b3e10b2d93973602cebb2369559612cb4267f4826028cea7b067d6ec3658cc72155a4b17b4ba277c143d40ce49c407102c62ca759d04e74dd0778ac514292be09f66449993c36b0bc0cb78f41368bc394d0cf444d452bea0e7df5766b92a3c3a3c57169c2529e9aa36e89b3f6dfcfddc6027f3aabd47dedbd9851729a3f6fba899842b1f5e949117c62e94f558da5ebd37feb4927209e2ead2d492c1d647049e8a1347c46c75411a14c5420ef6896cd0d0c6145af76668d9313f3e71e1970de58f674f3b387e4c74d24214fbc1ad7d30b3d2db3d6fb7d9e92dd1a9f836dad7c2713dc6ebfec62f",
          "pin_identifier": "38e2f188-b3a8-4d98-a7f9-6c348cb54cfe",
          "salt": "a99/9Qy6P7ON4Umk2FafVQ=="
       }
   }

:pin: The PIN entered by the user to unlock the wallet.
:pin_data: See :ref:`pin-data`.

To authenticate a watch-only user:

.. code-block:: json

   {
      "username": "my_watch_only_username",
      "password": "my_watch_only_password"
   }

To authenticate a descriptor watch-only wallet (singlesig only):

.. code-block:: json

   {
      "core_descriptors": ["pkh([00000000/44'/1'/0']tpubDC2Q4xK4XH72J7Lkp6kAvY2Q5x4cxrKgrevkZKC2FwWZ9A9qA5eY6kvv6QDHb6iJtByzoC5J8KZZ29T45CxFz2Gh6m6PQoFF3DqukrRGtj5/0/*"],
   }

Or alternatively:

.. code-block:: json

   {
      "slip132_extended_pubkeys": ["tpubDC2Q4xK4XH72J7Lkp6kAvY2Q5x4cxrKgrevkZKC2FwWZ9A9qA5eY6kvv6QDHb6iJtByzoC5J8KZZ29T45CxFz2Gh6m6PQoFF3DqukrRGtj5"],
   }

The values to use for ``"core_descriptors"`` and ``"slip132_extended_pubkeys"`` can be
obtained by calling `GA_get_subaccount` from a non-descriptor watch-only session.


.. _login-result:

Register/Login result JSON
--------------------------

Contains wallet identifiers and any warnings resulting from registering or
logging in to a wallet with `GA_register_user`/`GA_login_user`. Also returned
by `GA_get_wallet_identifier` to get identifiers without logging in.

.. include:: examples/login_user.json

:wallet_hash_id: A 32 byte, per-network unique identifier for the wallet, as a hex string.
:xpub_hash_id: A 32 byte, cross-network unique identifier for the wallet, as a hex string.
:warnings: An array of warning strings for the wallet/GDK version, or empty if there are no warnings. Only returned when registering or logging in.


.. _hw-device:

HW device JSON
--------------

Describes the capabilities of an external signing device.

.. code-block:: json

   {
      "device": {
         "name": "Ledger",
         "supports_ae_protocol": 0,
         "supports_arbitrary_scripts": true,
         "supports_host_unblinding": false,
         "supports_external_blinding": false,
         "supports_liquid": 1,
         "supports_low_r": false,
         "supports_p2tr": false,
         "supports_liquid_p2tr": false
      }
   }

:name: The unique name of the hardware device.
:supports_arbitrary_scripts: True if the device can sign non-standard scripts such as CSV.
:supports_low_r: True if the device can produce low-R ECDSA signatures. Note that
                 all signing devices must produce low-S signatures to comply with
                 network standardness rules.
:supports_liquid: 0 if the device does not support Liquid, 1 otherwise.
:supports_host_unblinding: True if the device supports returning the Liquid master blinding key.
:supports_external_blinding: True if the device supports blinding and signing Liquid transactions
    with outputs that are already blinded from another wallet (e.g. 2-step swaps).
:supports_ae_protocol: See "ae_protocol_support_level" enum  in the gdk source for details.
:supports_p2tr: True if the device can sign Bitcoin BIP-341 taproot inputs.
:supports_liquid_p2tr: True if the device can sign Liquid/Elements BIP-341 taproot inputs.

The default for any value not provided is false or 0.


.. _pin-data:

PIN data JSON
-------------

Contains the data returned by `GA_encrypt_with_pin`. The caller must persist this
data and pass it to `GA_login_user` along with the users PIN in order to
allow a PIN login.

.. code-block:: json

   {
      "encrypted_data": "0b39c1e90ca6adce9ff35d1780de74b91d46261a7cbf2b8d2fdc21528c068c8e2b26e3bf3f6a2a992e0e1ecfad0220343b9659495e7f4b21ff95c32cee1b2dd6b0f44b3828ccdc73d68d9e4142a25437b0c6b53a056e2415ca23442dd18d11fb5f62ef9155703c36a5b3e10b2d93973602cebb2369559612cb4267f4826028cea7b067d6ec3658cc72155a4b17b4ba277c143d40ce49c407102c62ca759d04e74dd0778ac514292be09f66449993c36b0bc0cb78f41368bc394d0cf444d452bea0e7df5766b92a3c3a3c57169c2529e9aa36e89b3f6dfcfddc6027f3aabd47dedbd9851729a3f6fba899842b1f5e949117c62e94f558da5ebd37feb4927209e2ead2d492c1d647049e8a1347c46c75411a14c5420ef6896cd0d0c6145af76668d9313f3e71e1970de58f674f3b387e4c74d24214fbc1ad7d30b3d2db3d6fb7d9e92dd1a9f836dad7c2713dc6ebfec62f",
      "pin_identifier": "38e2f188-b3a8-4d98-a7f9-6c348cb54cfe",
      "salt": "a99/9Qy6P7ON4Umk2FafVQ=="
   }


.. _encrypt-with-pin-details:

Encrypt with PIN JSON
---------------------

.. code-block:: json

   {
      "pin": "...",
      "plaintext": {}
   }

:pin: The PIN to protect the server provided key.
:plaintext: The json to encrypt. For instance it can be the :ref:`login-credentials` with the mnemonic.


.. _encrypt-with-pin-result:

Encrypt with PIN Result JSON
----------------------------

.. code-block:: json

   {
      "pin_data": "...",
   }

:pin_data: See :ref:`pin-data`.


.. _decrypt-with-pin-details:

Decrypt with PIN JSON
---------------------

.. code-block:: json

   {
      "pin": "...",
      "pin_data": "...",
   }

:pin: The PIN that protects the server provided key.
:pin_data: See :ref:`pin-data`.


.. _rsa-verify:

RSA Verify JSON
---------------

Contains the details required to perform RSA challenge verification by `GA_rsa_verify`.

.. code-block:: json

   {
      "pem": "...",
      "challenge": "...",
      "signature": "..."
   }

:pem: The PEM containing the public key that ``"signature"`` should sign for.
:challenge: The challenge that ``"signature"`` should be a valid signature for, hex encoded.
:signature: The signature that signs ``"challenge"`` with the private key corresponding to the public key in ``"pem"``, hex encoded.


.. _rsa-verify-result:

RSA Verify Result JSON
----------------------

Contains the result of an RSA challenge verification by `GA_rsa_verify`.

.. code-block:: json

   {
      "result": true,
      "error": ""
   }

:result: ``true`` if the verification succeeded, ``false`` otherwise.
:error: A text description of the error that occurred, if any. When empty, the
    ``"result"`` value alone determines whether verification succeeded.


.. _wallet-id-request:

Wallet identifier request JSON
------------------------------

Describes the wallet to compute an identifier for using `GA_get_wallet_identifier`.
You may pass :ref:`login-credentials` to compute an identifier from a mnemonic
and optional password, note that PIN or watch-only credentials cannot be used.
otherwise, pass the wallets master xpub as follows:

.. code-block:: json

   {
      "master_xpub": "tpubD8G8MPH9RK9uk4EV97RxhzaY8SJPUWXnViHUwji92i8B7vYdht797PPDrJveeathnKxonJe8SbaScAC1YJ8xAzZbH9UvywrzpQTQh5pekkk",
   }

:master_xpub: The base58-encoded BIP32 extended master public key of the wallet.


 .. _get-credentials-details:

Get credentials JSON
----------------------

Accepts an optional password to encrypt the mnemonic.

.. code-block:: json

   {
      "password": ""
   }


.. _subaccount-detail:

Subaccount JSON
---------------

Describes a subaccount within the users wallet. Returned by `GA_get_subaccount` and
as the array elements of `GA_get_subaccounts`.

.. include:: examples/get_subaccount_multisig.json
.. include:: examples/get_subaccount_singlesig.json
.. include:: examples/get_subaccount_multisig_liquid.json
.. include:: examples/get_subaccount_singlesig_liquid.json

:hidden: Whether the subaccount is hidden.
:name: The name of the subaccount.
:pointer: The subaccount number.
:receiving_id: The Green receiving ID for the subaccount.
:recovery_xpub: For ``"2of3"`` subaccounts, the BIP32 xpub of the users recovery
    key. For all other subaccount types this value is empty.
:required_ca: For ``"2of2_no_recovery"`` subaccounts, the number of confidential addresses
    that the user must upload to the server before transacting.
:type: For multisig subaccounts, one of ``"2of2"``, ``"2of3"`` or ``"2of2_no_recovery"``.
    For singlesig subaccounts, one of ``"p2pkh"``, ``"p2wpkh"``, ``"p2sh-p2wpkh"`` or ``"p2tr"``.
:bip44_discovered: Singlesig only. Whether or not this subaccount contains at least one transaction.
:user_path: The BIP32 path for this subaccount.
:core_descriptors: Singlesig only. The Bitcoin Core compatible output descriptors.
    One for the external chain and one for internal chain (change),
    for instance ``"sh(wpkh(tpubDC2Q4xK4XH72H18SiEV2A6HUwUPLhXiTEQXU35r4a41ZVrUv2cgKUMm2fsKTapi8DH4Y8ZVjy8TQtmyWMuH37kjw8fQGJahjWbuQoPm6qRF/0/*))"``
    ``"sh(wpkh(tpubDC2Q4xK4XH72H18SiEV2A6HUwUPLhXiTEQXU35r4a41ZVrUv2cgKUMm2fsKTapi8DH4Y8ZVjy8TQtmyWMuH37kjw8fQGJahjWbuQoPm6qRF/1/*))"``
    for a ``p2sh-p2wpkh`` subaccount.
:slip132_extended_pubkey: Singlesig and Bitcoin only. The extended public key with modified version
    as specified in SLIP-0132 (xpub, ypub, zpub, tpub, upub, vpub).
    Use of this value is discouraged and this field might be removed in the future.
    Callers should use descriptors instead.

.. note:: Ledger sets some xpub fields incorrectly (e.g. always sets child number ``"0"``).
   Thus if you're using a Ledger device the returned ``"core_descriptors"`` and ``"slip132_extended_pubkey"``
   are "incorrect", meaning that the xpub is different from xpubs returned by other signers
   using the same secret (but the generated addresses are the same).


.. _subaccount-update:

Subaccount update JSON
----------------------

Describes updates to be made to a subaccount via `GA_update_subaccount`.

.. code-block:: json

   {
     "hidden": true,
     "name": "New name",
     "subaccount": 1
   }

:hidden: If present, updates whether the subaccount will be marked hidden.
:name: If present, updates the name of the subaccount.
:subaccount: The subaccount to update.



.. _subaccount-list:

Subaccounts list JSON
---------------------

.. code-block:: json

  {
    "subaccounts": [
      { },
      { }
    ]
  }

:subaccounts: An array of :ref:`subaccount-detail` elements for each of the users subaccounts.

.. _tx-list:

Transaction list JSON
---------------------

Describes a users transaction history returned by `GA_get_transactions`.

.. include:: examples/get_transactions_multisig.json
.. include:: examples/get_transactions_singlesig.json
.. include:: examples/get_transactions_multisig_liquid.json
.. include:: examples/get_transactions_singlesig_liquid.json


:transactions: Top level container for the users transaction list.
:block_height: The network block height that the transaction was confirmed
    in, or ``0`` if the transaction is in the mempool.
:can_cpfp: A boolean indicating whether the user can CPFP the transaction.
:can_rbf: A boolean indicating whether the use can RBF (bump) the transaction fee.
:created_at_ts: The timestamp in microseconds from the Unix epoch when the transaction
    was seen by gdk or Green servers, or included in a block.
:fee: The BTC or L-BTC network fee paid by the transaction in satoshi.
:fee_rate: The fee rate in satoshi per thousand bytes.
:inputs: See :ref:`tx-list-input`.
:memo: The users memo, if previously set by `GA_set_transaction_memo`.
:outputs: See :ref:`tx-list-output`.
:rbf_optin: A boolean indicating whether the transaction is RBF-enabled.
:satoshi: A map of asset names to the signed satoshi total for that asset in the
    transaction. Negative numbers represent outgoing amounts, positive incoming.
:spv_verified: The SPV status of the transaction, one of ``"in_progress"``, ``"verified"``,
    ``"not_verified"``, ``"disabled"``, ``"not_longest"`` or ``"unconfirmed"``.
:transaction_vsize: The size of the transaction in vbytes.
:transaction_weight: The weight of the transaction.
:txhash: The txid of the transaction.
:type: One of ``"incoming"``, ``"outgoing"``, ``"mixed"`` or ``"not unblindable"``.


.. _tx-list-input:

Transaction list input element
------------------------------

Describes a transaction input in :ref:`tx-list`.

.. include:: examples/get_transactions_input_multisig.json
.. include:: examples/get_transactions_input_singlesig.json
.. include:: examples/get_transactions_input_multisig_liquid.json
.. include:: examples/get_transactions_input_singlesig_liquid.json


:address: For user wallet addresses, the wallet address in base58, bech32 or blech32 encoding.
:addressee: Optional, multisig only. For historical social payments, the account name sent from.
:address_type: For user wallet addresses, One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``, ``"p2tr"`` (singlesig), indicating
    the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:is_output: Always false. Deprecated, will be removed in a future release.
:is_relevant: A boolean indicating whether the input relates to the subaccount the
    caller passed to `GA_get_transactions`.
:is_spent: Always true. Deprecated, will be removed in a future release.
:pointer: For user wallet addresses, the address number/final number in the address derivation path.
:pt_idx: Deprecated, will be removed in a future release.
:satoshi: The amount of the input in satoshi.
:subaccount: For user wallet addresses, the subaccount this output belongs to, or ``0``.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks used in the receiving scriptpubkey.

Liquid inputs have additional fields:

:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:commitment: The hex-encoded value commitment.
:is_blinded: A boolean indicating whether or not the input is blinded.
:nonce_commitment: The hex-encoded nonce commitment.
:previdx: The output index of the transaction containing the output representing this input.
:prevpointer: Deprecated, will be removed in a future release.
:prevsubaccount: Deprecated, will be removed in a future release.
:prevtxhash: The txid of the transaction containing the output representing this input.
:script: The scriptpubkey of the output representing this input.


.. _tx-list-output:

Transaction list output element
-------------------------------

Describes a transaction output in :ref:`tx-list`.

.. include:: examples/get_transactions_output_multisig.json
.. include:: examples/get_transactions_output_singlesig.json
.. include:: examples/get_transactions_output_multisig_liquid.json
.. include:: examples/get_transactions_output_singlesig_liquid.json


:address: For user wallet addresses, the wallet address in base58, bech32 or blech32 encoding.
:address_type: For user wallet output addresses, One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``, ``"p2tr"`` (singlesig), indicating
    the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:is_output: Always true. Deprecated, will be removed in a future release.
:is_relevant: A boolean indicating whether the output relates to the subaccount the
    caller passed to `GA_get_transactions`.
:is_spent: A boolean indicating if this output has been spent.
:pointer: For user wallet addresses, the address number/final number in the address derivation path.
:pt_idx: Deprecated, will be removed in a future release.
:satoshi: The amount of the output in satoshi.
:subaccount: For user wallet addresses, the subaccount this output belongs to, or ``0``.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks used in the receiving scriptpubkey.


Liquid outputs have the following additional fields:

:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:blinding_key: The blinding public key for the output.
:commitment: The hex-encoded value commitment.
:is_blinded: For user wallet outputs, a boolean indicating whether or not the output is blinded.
:is_confidential: Whether or not the address in ``"address"`` is a confidential address. Note that this does not indicate whether the output was originally sent to a confidential address (which is determined by ``"is_blinded"``), only whether the ``"address"`` field is a confidential or non-confidential address, i.e. whether it contains the blinding public key or not.
:nonce_commitment: The hex-encoded nonce commitment.
:script: For user wallet outputs, the scriptpubkey of this output.
:unconfidential_address: For user wallet outputs, the non-confidential address
    corresponding to ``address``. This is provided for informational purposes
    only and should not be used to receive.


.. _external-tx-detail:

Transaction details JSON
------------------------

Contains information about a transaction that may not be associated with the
users wallet. Returned by `GA_get_transaction_details`.

.. include:: examples/get_transaction_details_multisig.json
.. include:: examples/get_transaction_details_singlesig.json
.. include:: examples/get_transaction_details_multisig_liquid.json
.. include:: examples/get_transaction_details_singlesig_liquid.json


.. _sign-tx-details:

Sign transaction JSON
---------------------

Contains the details of a caller-generated transaction to sign.

To sign with a specific sighash, set ``"user_sighash"`` for the elements of
``"transaction_inputs"`` you wish to sign with a certain sighash, otherwise
``SIGHASH_ALL`` (``1``) will be used.

Set ``"skip_signing"`` to ``true`` for any input in ``"transaction_inputs"``
you do not wish to have signed.

All other fields are not user-editable and should be passed unchanged.


.. _send-tx-details:

Send transaction JSON
---------------------

Contains the details of a caller-generated and signed transaction
from `GA_sign_transaction` to send to the network.

For multisig session, this will send via the Green backend service, signing
any inputs that require service signatures before broadcasting.

All fields are not user-editable and should be passed unchanged.


.. _broadcast-transaction-details:

Broadcast transaction JSON
--------------------------

Contains the details of a caller-generated and fully signed transaction
to send to the network via `GA_broadcast_transaction`.

Unlike `GA_send_transaction`, this call does not sign the server side of
Green multisig inputs before broadcasting. The caller must ensure the
transaction/PSBT is fully signed before calling.

This call can be used to broadcast transactions that are not related to the
users wallet. The ``"memo"`` element should be ommitted or blank in this case.

.. code-block:: json

  {
    "transaction": "<transaction hex>",
    "psbt": "<base64 PSBT>",
    "memo": "sample memo",
    "simulate_only": false
  }

:transaction: Optional. The fully signed transaction to broadcast, hex
    encoded. If not given, the ``"psbt"`` element must be present.
:psbt: Optional. The fully signed PSBT or PSET representing the transaction to
    broadcast. If not given, the ``"transaction"`` element must be present.
:memo: Optional. A transaction memo to store with the transaction. Should only be
    provided for transactions which include at least one wallet input or output.
:simulate_only: Optional, defaults to ``false``. If set to ``true``, any PSBT given
    is finalized and extracted to populate the resulting ``"transaction"`` element.
    The ``"transaction"`` element is then parsed, and if valid, is returned (along
    with the finalized PSBT in the resulting ``"psbt"`` element if one was provided).


.. _broadcast-transaction-result:

Broadcast transaction result JSON
---------------------------------

Contains the result of calling `GA_broadcast_transaction`.

The returned data is a copy of the :ref:`broadcast-transaction-details` given
when calling `GA_broadcast_transaction`, modified as follows:

- The ``"txhash"`` element is populated with the txid of the transaction.
- If a ``"psbt"`` element was given, the value is updated to contain the
  given PSBT after finalization, and a ``"transaction"`` element is added
  containing the extracted final transaction hex.


.. _create-swap-tx-details:

Create Swap Transaction JSON
----------------------------

Describes the swap to be created when calling `GA_create_swap_transaction`.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v1",
    "liquidex_v1": {},
    "output_type": "liquidex_v1"
  }

:swap_type: Pass ``"liquidex"`` to create the maker's side of a LiquiDEX 2-step swap.
:input_type: Pass ``"liquidex_v1"`` to pass LiquiDEX version 1 details.
:liquidex_v1: The LiquiDEX v1 specific parameters, see :ref:`liquidex-v1-create-details`.
              This field must included only if ``"input_type"`` is ``"liquidex_v1"``.
:output_type: Pass ``"liquidex_v1"`` to return LiquiDEX proposal JSON version 1.

.. _create-swap-tx-result:

Create Swap Transaction Result JSON
-----------------------------------

If the ``"output_type"`` was ``"liquidex_v1"`` this field is `liquidex-v1-create-result`.


.. _complete-swap-tx-details:

Complete Swap Transaction JSON
------------------------------

Describes the swap to be completed when calling `GA_complete_swap_transaction`.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v1",
    "liquidex_v1": {},
    "output_type": "transaction",
    "utxos": {},
  }

:swap_type: Pass ``"liquidex"`` to complete the taker's side of a LiquiDEX 2-step swap.
:input_type: Pass ``"liquidex_v1"`` to pass a LiquiDEX proposal JSON version 1.
:liquidex_v1: The LiquiDEX v1 specific parameters, see :ref:`liquidex-v1-complete-details`.
              This field must included only if ``"input_type"`` is ``"liquidex_v1"``.
:output_type: Pass ``"transaction"`` to return a transaction JSON that can be passed to `GA_sign_transaction`.
:utxos: Mandatory. The UTXOs to fund the transaction with, :ref:`unspent-outputs` as returned by `GA_get_unspent_outputs`.
        Note that coin selection is not performed on the passed UTXOs.
        All passed UTXOs of the same asset as the receiving asset id will be included in the transaction.

.. _complete-swap-tx-result:

Complete Swap Transaction Result JSON
-------------------------------------

If the ``"output_type"`` was ``"transaction"`` this field is :ref:`sign-tx-details`.


.. _create-redeposit-tx-details:

Create Redeposit Transaction JSON
---------------------------------

Passed to `GA_create_redeposit_transaction` to create a transaction that
re-deposits expired UTXOs in order to maintain two factor protection.

.. code-block:: json

  {
    "utxos": [],
    "expired_at": 99999,
    "expires_in": 144,
    "fee_rate": 1000,
    "fee_subaccount": 0
  }

:utxos: Mandatory. The UTXOs that should be re-deposited, :ref:`unspent-outputs` as
        returned by `GA_get_unspent_outputs`. Non-expired UTXOs will be ignored,
        except for L-BTC UTXOs that may be required for fees when re-depositing assets.
        For Liquid, all assets except L-BTC must come from the same subaccount.
:expired_at: Optional. If given, only re-deposit UTXOs where two factor authentication
        expires by the given block. Defaults to the current block height if ommitted.
:expires_in: Optional, may only be given if ``"expired_at"`` is excluded. If present,
        the number of blocks given is added to the current block height to
        determine the expiry height to check as ``"expired_at"``.
:fee_rate: Optional. The fee rate in satoshi per thousand bytes.
:fee_subaccount: Optional. If given, change from fees will be sent to this
                 suabaccount. Otherwise, fee change is sent to the subaccount of
                 the first fee UTXO used.


.. _create-redeposit-tx-result:

Create Redeposit Transaction Result JSON
----------------------------------------

The result JSON is a complete transaction ready to be signed with `GA_sign_transaction`,
(after blinding with `GA_blind_transaction` if creating a Liquid transaction).


.. _sign-psbt-details:

Sign PSBT JSON
--------------

.. code-block:: json

  {
    "psbt": "...",
    "utxos": [],
    "blinding_nonces": [],
  }

:psbt: The PSBT or PSET encoded in base64 format.
:utxos: Mandatory. The UTXOs that should be signed, :ref:`unspent-outputs` as returned by `GA_get_unspent_outputs`.
        UTXOs that are not inputs of the PSBT/PSET can be included.
        Caller can avoid signing an input by not passing in its UTXO.
:blinding_nonces: For ``"2of2_no_recovery"`` subaccounts only, the blinding nonces in hex format for all outputs.


.. _sign-psbt-result:

Sign PSBT Result JSON
---------------------

.. code-block:: json

  {
    "psbt": "...",
    "utxos": [],
  }

:psbt: The input PSBT or PSET in base64 format, with signatures added for all inputs signed.
:utxos: The UTXOs corresponding to each signed input, in the order they appear in the PSBT transaction.



.. _psbt-wallet-details:

PSBT Get Details JSON
---------------------

.. code-block:: json

  {
    "psbt": "...",
    "utxos": [],
  }

:psbt: The PSBT or PSET encoded in base64 format.
:utxos: Mandatory. The UTXOs owned by the wallet, :ref:`unspent-outputs` as returned by `GA_get_unspent_outputs`.
        UTXOs that are not inputs of the PSBT/PSET can be included.


.. _psbt-get-details-result:

PSBT Get Details Result JSON
----------------------------

.. code-block:: json

  {
    "inputs": [
      {
        "asset_id": "...",
        "satoshi": 0,
        "subaccount": 0,
      },
    ],
    "outputs": [
      {
        "asset_id": "...",
        "satoshi": 0,
        "subaccount": 0,
      },
    ],
  }

.. note:: Inputs and outputs might have additional fields that might be removed or changed in following releases.


.. _sign-message-request:

Sign Message JSON
-----------------

Describes a request for the wallet to sign a given message via `GA_sign_message`.

.. code-block:: json

  {
    "address": "...",
    "message": "..."
  }

:address: The address to use for the private key.
    Must be a singlesig address, and the address must belong to the wallet.
:message: The message to sign.


.. _sign-message-result:

Sign Message Result JSON
------------------------

Returned by `GA_sign_message`.

.. code-block:: json

  {
    "error", "",
    "signature": "..."
  }

:error: A text description of the error that occurred, if any. If this element
    is not empty, the ``"signature"`` field will not be present.
:signature: The recoverable signature of the message encoded in base 64.


.. _estimates:

Fee estimates JSON
------------------

.. code-block:: json

  {"fees":[1000,10070,10070,10070,3014,3014,3014,2543,2543,2543,2543,2543,2543,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499]}

.. _twofactor_configuration:

Two Factor Config JSON
----------------------

Describes the wallets enabled two factor methods, current spending limits, and two factor reset status.

.. include:: examples/get_twofactor_config_none_multisig.json

.. include:: examples/get_twofactor_config_all_multisig.json

.. include:: examples/get_twofactor_config_singlesig.json

:all_methods: An array containing all two factor methods available. For each
    available method in ``"all_methods"``, a :ref:`twofactor-detail` element
    is returned with the current state of the method for the wallet.
:any_enabled: ``true`` if any two factor method is enabled, ``false`` otherwise.
:enabled_methods: An array containing all enabled two factor methods.
:limits: :ref:`transaction-limits` describing the users current limit.
:twofactor_reset/days_remaining: The number of days remaining before the wallets two factor
                                 authentication is reset, or -1 if no reset procedure is underway.
:twofactor_reset/is_active: Whether or not the wallet is currently undergoing the two factor reset procedure.
:twofactor_reset/is_disputed: Whether or not the wallet two factor reset procedure is disputed.


.. _cache-control-request:

Cache Control Request JSON
--------------------------

Describes the operation to perform on cached wallet data using `GA_cache_control`.

.. code-block:: json

  {
    "action": "fetch",
    "data_source": "client_blob"
  }

:action: The cache action to perform. Currently only ``"fetch"`` is accepted.
:data_source: The data source to operate on as described below.

.. list-table:: Cached Data Sources
   :widths: 25 75
   :header-rows: 1

   * - data_source
     - Description
   * - ``"client_blob"``
     - Private user data stored encrypted in the users client blob.


.. _cache-control-result:

Cache Control Result JSON
--------------------------

Describes the result of a cache control operation requested via `GA_cache_control`.

for the action ``"fetch"`` with a data source of ``"client_blob"``, the following
data is returned:

.. code-block:: json

  {
      "bip329": []
  }

:bip329: An array of BIP329 (https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki) compatible
    elements representing the users metadata. Note that in order to comply with BIP329 (e.g. for
    exporting the data), the caller must convert the array into JSON Lines format.
    See https://jsonlines.org for more details.


.. _bcur-encode:

BCUR Encode JSON
----------------

Contains CBOR data to encode into UR format using `GA_bcur_encode`.

.. code-block:: json

 {
    "ur_type": "crypto-seed",
    "data": "A20150C7098580125E2AB0981253468B2DBC5202D8641947DA",
    "max_fragment_len": 100
 }

:ur_type: The type of the CBOR-encoded data.
:data: CBOR-encoded data in hex format.
:max_fragment_len: The maximum size of each UR-encoded fragment to return.

Where ``data`` is longer than ``max_fragment_len``, the result is a multi-part
encoding using approximately 3 times the minimum number of fragments needed to
decode the data, split into parts of size ``max_fragment_len`` or less.

In this case, the caller must provide all returned parts to any decoder, e.g. by
generating an animated QR code from them.

Special case is for ``ur_type`` equal to ``crypto-psbt``: ``data`` field is expected to be in base64 format.


.. _bcur-encoded:

BCUR Encoded fragments JSON
---------------------------

Contains UR format data encoded using `GA_bcur_encode`.

.. code-block:: json

 {
    "parts": ["ur:crypto-seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaotpiecffltnlpqdenos"]
 }

:parts: The resulting array of UR-encoded fragments representing the input CBOR.


.. _bcur-decode:

BCUR Decode JSON
----------------

Contains UR encoded data to decode into CBOR using `GA_bcur_decode`.

.. code-block:: json

 {
    "part": "ur:crypto-seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaotpiecffltnlpqdenos",
    "return_raw_data": true
 }

:part: Mandatory. The UR-encoded string for an individual part. For multi-part
       decoding, the parts can be provided in any order.
:return_raw_data: Optional, default ``false``. If ``true``, return the raw
        CBOR byte data as a hex string in addition to any decoded data.


.. _bcur-decode-auth-handler-status:

BCUR Decoding Auth Handler JSON
-------------------------------

When further multi-part data is required to decode UR encoded data, the auth
handler will request it from the caller using :ref:`auth-handler-status` as below:

* ``"request_code" example``:

.. code-block:: json

  {
    "status": "resolve_code",
    "action": "data",
    "method": "data",
    "name": "bcur_decode",
    "auth_data": {
        "estimated_progress": 35,
        "received_indices": [0, 1, 2]
    }
  }


The caller should provide the requested data using `GA_auth_handler_resolve_code` as
follows:

* ``"resolve_code" example``:

.. code-block:: json

  "ur:jade-pin/1-4/lpadaacswecylb[...]"


.. _bcur-decoded:

BCUR Decoded data JSON
----------------------

Contains CBOR data decoded from UR format using `GA_bcur_decode`.
The returned JSON depends on the type of the input as returned in
the ``ur_type`` element. If the type is not one of those listed below,
it is returned as if it were ``"bytes"``.

if ``"return_raw_data"`` was given as ``true`` when calling `GA_bcur_decode`,
decoded data will additionally contain a ``"data"`` element as detailed
in the ``"bytes"`` ``ur_type`` section below.

.. include:: examples/bcur_decode_crypto_psbt.json

:ur_type: "crypto-psbt".
:psbt: The psbt in base-64 format.

.. include:: examples/bcur_decode_crypto_output.json

:ur_type: "crypto-output".
:descriptor: The bitcoin output descriptor.

.. include:: examples/bcur_decode_crypto_account.json

:ur_type: "crypto-account".
:descriptors: The list of all available descriptors for the account.
:master_fingerprint: The BIP32 key fingerprint of the master key of the account.

.. include:: examples/bcur_decode_bytes.json

:ur_type: "bytes".
:data: The decoded bytes in hex format.

.. include:: examples/bcur_decode_custom.json

:ur_type: "custom".
:data: The decoded data in hex format.


.. _settings:

Settings JSON
-------------

Contains the users settings returned from `GA_get_settings`, or passed
to `GA_change_settings` to update the users settings.

If a given key is ommitted when changing settings, that setting will remain
unchanged. Settings that are not applicable to the session type are ignored.

.. include:: examples/get_settings_multisig.json
.. include:: examples/get_settings_singlesig.json
.. include:: examples/get_settings_multisig_liquid.json
.. include:: examples/get_settings_singlesig_liquid.json

:altimeout: The time in seconds before the wallet should time out and disconnect. Defaults to ``5``.
:csvtime: Multisig Only. The number of blocks before CSV UTXOs expire. Defaults to the highest value in the ``"csv_buckets"`` list in the network's :ref:`network`. Can only be set from a full session.
:nlocktime: Multisig Only. The number of blocks before P2SH UTXOs expire. Defaults to ``12960``, must be between ``144`` and ``200000``. Can only be set from a full session.
:required_num_blocks: The number of blocks to use for the default transaction fee estimate. Defaults to ``12``.
:sound: Whether the wallet should enable notification sounds if supported. Defaults to ``true``.
:unit: The users preferred unit for displaying coin amounts. Defaults to ``"BTC"``, must be one of ``"btc"``, ``"mbtc"``, ``"ubtc"``, ``"bits"`` or ``"sats"``.
:notifications/email_login: Multisig Only. Whether to email the user whenever a login is made. Defaults to ``false``. Can only be set from a full session.
:notifications/email_incoming: Multisig Only. Whether to email notifications of incoming transactions. Defaults to ``false``. Can only be set from a full session.
:notifications/email_outgoing: Multisig Only. Whether to email notifications of outgoing transactions. Defaults to ``false``. Can only be set from a full session.
:pricing/currency: The users preferred fiat currency for displaying fiat amounts. Defaults to ``"USD"``, must be one of the values returned in :ref:`currencies` for the chosen ``"exchange"``.
:pricing/exchange: The users preferred exchange source for fiat pricing. Defaults to ``"BITSTAMP"``, must be one of the ``"per_exchange"`` keys returned in :ref:`currencies`.


.. _receive-address-request:

Receive address request JSON
-------------------------------

Contains the query parameters for requesting an address using `GA_get_receive_address`.

.. code-block:: json

  {
    "subaccount": 0,
    "is_internal": false,
    "ignore_gap_limit": false,
  }

:subaccount: Mandatory. The value of "pointer" from :ref:`subaccount-list` or :ref:`subaccount-detail` for the subaccount to fetch addresses for.
:is_internal: Optional, singlesig only. Whether or not the user key belongs to the internal chain.
:ignore_gap_limit: Optional, singlesig only. Whether to allow squentially generated addresses to go beyond the ``"gap_limit"`` passed to or defaulted by `GA_connect`.
    This is potentially dangerous as funds received on such addresses are not synced until an address within the gap_limit receives funds.


.. _receive-address-details:

Receive address details JSON
----------------------------

.. include:: examples/get_receive_address_multisig.json
.. include:: examples/get_receive_address_singlesig.json
.. include:: examples/get_receive_address_multisig_liquid.json
.. include:: examples/get_receive_address_singlesig_liquid.json

:address: The wallet address in base58, bech32 or blech32 encoding.
:address_type: One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``, ``"p2tr"`` (singlesig), indicating
    the type of address.
:branch: Always ``1``, used in the address derivation path for subaccounts.
:pointer: The address number/final number in the address derivation path.
:script: The locking script of the address.
:scriptpubkey: The scriptpubkey of the address.
:subaccount: The subaccount this address belongs to. Matches ``"pointer"`` from :ref:`subaccount-list` or :ref:`subaccount-detail`.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks referenced in ``"script"``, otherwise, 0.
:user_path: The BIP32 path for the user key.

For Liquid addresses, the following additional fields are returned:

.. code-block:: json

  {
    "blinding_key": "02a519491b130082a1abbe17395213b46dae43c3e1c05b7a3dbd2157bd83e88a6e",
    "is_blinded": true,
    "unconfidential_address": "XV4PaYgbaJdPnYaJDzE41TpbBF6yBieeyd"
  }

:blinding_key: The blinding key used to blind this address.
:is_blinded: Always ``true``.
:unconfidential_address: The non-confidential address corresponding to ``address``.  This
    is provided for informational purposes only and should not be used to receive.


.. _previous-addresses-request:

Previous addresses request JSON
-------------------------------

Contains the query parameters for requesting previously generated addresses using `GA_get_previous_addresses`.

.. code-block:: json

  {
    "subaccount": 0,
    "last_pointer": 0,
  }

:subaccount: Mandatory. The value of "pointer" from :ref:`subaccount-list` or :ref:`subaccount-detail` for the subaccount to fetch addresses for.
:last_pointer: The address pointer from which results should be returned. If this key is not present, the
               newest generated addresses are returned. If present, the "last_pointer" value from the
               resulting :ref:`previous-addresses` should then be given, until sufficient pages have been
               fetched or the "last_pointer" key is not present indicating all addresses have been fetched.
:is_internal: Singlesig only. Whether or not the user key belongs to the internal chain.



.. _previous-addresses:

Previous addresses JSON
-----------------------

Contains a page of previously generated addresses, from newest to oldest.

.. include:: examples/get_previous_addresses_multisig.json
.. include:: examples/get_previous_addresses_singlesig.json
.. include:: examples/get_previous_addresses_multisig_liquid.json
.. include:: examples/get_previous_addresses_singlesig_liquid.json


:last_pointer: If present indicates that there are more addresses to be fetched, and the caller
               to get the next page should call again `GA_get_previous_addresses` passing this
               value in :ref:`previous-addresses-request`.
               If not present there are no more addresses to fetch.
:list: Contains the current page of addresses in :ref:`receive-address-details` format.



.. _unspent-outputs-request:

Unspent outputs request JSON
----------------------------

Describes which unspent outputs to return from `GA_get_unspent_outputs`,
or which unspent outputs to include in the balance returned by `GA_get_balance`.

.. code-block:: json

  {
    "subaccount": 3,
    "num_confs": 0,
    "address_type": "csv",
    "all_coins": false,
    "expired_at": 99999,
    "expires_in": 144,
    "confidential": false,
    "dust_limit": 546,
    "sort_by": "newest"
  }

:subaccount: The subaccount to fetch unspent outputs for.
:num_confs: Pass ``0`` for unconfirmed UTXOs or ``1`` for confirmed.
:address_type: If given, one of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``, ``"p2tr"`` (singlesig),
    indicating the type of address to return. Defaults to blank (no address filtering).
:all_coins: Pass ``true`` to include UTXOs with status ``frozen``. Defaults to ``false``.
:expired_at: Optional. If given, only UTXOs where two factor authentication expires
    by the given block are returned.
:expires_in: Optional, may only be given if ``"expired_at"`` is excluded. If present,
    the number of blocks given is added to the current block height to
    determine the expiry height to check as ``"expired_at"``.
:confidential: Pass ``true`` to include only confidential UTXOs. Defaults to ``false``.
:dust_limit: If given, only UTXOs with a value greater than the limit value are returned.
:sort_by: One of ``"oldest"``, ``"newest"``, ``"largest"``, ``"smallest"``. Returns the
     unspent outputs sorted by block height or value respectively. If not given, defaults
     to ``"oldest"`` for 2of2 subaccounts and ``"largest"`` for other subaccount types.



.. _unspent-outputs-private-request:

Unspent outputs for private key request JSON
--------------------------------------------

Describes the private key to search for unspent outputs for
with `GA_get_unspent_outputs_for_private_key`.

.. code-block:: json

  {
    "private_key": "6PRK95NQL1rJWZYegfeY1x2vPdsWFsiDDJTziatqkpVFeYi3osJDtiQiw9",
    "password": "foobar"
  }

:private_key: Mandatory. The private key in WIF or BIP 38 format.
    If you want to sweep "p2wpkh"/"p2sh-p2wpkh" outputs, prefix
    the WIF key with ``"p2wpkh:"``/``"p2wpkh-p2sh:"``.
:password: Optional. The password the key is encrypted with, if any.



.. _unspent-outputs:

Unspent outputs JSON
--------------------

Contains unspent outputs for the wallet as requested by `GA_get_unspent_outputs`.

.. include:: examples/get_unspent_outputs_multisig.json
.. include:: examples/get_unspent_outputs_singlesig.json
.. include:: examples/get_unspent_outputs_multisig_liquid.json
.. include:: examples/get_unspent_outputs_singlesig_liquid.json

:txhash: The txid of the transaction.
:pt_idx: The index of the output, the vout.
:satoshi: The amount of the output.
:block_height: The height of the block where the transaction is included.
               Is 0 if the transaction is unconfirmed.
:address_type: One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``, ``"p2tr"`` (singlesig), indicating
    the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:pointer: The user key number/final number in the derivation path.
:subaccount: The subaccount this output belongs to.
             Matches ``"pointer"`` from :ref:`subaccount-list` or :ref:`subaccount-detail`.
:prevout_script: The script being signed, the script code.
:user_path: The BIP32 path for the user key.
:public_key: Singlesig only. The user public key.
:expiry_height: Multisig only.
                The block height when two factor authentication expires.
:user_status: Multisig only. 0 for ``"default"`` and 1 for ``"frozen"``.
:subtype: Multisig only. For ``"address_type"`` ``"csv"``,
          the number of CSV blocks referenced in ``"script"``, otherwise, 0.

For Liquid instead of having the ``"btc"`` field, there are (possibly) multiple
fields, one for each asset owned, and the keys are the hex-encoded policy ids.

For Liquid the inner maps have additional fields:

:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:commitment: The hex-encoded value commitment.
:is_blinded: A boolean indicating whether or not the output is blinded.
:nonce_commitment: The hex-encoded nonce commitment.

.. _unspent-outputs-status:

Unspent outputs set status JSON
-------------------------------

Valid status values are ``"default"`` for normal behavior or ``"frozen"``. Frozen
outputs are hidden from the caller's balance and unspent output requests, are
not returned in nlocktime emails, and cannot be spent. An account containing
frozen outputs can be deleted, whereas an account with unfrozen outputs can not.

Freezing an output requires two factor authentication. Outputs should only be
frozen in response to e.g. a dust attack on the wallet. Once a wallet is
deleted, any frozen outputs it contained will be unspendable forever.

.. note:: Only outputs of value less that two times the dust limit can be frozen.

.. code-block:: json

  {
    "list": [
      {
        "txhash": "09933a297fde31e6477d5aab75f164e0d3864e4f23c3afd795d9121a296513c0",
        "pt_idx": 1,
        "user_status": "frozen"
      }
    ]
  }

.. _transactions-details:

Transactions details JSON
-------------------------

.. code-block:: json

  {"subaccount":0,"first":0,"count":30}



.. _network:

Network JSON
------------

Contains the data describing a network the caller can connect to.

.. include:: examples/network.json


.. _networks-list:

Network list JSON
-----------------

Contains details of all available networks the API can connect to.


For each network listed, a :ref:`network` element is present containing
the networks information.

.. include:: examples/get_networks.json



.. _transaction-limits:

Transaction limits JSON
-----------------------

Describes the users spending limits/desired spending limits. A spending limit
of zero means the user has no limit currently set.

.. warning:: Fiat spending limits are deprecated and support will be removed in a future release.

When calling `GA_twofactor_change_limits`, the caller should pass whether or
not the limit is in fiat, and the value. For limits in BTC, the value can be given
as any unit from :ref:`convert-amount` (e.g. ``"satoshi"``, ``"mbtc"`` etc).

.. include:: examples/twofactor_change_limits_fiat.json

:is_fiat: ``true`` to indicate a fiat limit is being set.
:fiat: A string containing the limit amount in fiat cents.
:fiat_currency: The currency of the limit.

.. include:: examples/twofactor_change_limits_btc.json

:is_fiat: ``false`` to indicate a BTC limit is being set.
:<value_key>: A value key from :ref:`convert-amount` giving the limit.

The returned value from `GA_twofactor_change_limits`, and the ``"limits"``
section of :ref:`twofactor_configuration` is identical to the set value for
fiat. For BTC, the limit is passed through `GA_convert_amount` and so all
units are returned.

.. include:: examples/twofactor_change_limits_fiat_multisig.json
.. include:: examples/twofactor_change_limits_btc_multisig.json



.. _twofactor-detail:

Two Factor Detail JSON
----------------------

Describes the status/desired status of an individual two factor method for a wallet.

Describes the desired status of an individual two factor method for a wallet
when passed to `GA_change_settings_twofactor`. Describes the current status of
a two factor method when returned as an element of :ref:`twofactor_configuration`
by `GA_get_twofactor_config`.

.. code-block:: json

  {
    "confirmed": true,
    "data": "<method specific data>",
    "enabled": true
  }

:confirmed: ``true`` to confirm the method or if method is confirmed. Confirmation
    is performed by the Green server, which requests a two factor code using the
    details in ``"data"``.
:enabled: ``true`` to enable the method or if the method is enabled. Handled by
    the Green server automatically as with ``"confirmed"``.
:data: Method-specific data, as described below.

.. list-table:: Two factor ``"data"`` values
   :widths: 25 50 25
   :header-rows: 1

   * - Method
     - Value
     - Example
   * - ``"email"``
     - Email address
     - ``"sample_email@my_domain.com"``
   * - ``"sms"``
     - Phone number
     - ``+123456789``
   * - ``"phone"``
     - Phone number
     - ``+123456789``
   * - ``"gauth"``
     - OTP auth URL
     - ``"otpauth://..."``

For ``"gauth"`` (Google authenticator), the OTP auth URL is generated by the
Green server, and changes randomly until the user enables this method. The
user should set ``"data"`` to the data value returned for gauth
by `GA_get_twofactor_config` when enabling.

.. note:: When returned from `GA_get_twofactor_config`, the ``"data"`` values
    will be partially masked for user privacy/security.

*Phone as an SMS backup*

If the caller only has SMS two factor enabled, but is unable to receive the
SMS messages sent by the Green server, they may enable phone two factor on
the same phone number without further authorization. This is done by passing
``"is_sms_backup"`` as ``true``, as follows:

.. code-block:: json

  {
    "confirmed": true,
    "data": "<existing sms phone number for the wallet>",
    "enabled": true,
    "is_sms_backup": true
  }



.. _auth-handler-status:

Auth handler status JSON
------------------------

Describes the status of a GA_auth_handler. Returned by `GA_auth_handler_get_status`.

All status JSON contains a ``"name"`` element with the name of the handler being invoked.

The remaining data returned depends on the current state of the handler, as follows:

* ``"done"``:

.. code-block:: json

  {
    "status": "done",
    "action": "disable_2fa",
    "result": {}
  }

:action: The action being processed.
:result: The data returned from the call, if any.

* ``"error"``:

.. code-block:: json

  {
    "status": "error",
    "action": "disable_2fa",
    "error": "Incorrect code"
  }

:action: The action being processed.
:error: A text description of the error that occurred.

* ``"call"``:

.. code-block:: json

  {
    "status": "call",
    "action": "disable_2fa"
  }

:action: The action being processed.

* ``"request_code"``:

.. code-block:: json

  {
    "status": "request_code",
    "action": "disable_2fa",
    "methods": [ "email", "sms", "phone", "gauth", "telegram" ]
  }

:action: The action being processed.
:methods: A list of available two factor methods the user has enabled, or the
    single element ``"data"`` if the call requires more data to continue.

* ``"resolve_code"`` (two factor):

.. code-block:: json

  {
    "status": "resolve_code",
    "action": "disable_2fa",
    "method": "email",
    "auth_data": {},
    "attempts_remaining": "3"
  }

:action: The action being processed.
:method: The two factor method the user should fetch the code to enter from.
:auth_data: Method-specific ancillary data for resolving the call.
:attempts_remaining: If present, the number of incorrect attempts that can be
    made before the call fails.


* ``"resolve_code"`` (hardware wallet/external device):

.. code-block:: json

  {
    "status": "resolve_code",
    "action": "disable_2fa",
    "required_data": {
        "action": "get_xpubs",
        "device": {}
    }
  }

:action: The action being processed.
:required_data: Contains the data the HWW must provide, see :ref:`hw-resolve-overview`.

* ``"resolve_code"`` (request for additional data):

.. code-block:: json

  {
    "status": "resolve_code",
    "action": "data",
    "method": "data",
    "auth_data": {}
  }

:action: Always "data".
:method: Always "data".
:auth_data: Method-specific ancillary data for processing the additional data request.


.. _reconnect:

Reconnect JSON
--------------

Controls session and internal Tor instance reconnection behavior.

.. code-block:: json

   {
     "hint": "connect",
     "tor_hint": "connect"
   }

:hint: Optional, must be either ``"connect"`` or ``"disconnect"`` if given.
:tor_hint: Optional, must be either ``"connect"`` or ``"disconnect"`` if given.

For both hint types, ``"disconnect"`` will disconnect the underlying network
connection used by the session, while ``"connect"`` will reconnect it. if
a hint is not given, no action will be taken for that connection type.

Each session will automatically attempt to reconnect in the background when
they detect a disconnection, unless ``"disconnect"`` is passed to close the
connection first. The session will be notified using a :ref:`ntf-network` when
the underlying network connection changes state.

For environments such as mobile devices where networking may become
unavailable to the callers application, the network must be disconnected
and reconnected using `GA_reconnect_hint` in order for connectivity to
be resumed successfully. In particular, when using the built-in Tor
implementation to connect, failure to do so may result in Tor failing
to connect for the remaining lifetime of the application (this is a
Tor limitation).

.. _convert-amount:

Convert amount JSON
-------------------

Amounts to convert are passed with a single key containing the unit value
to convert, returning all possible conversion values for that value.
See :ref:`amount-data` for the list of unit values available.

For example, to convert satoshi into all available units:

.. code-block:: json

  {
    "satoshi": 1120
  }

If ``"fiat_currency"`` and ``"fiat_rate"`` members are provided, the fiat
conversion will fall back on these values if no fiat rates are available.
Callers can check the ``"is_current"`` member in the result :ref:`amount-data`
to determine if the fall back values were used.

For example, to convert bits into all available units, with a fiat
conversion fallback:

.. code-block:: json

  {
    "bits": "20344.69",
    "fiat_currency": "USD",
    "fiat_rate": "42161.22"
  }

It is possible to call this method in non logged Electrum sessions by providing
pricing details. For example:

.. code-block:: json

  {
    "satoshi": 1000,
    "pricing": {
      "currency": "USD",
      "exchange": "BITFINEX"
    }
  }

For Liquid it's possible to convert asset amounts using the asset precision.
To do so, it's necessary to specify the ``"asset_info"`` field.

It's possible to convert from the asset base unit, ``"satoshi"``:

.. code-block:: json

   {
     "asset_info": {
       "asset_id": "aa..aa",
       "precision": 2,
     },
     "satoshi": 12345,
   }

Or from the asset string representation, using the ``"asset id"`` value
specified in ``"asset_info"``.

.. code-block:: json

   {
     "asset_info": {
       "asset_id": "aa..aa",
       "precision": 2,
     },
     "aa..aa": 123.45,
   }

.. _amount-data:

Amount JSON
-----------

.. code-block:: json

  {
    "bits": "20344.69",
    "btc": "0.02034469",
    "fiat": "0.02",
    "fiat_currency": "EUR",
    "fiat_rate": "1.10000000",
    "mbtc": "20.34469",
    "satoshi": 2034469,
    "sats": "2034469",
    "subaccount": 0,
    "ubtc": "20344.69"
    "is_current": true,
    "aa..aa": "0.02034469",
  }

:fiat_currency: Set to the users fiat currency if available, otherwise an empty string.
:fiat_rate: Set to the users fiat exchange rate if available, otherwise ``null``.
:is_current: ``true`` if the ``"fiat_currency"`` and ``"fiat_rate"`` members are current.
:aa..aa: This field is only present if ``"asset_info"`` was passed. The key is the
         ``"asset_id"`` in ``"asset_info"``, and the value is the string representation of
         the asset amount according to the ``"precision"`` in ``"asset_info"``.


.. _currencies:

Available currencies JSON
-------------------------

Lists the currencies and pricing sources (exchanges) available to the session,
returned by `GA_get_available_currencies`. Note that the available pricing
sources and/or currencies available at each source may differ between singlesig
multisig sessions.

.. include:: examples/get_available_currencies_singlesig.json
.. include:: examples/get_available_currencies_multisig.json

:all: An array of all currecies available across all pricing sources.
:per_exchange: An array of pricing source keys, with the currencies available for each pricing source as the keys value.


.. _http-params:

HTTP parameters JSON
--------------------

.. code-block:: json

   {
      "accept":"json"
      "method":"GET"
      "urls":[
          "https://assets.blockstream.info/index.json"
          "http://vi5flmr4z3h3luup.onion/index.json"
      ]
      "proxy":"localhost:9150"
      "headers":{"If-Modified-Since":"Mon, 02 Sep 2019 22:39:39 GMT"}
      "timeout":10
   }



.. _set-locktime-details:

Locktime details JSON
-------------------------

.. code-block:: json

  {
    "value":65535
  }


.. _assets-params-data:

Asset parameters JSON
---------------------

.. code-block:: json

   {
      "assets": true,
      "icons": true
   }

.. _get-assets-params:

Get assets parameters JSON
--------------------------

Information about Liquid assets can be obtained by either passing a list of
asset ids to query:

.. code-block:: json

   {
      "assets_id": ["6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d","ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2"]
   }

or by specifying one or more of the following attributes:

:names: a list of strings representing asset names;
:tickers: a list of strings representing asset tickers:
:category: must be one of:
        - ``"with_icons"``: only assets that have icons associated to them will be returned;
        - ``"hard_coded"``: only assets bundled in the GDK release will be returned;
        - ``"all"``: all the locally-stored assets and icons will be returned.

Specifying multiple attributes is interpreted as a logical AND. For example,
``{"category": "with_icons", "tickers": ["LCAD"]}`` will return all the assets
with ticker ``LCAD`` that also have an icon.

.. _asset-details:

Asset details JSON
------------------

.. code-block:: json

   {
      "assets": {
         "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d": {
            "asset_id": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
            "contract": null,
            "entity": null,
            "issuance_prevout": {
               "txid": "0000000000000000000000000000000000000000000000000000000000000000",
               "vout": 0
            },
            "issuance_txin":{
               "txid": "0000000000000000000000000000000000000000000000000000000000000000",
               "vin": 0
            },
            "issuer_pubkey": "",
            "name": "btc",
            "precision": 8,
            "ticker": "L-BTC",
            "version": 0
         }
      },
      "icons": {
         "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d": "BASE64"
      }
   }


.. _error-details:

Error details JSON
------------------

.. code-block:: json

   {
      "details":"assertion failure: ga_session.cpp:2166:Unknown subaccount"
   }

.. _get-subaccounts-params-data:

Get Subaccounts parameters JSON
-------------------------------

Parameters controlling the `GA_get_subaccounts` call.

.. code-block:: json

   {
      "refresh": false
   }

:refresh: If set to ``true``, subaccounts are re-discovered if appropriate for the session type. Note that this will take significantly more time if set. Defaults to ``false``.


.. _validate-details:

Validate JSON
-------------

Passed to `GA_validate` to check the validity of gdk input data.

To validate addressees, for example prior to calling `GA_create_transaction`:

.. code-block:: json

  {
    "addressees": {},
    "network": "mainnet"
  }

:addressees: Mandatory. An array of :ref:`addressee` elements.
:network: Optional. The name of a network to validate the addressees against.

Validation includes that the address is correct and supported by the network,
and that the amount given is valid. The given amount in whatever denomination
will be converted into ``"satoshi"`` in the returned addressee. For Liquid, a
valid hex ``"asset_id"`` must be present.

It is also possible to validate an addressee for another network than that of
the current session. To do so, pass a network name in ``"network"``. Note that
when validating against a different network, any amount in the addressee will
not be validated or converted, as the session does not have pricing data for
other networks than its own.

To validate a LiquiDEX version 1 proposal:

.. code-block:: json

  {
    "liquidex_v1": {
      "proposal": {}
    }
  }

:liquidex_v1/proposal: The LiquiDEX version 1 proposal to validate.

.. _validate-result:

Validate Result JSON
--------------------

Returned from `GA_validate` to indicate the validity of the given JSON document.

.. code-block:: json

  {
    "is_valid": true,
    "errors": [],
    "addressees": {}
  }

:is_valid: ``true`` if the JSON is valid, ``false`` otherwise.
:errors: An array of strings describing each error found in the given document;
         Empty if ``"is_valid"`` is ``true``.
:addressees: If validating addressees, the given :ref:`addressee` elements with
         data sanitized and converted if required. For example, BIP21 URLs are
         converted to addresses, plus amount/asset if applicable.
