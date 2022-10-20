GDK JSON
========

This section describes the various JSON formats used by the library.

.. _init-config-arg:

Initialization config JSON
--------------------------

Passed to `GA_init` when initializing the library.

.. code-block:: json

    {
        "datadir": "/path/to/store/data"
        "tordir": "/path/to/store/tor/data"
        "registrydir": "/path/to/store/registry/data"
        "log_level": "info",
    }

:datadir: Mandatory. A directory which gdk will use to store encrypted data
          relating to sessions.
:tordir: An optional directory for tor state data, used when the internal tor
         implementation is enabled in :ref:`net-params`. Note that each process
         using the library at the same time requires its own distinct directory.
         If not given, a subdirectory ``"tor"`` inside ``"datadir"`` is used.
:registrydir: An optional directory for the registry data, used when the network
         is liquid based. Note that each process using the library at the same
         time requires its own distinct directory.
         If not given, a subdirectory ``"registry"`` inside ``"datadir"`` is used.
:log_level: Library logging level, one of ``"debug"``, ``"info"``, ``"warn"``,
           ``"error"``, or ``"none"``.

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
      "cert_expiry_threshold": 1
   }

:name: The name of the network to connect to. Must match a key from :ref:`networks-list`.
:proxy: The proxy connection to pass network traffic through, if any.
:use_tor: ``true`` to enable Tor connections, ``false`` otherwise. If enabled
          and a proxy is not given, a Tor connection will be started internally.
          If a proxy is given and Tor is enabled, the proxy must support
          resolving ``".onion"`` domains.
:user_agent: The user agent string to pass to the server for multisig connections.
:spv_enabled: ``true`` to enable SPV verification for the session, ``false`` otherwise.
:cert_expiry_threshold: Ignore certificates expiring within this many days from today. Used to pre-empt problems with expiring embedded certificates.


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
         "supports_liquid": 1,
         "supports_low_r": false,
      }
   }

:name: The unique name of the hardware device.
:supports_arbitrary_scripts: True if the device can sign non-standard scripts such as CSV.
:supports_low_r: True if the device can produce low-R ECDSA signatures.
:supports_liquid: 0 if the device does not support Liquid, 1 otherwise.
:supports_host_unblinding: True if the device supports returning the Liquid master blinding key.
:supports_ae_protocol: See "ae_protocol_support_level" enum  in the gdk source for details.

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

.. code-block:: json

  {
    "hidden": false,
    "name": "Subaccount Name",
    "pointer": 0,
    "receiving_id": "GA7ZnuhsieSMNp2XAB3oEyLy75peM",
    "recovery_chain_code": "",
    "recovery_pub_key": "",
    "recovery_xpub": "",
    "required_ca": 0,
    "type": "2of2"
    "bip44_discovered": false
  }

:hidden: Whether the subaccount is hidden.
:name: The name of the subaccount.
:pointer: The subaccount number.
:receiving_id: The Green receiving ID for the subaccount.
:recovery_chain_code: For ``"2of3"`` subaccounts, the BIP32 chaincode of the users recovery key.
:recovery_pub_key: For ``"2of3"`` subaccounts, the BIP32 public key of the users recovery key.
:recovery_xpub: For ``"2of3"`` subaccounts, the BIP32 xpub of the users recovery key.
:required_ca: For ``"2of2_no_recovery"`` subaccounts, the number of confidential addresses
    that the user must upload to the server before transacting.
:type: For multisig subaccounts, one of ``"2of2"``, ``"2of3"`` or ``"2of2_no_recovery"``.
    For singlesig subaccounts, one of ``"p2pkh"``, ``"p2wpkh"`` or ``"p2sh-p2wpkh"``.
:bip44_discovered: Singlesig only. Whether or not this subaccount contains at least one transaction.
:user_path: The BIP32 path for this subaccount.
    This field is only returned by `GA_get_subaccount`.
:core_descriptors: Singlesig only. The Bitcoin Core compatible output descriptors.
    One for the external chain and one for internal chain (change),
    for instance ``"sh(wpkh(tpubDC2Q4xK4XH72H18SiEV2A6HUwUPLhXiTEQXU35r4a41ZVrUv2cgKUMm2fsKTapi8DH4Y8ZVjy8TQtmyWMuH37kjw8fQGJahjWbuQoPm6qRF/0/*))"``
     ``"sh(wpkh(tpubDC2Q4xK4XH72H18SiEV2A6HUwUPLhXiTEQXU35r4a41ZVrUv2cgKUMm2fsKTapi8DH4Y8ZVjy8TQtmyWMuH37kjw8fQGJahjWbuQoPm6qRF/1/*))"``
    for a ``p2sh-p2wpkh`` subaccount.
    This field is only returned by `GA_get_subaccount`.
:slip132_extended_pubkey: Singlesig and Bitcoin only. The extended public key with modified version
    as specified in SLIP-0132 (xpub, ypub, zpub, tpub, upub, vpub).
    Use of this value is discouraged and this field might be removed in the future.
    Callers should use descriptors instead.
    This field is only returned by `GA_get_subaccount`.

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

.. code-block:: json

  {
    "transactions": [
      {
        "block_height": 2098691,
        "can_cpfp": false,
        "can_rbf": false,
        "created_at_ts": 1633987189032056,
        "fee": 207,
        "fee_rate": 1004,
        "inputs": [
          {
            "address": "",
            "address_type": "csv",
            "is_internal": false,
            "is_output": false,
            "is_relevant": true,
            "is_spent": true,
            "pointer": 287,
            "pt_idx": 0,
            "satoshi": 27071081568,
            "script_type": 15,
            "subaccount": 0,
            "subtype": 0
          }
        ],
        "memo": "",
        "outputs": [
          {
            "address": "2MztTCrvpq73a8homScCo659VADSLEfR2FW",
            "address_type": "csv",
            "is_internal": false,
            "is_output": true,
            "is_relevant": true,
            "is_spent": false,
            "pointer": 288,
            "pt_idx": 0,
            "satoshi": 26970081361,
            "script_type": 15,
            "subaccount": 0,
            "subtype": 51840
          },
          {
            "address": "tb1qt0lenzqp8ay0ryehj7m3wwuds240mzhgdhqp4c",
            "address_type": "",
            "is_internal": false,
            "is_output": true,
            "is_relevant": false,
            "is_spent": false,
            "pointer": 0,
            "pt_idx": 1,
            "satoshi": 101000000,
            "script_type": 11,
            "subaccount": 0,
            "subtype": 0
          }
        ],
        "rbf_optin": false,
        "satoshi": {
          "btc": -101000207
        },
        "spv_verified": "disabled",
        "transaction_size": 375,
        "transaction_vsize": 206,
        "transaction_weight": 824,
        "txhash": "0a934eaa5c8a7c961c1c3aef51a49d11d7d9a04a839620ec6e796156b429c7b4",
        "type": "outgoing"
      }
    ]
  }


:transactions: Top level container for the users transaction list.
:block_height: The network block height that the transaction was confirmed
    in, or ``0`` if the transaction is in the mempool.
:can_cpfp: A boolean indicating whether the user can CPFP the transaction.
:can_rbf: A boolean indicating whether the use can RBF (bump) the transaction fee.
:created_at_ts: The timestamp in microseconds from the Unix epoc when the transaction
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
:transaction_size: The size of the transaction in bytes.
:transaction_vsize: The size of the transaction in vbytes.
:transaction_weight: The weight of the transaction.
:txhash: The txid of the transaction.
:type: One of ``"incoming"``, ``"outgoing"``, ``"mixed"`` or ``"not unblindable"``.


.. _tx-list-input:

Transaction list input element
------------------------------

Describes a transaction input in :ref:`tx-list`.

.. code-block:: json

  {
    "address": "2MxVC4kQTpovRHiEmzd3q7vGtofM8CAijYY",
    "address_type": "csv",
    "is_internal": false,
    "is_output": false,
    "is_relevant": true,
    "is_spent": true,
    "pointer": 287,
    "pt_idx": 0,
    "satoshi": 27071081568,
    "script_type": 15,
    "subaccount": 0,
    "subtype": 0
  }


:address: For user wallet addresses, the wallet address in base58, bech32 or blech32 encoding.
:addressee: Optional, multisig only. For historical social payments, the account name sent from.
:address_type: For user wallet addresses, One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"`` (singlesig), indicating the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:is_output: Always false. Deprecated, will be removed in a future release.
:is_relevant: A boolean indicating whether the input relates to the subaccount the
    caller passed to `GA_get_transactions`.
:is_spent: Always true. Deprecated, will be removed in a future release.
:pointer: For user wallet addresses, the address number/final number in the address derivation path.
:pt_idx: Deprecated, will be removed in a future release.
:satoshi: The amount of the input in satoshi.
:script_type: Deprecated, will be removed in a future release.
:subaccount: For user wallet addresses, the subaccount this output belongs to, or ``0``.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks used in the receiving scriptpubkey.

Liquid inputs have additional fields:

.. code-block:: json

  {
    "amountblinder": "3ad591ed6289ab0a7fa1777197f84a05cd12f651cca831932eaa8a09ac7cc7d2",
    "asset_id": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
    "asset_tag": "0b5ff0a91c05353089cd40250a2b6c81f09507637d90c37c7e372a8465a4dc0458",
    "assetblinder": "0cd232883f93a3376b88e19a17192495663315a94bd54a24f20299b9af7a696c",
    "commitment": "09f9ac1dfa5042e25a9791fde4aa8292e21c25479eec7783ec5400805a227be256",
    "confidential": true,
    "nonce_commitment": "03dcec00304fe2debe04a57f84962966b92db9390b96e9931fef47b002fb265278",
    "previdx": 1,
    "prevpointer": 40,
    "prevsubaccount": null,
    "prevtxhash": "be5ad6db9598873b1443796aa0b34445aa85145586b3355324130c0fd869948f",
    "script": "a914759262b6664d3be92ff41f3a06ade42fa429843087",
  }


:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:commitment: The hex-encoded value commitment.
:confidential: A boolean indicating whether or not the output is confidential.
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

.. code-block:: json

  {
    "address": "2MwdBCwyJnEtp2Bq8CBxyeSi5JWJQ9nXkjj",
    "address_type": "p2wsh",
    "is_internal": false,
    "is_output": true,
    "is_relevant": true,
    "is_spent": true,
    "pointer": 275,
    "pt_idx": 0,
    "satoshi": 1000,
    "script_type": 14,
    "subaccount": 0,
    "subtype": 0
  }

:address: The output address.
:address_type: For user wallet output addresses, One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"`` (singlesig), indicating the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:is_output: Always true. Deprecated, will be removed in a future release.
:is_relevant: A boolean indicating whether the output relates to the subaccount the
    caller passed to `GA_get_transactions`.
:is_spent: A boolean indicating if this output has been spent.
:pointer: For user wallet addresses, the address number/final number in the address derivation path.
:pt_idx: Deprecated, will be removed in a future release.
:satoshi: The amount of the output in satoshi.
:script_type: Deprecated, will be removed in a future release.
:subaccount: For user wallet addresses, the subaccount this output belongs to, or ``0``.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks used in the receiving scriptpubkey.


Liquid outputs have additional fields:

.. code-block:: json

  {
    "amountblinder": "752defd24e9163917aea608a2ff8b77773311a4728551f49761781af9eb4905a",
    "asset_id": "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
    "asset_tag": "0ad82ac7489779a5303af3c30b1ec8abd47007f3d5ee01cb1f3b0aac2277a1df23",
    "assetblinder": "d29b09a3f18c7b404ba99338f6427370d0a3b0f6b9591ecf54bce4623a93eb06",
    "blinding_key": "039f2fd9daf37ae24e6a5311ffc18f60aaf3d8adac755c4ee93bf23bbde62071f7",
    "commitment": "0920c8c8ffe7a3529d48947ee1102e3ffbaa62ffa941bc00544d4dd90767426f2d",
    "confidential": true,
    "is_blinded": true,
    "nonce_commitment": "0389e67d84f9d04fd163ca540efa599fb51433e7891156c96321f9e85a2687b270",
    "script": "a9144371b94845ee9b316fad126238ccefc05ae74ae587",
    "unblinded_address": "8ka5DahqHU82oALm372w9rPLZskn4jwpSu"
  }

:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:commitment: The hex-encoded value commitment.
:confidential: For user wallet outputs, a boolean indicating whether or not the output
    is confidential, i.e. whether its asset and value have been blinded.
:is_blinded: For user wallet outputs, alays true when ``confidential`` is true.
:nonce_commitment: The hex-encoded nonce commitment.
:script: For user wallet outputs, the scriptpubkey of this output.


.. _external-tx-detail:

Transaction details JSON
------------------------

Contains information about a transaction that may not be associated with the
users wallet. Returned by `GA_get_transaction_details`.

.. code-block:: json

  {
    "transaction": "02000000000101ab0dec345ed48b0761411306eae50f90dd34f3c8598e48f1c3ad324a862bc72b0000000000feffffff02f4958b4400000000160014a0573f94da51090f3225ddccab864bf3add1019300e1f5050000000017a914fda46ba3f2fc040df40d8cb8543b3dcdc168b6fa870247304402201420ca8bb17c74eef87d7c26a1bed69ddaec8f389df06f3d0233edf0070eec69022051e7bf1efb00a198a5c9958811246f19a1071ac6b68fa9c2f3d91d7a080a56fa012102be66aba37c4c48c85b6eea4d0d7c6ba0e22803438d3f1e29bc8e6e352786335fb0010000",
    "transaction_locktime": 432,
    "transaction_size": 223,
    "transaction_version": 2,
    "transaction_vsize": 142,
    "transaction_weight": 565,
    "txhash": "dc5c908a6c979211e6482766adb69cbcbe760c92923671f6304d12a3f462a2b0"
  }


.. _create-tx-details:

Create transaction JSON
-----------------------

.. code-block:: json

 {
  "addressees": [
    {
      "address": "bitcoin:2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b?amount=0.001"
    }
  ],
  "utxos": { }
 }

 {
  "addressees": [
    {
      "address": "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b",
      "satoshi": 100000
    }
  ],
  "utxos": { }
  "fee_rate": 1000
 }

.. _sign-tx-details:

Sign transaction JSON
---------------------

.. code-block:: json

  {
  "addressees": [
    {
      "address": "2N5xpcfb1TCjncrKABhw2LWPKTSdzVYSy3A",
      "satoshi": 5000
    }
  ],
  "addressees_have_assets": false,
  "addressees_read_only": false,
  "amount_read_only": false,
  "available_total": 50000,
  "calculated_fee_rate": 1000,
  "change_address": {
    "btc": {
      "address": "2N7M3gisUPGmZBeU4WnV9UNkJ9zW2n8bEW7",
      "address_type": "csv",
      "branch": 1,
      "pointer": 3,
      "script": "2103bff5afb55b115068c2f5d906fc97a41ec3b81446f616a31d2304d2cf18c87db9ad2103eaf7e8cf60e89cfb9fe8cabf141b041b0eb6ade361f9ec84943445bd0abdfe29ac73640380ca00b268",
      "script_type": 15,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "user_path": [
        1,
        3
      ]
    }
  },
  "change_amount": {
    "btc": 44792
  },
  "change_index": {
    "btc": 0
  },
  "change_subaccount": 0,
  "error": "",
  "fee": 208,
  "fee_rate": 1000,
  "have_change": {
    "btc": true
  },
  "is_redeposit": false,
  "is_sweep": false,
  "network_fee": 0,
  "satoshi": {
    "btc": 5000
  },
  "send_all": false,
  "transaction": "0200000000010135d2bb82963e54a9060567b101760530797590d2b4a636606c4f1e6ac62bed4300000000230000000000000000000000000000000000000000000000000000000000000000000000fdffffff02f8ae00000000000017a9149aaba80ae1e733f8fb4034abcb6bd835608a5c9e87881300000000000017a9148b7f781fc9425ffaeafcd4973d3ae1dc9a09d02b87040048000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268c9000000",
  "transaction_locktime": 201,
  "transaction_outputs": [
    {
      "address": "2N7M3gisUPGmZBeU4WnV9UNkJ9zW2n8bEW7",
      "address_type": "csv",
      "asset_id": "btc",
      "branch": 1,
      "is_change": true,
      "is_fee": false,
      "pointer": 3,
      "satoshi": 44792,
      "script": "a9149aaba80ae1e733f8fb4034abcb6bd835608a5c9e87",
      "script_type": 15,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "user_path": [
        1,
        3
      ]
    },
    {
      "address": "2N5xpcfb1TCjncrKABhw2LWPKTSdzVYSy3A",
      "asset_id": "btc",
      "is_change": false,
      "is_fee": false,
      "satoshi": 5000,
      "script": "a9148b7f781fc9425ffaeafcd4973d3ae1dc9a09d02b87"
    }
  ],
  "transaction_size": 379,
  "transaction_version": 2,
  "transaction_vsize": 208,
  "transaction_weight": 829,
  "used_utxos": [
    {
      "address_type": "csv",
      "block_height": 201,
      "expiry_height": 52041,
      "is_internal": false,
      "pointer": 1,
      "prevout_script": "210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268",
      "pt_idx": 0,
      "satoshi": 50000,
      "script_type": 15,
      "sequence": 4294967293,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "txhash": "43ed2bc66a1e4f6c6036a6b4d290757930057601b1670506a9543e9682bbd235",
      "user_path": [
        1,
        1
      ],
      "user_sighash": 1,
      "skip_signing": false,
      "user_status": 0
    }
  ],
  "utxo_strategy": "default",
  "utxos": {
    "btc": [
      {
        "address_type": "csv",
        "block_height": 201,
        "expiry_height": 52041,
        "is_internal": false,
        "pointer": 1,
        "prevout_script": "210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268",
        "pt_idx": 0,
        "satoshi": 50000,
        "script_type": 15,
        "sequence": 4294967293,
        "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
        "subaccount": 0,
        "subtype": 51840,
        "txhash": "43ed2bc66a1e4f6c6036a6b4d290757930057601b1670506a9543e9682bbd235",
        "user_path": [
          1,
          1
        ],
        "user_status": 0
      }
    ]
  }
  }


To sign with a specific sighash, set ``"user_sighash"`` for the elements of
``"used_utxos"`` you wish to sign with a certain sighash, otherwise
``SIGHASH_ALL`` (``1``) will be used.

Set ``"skip_signing"`` to ``true`` for any input in ``"used_utxos"`` you do
not wish to have signed.


.. _send-tx-details:

Send transaction JSON
---------------------

.. code-block:: json

  {
  "addressees": [
    {
      "address": "2N5xpcfb1TCjncrKABhw2LWPKTSdzVYSy3A",
      "satoshi": 5000
    }
  ],
  "addressees_have_assets": false,
  "addressees_read_only": false,
  "amount_read_only": false,
  "available_total": 50000,
  "blinded": true,
  "calculated_fee_rate": 1230,
  "change_address": {
    "btc": {
      "address": "2N7M3gisUPGmZBeU4WnV9UNkJ9zW2n8bEW7",
      "address_type": "csv",
      "branch": 1,
      "pointer": 3,
      "script": "2103bff5afb55b115068c2f5d906fc97a41ec3b81446f616a31d2304d2cf18c87db9ad2103eaf7e8cf60e89cfb9fe8cabf141b041b0eb6ade361f9ec84943445bd0abdfe29ac73640380ca00b268",
      "script_type": 15,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "user_path": [
        1,
        3
      ]
    }
  },
  "change_amount": {
    "btc": 44792
  },
  "change_index": {
    "btc": 0
  },
  "change_subaccount": 0,
  "error": "",
  "fee": 208,
  "fee_rate": 1000,
  "have_change": {
    "btc": true
  },
  "is_redeposit": false,
  "is_sweep": false,
  "network_fee": 0,
  "satoshi": {
    "btc": 5000
  },
  "send_all": false,
  "transaction": "0200000000010135d2bb82963e54a9060567b101760530797590d2b4a636606c4f1e6ac62bed430000000023220020babaa86eeaec7ae0f438218b993c7518e81efe6c8c64e9500648f861ccd590b3fdffffff02f8ae00000000000017a9149aaba80ae1e733f8fb4034abcb6bd835608a5c9e87881300000000000017a9148b7f781fc9425ffaeafcd4973d3ae1dc9a09d02b870147304402206aa051d8f6b373e9e73ea91967d3d574262a56f66b134804133893bc8b6a797f022069802eccea8174daadee65a6288f23434ed646d328bf184060e2517bd9c5aa3801c9000000",
  "transaction_locktime": 201,
  "transaction_outputs": [
    {
      "address": "2N7M3gisUPGmZBeU4WnV9UNkJ9zW2n8bEW7",
      "address_type": "csv",
      "asset_id": "btc",
      "branch": 1,
      "is_change": true,
      "is_fee": false,
      "pointer": 3,
      "satoshi": 44792,
      "script": "a9149aaba80ae1e733f8fb4034abcb6bd835608a5c9e87",
      "script_type": 15,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "user_path": [
        1,
        3
      ]
    },
    {
      "address": "2N5xpcfb1TCjncrKABhw2LWPKTSdzVYSy3A",
      "asset_id": "btc",
      "is_change": false,
      "is_fee": false,
      "satoshi": 5000,
      "script": "a9148b7f781fc9425ffaeafcd4973d3ae1dc9a09d02b87"
    }
  ],
  "transaction_size": 225,
  "transaction_version": 2,
  "transaction_vsize": 169,
  "transaction_weight": 675,
  "used_utxos": [
    {
      "address_type": "csv",
      "block_height": 201,
      "expiry_height": 52041,
      "is_internal": false,
      "pointer": 1,
      "prevout_script": "210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268",
      "pt_idx": 0,
      "satoshi": 50000,
      "script_type": 15,
      "sequence": 4294967293,
      "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
      "subaccount": 0,
      "subtype": 51840,
      "txhash": "43ed2bc66a1e4f6c6036a6b4d290757930057601b1670506a9543e9682bbd235",
      "user_path": [
        1,
        1
      ],
      "user_status": 0
    }
  ],
  "utxo_strategy": "default",
  "utxos": {
    "btc": [
      {
        "address_type": "csv",
        "block_height": 201,
        "expiry_height": 52041,
        "is_internal": false,
        "pointer": 1,
        "prevout_script": "210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268",
        "pt_idx": 0,
        "satoshi": 50000,
        "script_type": 15,
        "sequence": 4294967293,
        "service_xpub": "tpubEAUTpVqYYmSyPnSwSTWrdahLK22WRUkFK66kH348bRawwcBDegdUaucPGU28qS1z9ZiMjH7N2Qqc6HPJiQvekLS8GCpHHCxZfmNpF798ECb",
        "subaccount": 0,
        "subtype": 51840,
        "txhash": "43ed2bc66a1e4f6c6036a6b4d290757930057601b1670506a9543e9682bbd235",
        "user_path": [
          1,
          1
        ],
        "user_status": 0
      }
    ]
  }
  }

.. _create-swap-tx-details:

Create Swap Transaction JSON
----------------------------

Describes the swap to be created when calling `GA_create_swap_transaction`.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v0",
    "liquidex_v0": {},
    "output_type": "liquidex_v0"
  }

:swap_type: Pass ``"liquidex"`` to create the maker's side of a LiquiDEX 2-step swap.
:input_type: Pass ``"liquidex_v0"`` to pass LiquiDEX version 0 details.
:liquidex_v0: The LiquiDEX v0 specific parameters, see :ref:`liquidex-v0-create-details`.
              This field must included only if ``"input_type"`` is ``"liquidex_v0"``.
:output_type: Pass ``"liquidex_v0"`` to return LiquiDEX proposal JSON version 0.

.. _create-swap-tx-result:

Create Swap Transaction Result JSON
-----------------------------------

If the ``"output_type"`` was ``"liquidex_v0"`` this field is `liquidex-v0-create-result`.


.. _complete-swap-tx-details:

Complete Swap Transaction JSON
------------------------------

Describes the swap to be completed when calling `GA_complete_swap_transaction`.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v0",
    "liquidex_v0": {},
    "output_type": "transaction",
    "utxos": {},
  }

:swap_type: Pass ``"liquidex"`` to complete the taker's side of a LiquiDEX 2-step swap.
:input_type: Pass ``"liquidex_v0"`` to pass a LiquiDEX proposal JSON version 0.
:liquidex_v0: The LiquiDEX v0 specific parameters, see :ref:`liquidex-v0-complete-details`.
              This field must included only if ``"input_type"`` is ``"liquidex_v0"``.
:output_type: Pass ``"transaction"`` to return a transaction JSON that can be passed to `GA_sign_transaction`.
:utxos: Mandatory. The UTXOs to fund the transaction with.
        Note that coin selection is not performed on the passed UTXOs.
        All passed UTXOs of the same asset as the receiving asset id will be included in the transaction.

.. _complete-swap-tx-result:

Complete Swap Transaction Result JSON
-------------------------------------

If the ``"output_type"`` was ``"transaction"`` this field is :ref:`sign-tx-details`.


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
:utxos: The UTXOs that should be signed, in the format returned by `GA_get_unspent_outputs`.
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
:utxos: The UTXOs owned by the wallet, in the format returned by `GA_get_unspent_outputs`.
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


.. _estimates:

Fee estimates JSON
------------------

.. code-block:: json

  {"fees":[1000,10070,10070,10070,3014,3014,3014,2543,2543,2543,2543,2543,2543,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499]}

.. _twofactor_configuration:

Two-Factor config JSON
----------------------

Describes the wallets enabled two factor methods, current spending limits, and two factor reset status.

.. code-block:: json

 {
  "all_methods": [
    "email",
    "sms",
    "phone",
    "gauth"
  ],
  "any_enabled": true,
  "email": {
    "confirmed": true,
    "data": "***@@g***",
    "enabled": true
  },
  "enabled_methods": [
    "email"
  ],
  "gauth": {
    "confirmed": false,
    "data": "otpauth://totp/Green%20Bitcoin?secret=IZ3SMET5RDWVUSHB4CPTKUWBJM4HSYHO",
    "enabled": false
  },
  "limits": {
    "bits": "5000.00",
    "btc": "0.00500000",
    "fiat": "0.01",
    "fiat_currency": "EUR",
    "fiat_rate": "1.10000000",
    "is_fiat": false,
    "mbtc": "5.00000",
    "satoshi": 500000,
    "sats": "500000",
    "ubtc": "5000.00"
  },
  "phone": {
    "confirmed": false,
    "data": "",
    "enabled": false
  },
  "sms": {
    "confirmed": false,
    "data": "",
    "enabled": false
  },
  "twofactor_reset": {
    "days_remaining": -1,
    "is_active": false,
    "is_disputed": false
  }
 }

:twofactor_reset/days_remaining: The number of days remaining before the wallets two factor
                                 authentication is reset, or -1 if no reset procedure is underway.
:twofactor_reset/is_active: Whether or not the wallet is currently undergoing the two factor reset procedure.
:twofactor_reset/is_disputed: Whether or not the wallet two factor reset procedure is disputed.


.. _settings:

Settings JSON
-------------

.. code-block:: json

  {
    "altimeout": 10,
    "csvtime": 51840,
    "nlocktime": 12960,
    "notifications": {
      "email_incoming": true,
      "email_outgoing": true,
      "email_login": true
    },
    "pgp": "",
    "pricing": {
      "currency": "EUR",
      "exchange": "KRAKEN"
    },
    "required_num_blocks": 12,
    "sound": true,
    "unit": "BTC"
  }


.. _receive-address-details:

Receive address details JSON
----------------------------

.. code-block:: json

  {
    "address": "2N2x4EgizS2w3DUiWYWW9pEf4sGYRfo6PAX",
    "address_type": "p2wsh",
    "branch": 1,
    "pointer": 13,
    "script": "52210338832debc5e15ce143d5cf9241147ac0019e7516d3d9569e04b0e18f3278718921025dfaa85d64963252604e1b139b40182bb859a9e2e1aa2904876c34e82158d85452ae",
    "script_type": 14,
    "subaccount": 0,
    "subtype": 0
    "user_path": [1, 13]
  }

:address: The wallet address in base58, bech32 or blech32 encoding.
:address_type: One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"`` (singlesig), indicating the type of address.
:branch: Always ``1``, used in the address derivation path for subaccounts.
:pointer: The address number/final number in the address derivation path.
:script: The scriptpubkey of the address.
:script_type: Integer representing the type of script.
:subaccount: The subaccount this address belongs to. Matches ``"pointer"`` from :ref:`subaccount-list` or :ref:`subaccount-detail`.
:subtype: For ``"address_type"`` ``"csv"``, the number of CSV blocks referenced in ``"script"``, otherwise, 0.
:user_path: The BIP32 path for the user key.

For Liquid addresses, the following additional fields are returned:

.. code-block:: json

  {
    "blinding_key": "02a519491b130082a1abbe17395213b46dae43c3e1c05b7a3dbd2157bd83e88a6e",
    "blinding_script": "a914c2427b28b2796243e1e8ee65be7598d465264b0187",
    "is_blinded": true,
    "unblinded_address": "XV4PaYgbaJdPnYaJDzE41TpbBF6yBieeyd"
  }

:blinding_key: The blinding key used to blind this address.
:blinding_script: The script used to generate the blinding key via https://github.com/satoshilabs/slips/blob/master/slip-0077.md.
:is_blinded: Always ``true``.
:unblinded_address: The unblinded address. This is provided for informational purposes only and should not be used to receive.


.. _previous-addresses-request:

Previous addresses request JSON
-------------------------------

Contains the query parameters for requesting previously generated addresses using `GA_get_previous_addresses`.

.. code-block:: json

  {
    "subaccount": 0,
    "last_pointer": 0,
  }

:subaccount: The value of "pointer" from :ref:`subaccount-list` or :ref:`subaccount-detail` for the subaccount to fetch addresses for. Default 0.
:last_pointer: The address pointer from which results should be returned. If this key is not present, the
               newest generated addresses are returned. If present, the "last_pointer" value from the
               resulting :ref:`previous-addresses` should then be given, until sufficient pages have been
               fetched or the "last_pointer" key is not present indicating all addresses have been fetched.
:is_internal: Singlesig only. Whether or not the user key belongs to the internal chain.



.. _previous-addresses:

Previous addresses JSON
-----------------------

Contains a page of previously generated addresses, from newest to oldest.

.. code-block:: json

  {
    "last_pointer": 2,
    "list": [
      {
        "address": "2N52RVsChsCi439PpJ1Hn8fHCiTrRjcAEiL",
        "address_type": "csv",
        "branch": 1,
        "is_internal": false,
        "pointer": 2,
        "script": "2102df992d7fa8f012d61048349e366f710aa0168a1c08606d7bebb65f980ccf2616ad2102a503dfc70ad1f1a510f7e3c79ffeebc608f27c6670edfb7b420bd32fdb044b73ac73640380ca00b268",
        "script_type": 15,
        "subaccount": 0,
        "subtype": 51840,
        "tx_count": 0,
        "user_path": [
          1,
          2
        ],
      },
      {
        "address": "2MzyxeSfodsJkj4YYAyyNpGwqpvdze7qLSf",
        "address_type": "csv",
        "branch": 1,
        "is_internal": false,
        "pointer": 1,
        "script": "2102815c7ba597b1e0f08357ddb346dab3952b2a76e189efc9ebde51ec005df0b41cad210328154df2714de6b15e740330b3509ce26bc0a3e21bf77ce0eaefeea0e9e77b59ac73640380ca00b268",
        "script_type": 15,
        "subaccount": 0,
        "subtype": 51840,
        "tx_count": 0,
        "user_path": [
          1,
          1
        ],
      }
    ],
  }

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
    "all_coins": false,
    "expired_at": 99999,
    "confidential": false,
    "dust_limit": 546
  }

:subaccount: The subaccount to fetch unspent outputs for.
:num_confs: Pass ``0`` for unconfirmed UTXOs or ``1`` for confirmed.
:all_coins: Pass ``true`` to include UTXOs with status ``frozen``. Defaults to ``false``.
:expired_at: If given, only UTXOs where two-factor authentication expires
    by the given block are returned.
:confidential: Pass ``true`` to include only confidential UTXOs. Defaults to ``false``.
:dust_limit: If given, only UTXOs with a value greater than the limit value are returned.


.. _unspent-outputs:

Unspent outputs JSON
--------------------

Contains the filtered unspent outputs.

.. code-block:: json

  {
    "unspent_outputs": {
      "btc": [
        {
          "txhash": "09933a297fde31e6477d5aab75f164e0d3864e4f23c3afd795d9121a296513c0",
          "pt_idx": 0,
          "satoshi": 10000,
          "block_height": 1448369,
          "address_type": "p2wsh",
          "is_internal": false,
          "pointer": 474,
          "subaccount": 0,
          "prevout_script": "522102ff54a17dc6efe168673dbf679fe97e06b5cdcaf7dea8ab83dc6732350cd1b4e4210279979574e0743b4659093c005256c812f68f512c50d7d1622650b891de2cd61e52ae",
          "user_path": [
            1,
            474
          ],
          "public_key": "0279979574e0743b4659093c005256c812f68f512c50d7d1622650b891de2cd61e",
          "expiry_height": 1458369,
          "script_type": 14,
          "user_status": 0,
          "subtype": 0,
        },
      ],
    }
  }

:txhash: The txid of the transaction.
:pt_idx: The index of the output, the vout.
:satoshi: The amount of the output.
:block_height: The height of the block where the transaction is included.
               Is 0 if the transaction is unconfirmed.
:address_type: One of ``"csv"``, ``"p2sh"``, ``"p2wsh"`` (multisig),
    or ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"`` (singlesig), indicating the type of address.
:is_internal: Whether or not the user key belongs to the internal chain. Always false for multisig.
:pointer: The user key number/final number in the derivation path.
:subaccount: The subaccount this output belongs to.
             Matches ``"pointer"`` from :ref:`subaccount-list` or :ref:`subaccount-detail`.
:prevout_script: The script being signed, the script code.
:user_path: The BIP32 path for the user key.
:public_key: Singlesig only. The user public key.
:expiry_height: Multisig only.
                The block height when two-factor authentication expires.
:script_type: Multisig only. Integer representing the type of script.
:user_status: Multisig only. 0 for ``"default"`` and 1 for ``"frozen"``.
:subtype: Multisig only. For ``"address_type"`` ``"csv"``,
          the number of CSV blocks referenced in ``"script"``, otherwise, 0.

For Liquid instead of having the ``"btc"`` field, there are (possibly) multiple
fields, one for each asset owned, and the keys are the hex-encoded policy ids.

For Liquid the inner maps have additional fields:

.. code-block:: json

  {
    "amountblinder": "3be117b88ba8284b05b89998bdee1ded8cd5b561ae3d05bcd91d4e8abab2cd47",
    "asset_id": "e4b76d990f27bf6063cb66ff5bbc783d03258a0406ba8ac09abab7610d547e72",
    "asset_tag": "0b103a2d34cf469987dd06937919f9dae8c9856be17c554fd408fdc226b1769e59",
    "assetblinder": "aedb6c37d0ea0bc64fbc7036b52d0a0784da0b1ca90ac918c19ee1025b0c944c",
    "commitment": "094c3f83d5bac22b527ccac141fe04883d79bf04aef10a1dd42f501c5b51318907",
    "confidential": true,
    "nonce_commitment": "0211b39afe463473e428cfafd387f9c85b350f440131fad03aa5f4809b6c834f30"
  }


:amountblinder: The hex-encoded amount blinder (value blinding factor, vbf).
:asset_id: The hex-encoded asset id in display format.
:asset_tag: The hex-encoded asset commitment.
:assetblinder: The hex-encoded asset blinder (asset blinding factor, abf).
:commitment: The hex-encoded value commitment.
:confidential: A boolean indicating whether or not the output is confidential.
:nonce_commitment: The hex-encoded nonce commitment.

.. _unspent-outputs-status:

Unspent ouputs set status JSON
------------------------------

Valid status values are ``"default"`` for normal behaviour or ``"frozen"``. Frozen
outputs are hidden from the caller's balance and unspent output requests, are
not returned in nlocktime emails, and cannot be spent. An account containing
frozen outputs can be deleted, whereas an account with unfrozen outputs can not.

Freezing an output requires two factor authentication. Outputs should only be
frozen in response to e.g. a dust attack on the wallet. Once a wallet is
deleted, any frozen outputs it contained will be unspendable forever.

.. note:: Only outputs of value less that two times the dust limit can be frozen.

.. code-block:: json

  {
    "list" : [
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

.. code-block:: json

  {
    "address_explorer_url": "",
    "bech32_prefix": "bcrt",
    "bip21_prefix": "bitcoin",
    "csv_buckets": [
      144,
      4320,
      51840
    ],
    "development": true,
    "electrum_tls": false,
    "electrum_url": "localhost:19002",
    "liquid": false,
    "mainnet": false,
    "name": "Localtest",
    "network": "localtest",
    "p2pkh_version": 111,
    "p2sh_version": 196,
    "server_type": "green",
    "service_chain_code": "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04",
    "service_pubkey": "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3",
    "spv_multi": false,
    "spv_servers": [],
    "spv_enabled": false,
    "tx_explorer_url": "",
    "wamp_cert_pins": [],
    "wamp_cert_roots": [],
    "wamp_onion_url": "",
    "wamp_url": "ws://localhost:8080/v2/ws"
  }

.. _networks-list:

Network list JSON
-----------------

Contains a list of all available networks the API can connect to.


.. code-block:: json

  {
    "all_networks": [
      "mainnet",
      "liquid",
      "testnet"
    ],
    "liquid": { },
    "mainnet": { },
    "testnet": { },
  }

For each network listed, a :ref:`network` element is present containing
the networks information.


.. _transaction-limits:

Transaction limits JSON
-----------------------

.. code-block:: json

  {"is_fiat":false,"mbtc":"555"}
  {"is_fiat":true,"fiat":"555"}

.. _twofactor-detail:

Two-factor detail JSON
----------------------

.. code-block:: json

  {"confirmed":true,"data":"mail@example.com","enabled":true}

.. _auth-handler-status:

Auth handler status JSON
------------------------

Describes the status of a GA_auth_handler. Returned by `GA_auth_handler_get_status`.

The data returned depends on the current state of the handler, as follows:

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
:error: A text description of the error that occured.

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
:methods: A list of the two factor methods the user has enabled.

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


.. _reconnect:

Reconnect JSON
--------------

Controls session and internal Tor instance reconnection behaviour.

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
    "is_current": true
  }

:fiat_currency: Set to the users fiat currency if available, otherwise an empty string.
:fiat_rate: Set to the users fiat exchange rate if available, otherwise ``null``.
:is_current: ``true`` if the ``"fiat_currency"`` and ``"fiat_rate"`` members are current.


.. _currencies:

Available currencies JSON
-------------------------

.. code-block:: json

   {
     "all":["AUD","BRL","CAD","CHF","CNY","DKK","EUR","GBP","HKD","IDR","INR","JPY","MXN","MYR","NGN","NOK","NZD","PLN","RUB","SEK","SGD","THB","TRY","USD","ZAR"],
     "per_exchange":{"BITFINEX":["USD"],"BITSTAMP":["USD"],"BTCAVG":[],"BTCCHINA":[],"HUOBI":[],"KIWICOIN":["NZD"],"KRAKEN":["EUR","USD"],"LOCALBTC":["AUD","BRL","CAD","CHF","CNY","DKK","EUR","GBP","HKD","IDR","INR","JPY","MXN","MYR","NGN","NOK","NZD","PLN","RUB","SEK","SGD","THB","TRY","USD","ZAR"],"LUNO":["IDR","MYR","NGN","ZAR"],"QUADRIGACX":["CAD","USD"],"TRT":["EUR"]}
   }



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

.. code-block:: json

   {
      "assets_id": ["6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d","144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"],
   }


.. _asset-informations:

Asset informations JSON
--------------------------

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
      "details":"assertion failure: ../src/ga_session.cpp:rename_subaccount:2166:Unknown subaccount"
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

Validate a JSON.
Currently it's only possible to validate a LiquiDEX version 0 proposal.

.. code-block:: json

  {
    "liquidex_v0": {
      "proposal": {},
    },
  }

:liquidex_v0/proposal: The LiquiDEX version 0 proposal to validate.

.. _validate-result:

Validate Result JSON
--------------------

.. code-block:: json

  {
    "is_valid": true,
    "errors": []
  }

:is_valid: True if the JSON is valid.
:errors: If the JSON is not valid, a list of error strings.
