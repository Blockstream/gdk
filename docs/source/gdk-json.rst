GDK JSON
========

This section describes the various JSON formats used by the library.

.. _init-config-arg:

Initialization config JSON
--------------------------

Passed to `GA_init` when initializing the library.

.. code-block:: json

    {
        "datadir": "/path/to/datadir"
    }

:datadir: An optional directory which the gdk will use to store encrypted data
         relating to sessions. If omitted no local storage will be used, note
         that this may significantly decrease the performance of some calls.

.. _net-params:

Connection parameters JSON
--------------------------

.. code-block:: json

   {
      "name": "testnet",
      "log_level": "info",
      "proxy": "localhost:9150",
      "use_tor": true,
      "user_agent": "green_android v2.33",
      "spv_enabled": false,
      "cert_expiry_threshold": 1,
   }

:cert_expiry_threshold: Reject/ignore certificates expiring within this many days
                        from today. This is useful for pre-empting problems with
                        expiring embedded certificates.

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

Contains the data returned by `GA_set_pin`. The caller must persist this
data and pass it to `GA_login_user` along with the users PIN in order to
allow a PIN login.

.. code-block:: json

   {
      "encrypted_data": "0b39c1e90ca6adce9ff35d1780de74b91d46261a7cbf2b8d2fdc21528c068c8e2b26e3bf3f6a2a992e0e1ecfad0220343b9659495e7f4b21ff95c32cee1b2dd6b0f44b3828ccdc73d68d9e4142a25437b0c6b53a056e2415ca23442dd18d11fb5f62ef9155703c36a5b3e10b2d93973602cebb2369559612cb4267f4826028cea7b067d6ec3658cc72155a4b17b4ba277c143d40ce49c407102c62ca759d04e74dd0778ac514292be09f66449993c36b0bc0cb78f41368bc394d0cf444d452bea0e7df5766b92a3c3a3c57169c2529e9aa36e89b3f6dfcfddc6027f3aabd47dedbd9851729a3f6fba899842b1f5e949117c62e94f558da5ebd37feb4927209e2ead2d492c1d647049e8a1347c46c75411a14c5420ef6896cd0d0c6145af76668d9313f3e71e1970de58f674f3b387e4c74d24214fbc1ad7d30b3d2db3d6fb7d9e92dd1a9f836dad7c2713dc6ebfec62f",
      "pin_identifier": "38e2f188-b3a8-4d98-a7f9-6c348cb54cfe",
      "salt": "a99/9Qy6P7ON4Umk2FafVQ=="
   }


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

.. code-block:: json

    [
      {
        "addressees": [
          ""
        ],
        "block_height": 0,
        "calculated_fee_rate": 1004,
        "can_cpfp": true,
        "can_rbf": false,
        "created_at_ts": 1551280324000000,
        "fee": 206,
        "fee_rate": 1004,
        "inputs": [
          {
            "address": "",
            "address_type": "p2wsh",
            "addressee": "",
            "is_output": false,
            "is_relevant": false,
            "is_spent": true,
            "pointer": 1640,
            "pt_idx": 0,
            "satoshi": 1834469,
            "script_type": 14,
            "subaccount": 0,
            "subtype": 0
          }
        ],
        "memo": "",
        "outputs": [
          {
            "address": "2N3GFLkDKXZRNUqBdHN2SDdwFXrc5FKAJ3a",
            "address_type": "p2wsh",
            "addressee": "",
            "is_output": true,
            "is_relevant": true,
            "is_spent": false,
            "pointer": 1,
            "pt_idx": 0,
            "satoshi": 200000,
            "script_type": 14,
            "subaccount": 4,
            "subtype": 0
          },
          {
            "address": "2N8HdRzRsV8fF8jWroeX1Hd6CFTBvUuEZfJ",
            "address_type": "p2wsh",
            "addressee": "",
            "is_output": true,
            "is_relevant": false,
            "is_spent": false,
            "pointer": 1657,
            "pt_idx": 1,
            "satoshi": 1634263,
            "script_type": 14,
            "subaccount": 0,
            "subtype": 0
          }
        ],
        "rbf_optin": true,
        "satoshi": 200000,
        "server_signed": true,
        "transaction_size": 370,
        "transaction_vsize": 205,
        "transaction_weight": 820,
        "txhash": "fe50531d94fae597d9e209582a401e62b1f705ace93eca94fe2e42f187456e4a",
        "type": "incoming",
        "user_signed": true,
        "vsize": 205,
        "spv_verified": "disabled"
      }
    ]


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
  "subaccount": 0
 }

 {
  "addressees": [
    {
      "address": "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b",
      "satoshi": 100000
    }
  ],
  "subaccount": 0,
  "fee_rate": 1000
 }

.. _sign-tx-details:

Sign transaction JSON
---------------------

.. code-block:: json

  {
  "addressees": [
    {
      "address": "2MtcMpWnde3tf5vfwnHXKBaWuAUS8j89771",
      "bip21-params": null,
      "satoshi": 100000
    }
  ],
  "addressees_read_only": false,
  "amount_read_only": false,
  "available_total": 4999794,
  "calculated_fee_rate": 1000,
  "change_address": {
    "address": "2NAvvWUygud1YSdsqTZbnntMRjsbx4RxP3Z",
    "address_type": "p2wsh",
    "branch": 1,
    "pointer": 492,
    "script": "522102da0e5f74219dadbd392dc3157c43c3636e237005e7f3976a338e519901fdf9e32103326c44e51893994677bb43e5d272af11aea967a4ca3f1c431fe41e6a7851a35152ae",
    "script_type": 14,
    "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
    "subaccount": 0,
    "subtype": null,
    "user_path": [
      1,
      492
    ]
  },
  "change_amount": 4889588,
  "change_index": 0,
  "change_subaccount": 0,
  "error": "",
  "fee": 206,
  "fee_rate": 1000,
  "have_change": true,
  "is_redeposit": false,
  "is_sweep": false,
  "network_fee": 0,
  "satoshi": {
    "btc": 100000
  },
  "send_all": false,
  "server_signed": false,
  "subaccount": 0,
  "transaction": "02000000000101c01365291a12d995d7afc3234f4e86d3e064f175ab5a7d47e631de7f293a930901000000230000000000000000000000000000000000000000000000000000000000000000000000fdffffff02f49b4a000000000017a914c1fc2f90044f58698bf9c51f3283e25c809ac17d87a08601000000000017a9140ef7660003133f69023f0436dc8bcf427941dcf5870400480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000047522103bad7ac76143368781c4ac3e7afbb63cd6b52f2a923c715576804aa1046cabc1a210264f5fa70969907861ebdb2b2d53beb125523bb5140b90194481e2415ade1787452ae4ca21600",
  "transaction_locktime": 1483340,
  "transaction_outputs": [
    {
      "address": "2NAvvWUygud1YSdsqTZbnntMRjsbx4RxP3Z",
      "address_type": "p2wsh",
      "branch": 1,
      "is_change": true,
      "pointer": 492,
      "satoshi": 4889588,
      "script": "a914c1fc2f90044f58698bf9c51f3283e25c809ac17d87",
      "script_type": 14,
      "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
      "subaccount": 0,
      "subtype": null,
      "user_path": [
        1,
        492
      ]
    },
    {
      "address": "2MtcMpWnde3tf5vfwnHXKBaWuAUS8j89771",
      "is_change": false,
      "satoshi": 100000,
      "script": "a9140ef7660003133f69023f0436dc8bcf427941dcf587"
    }
  ],
  "transaction_size": 372,
  "transaction_version": 2,
  "transaction_vsize": 206,
  "transaction_weight": 822,
  "used_utxos": [
    0
  ],
  "user_signed": false,
  "utxo_strategy": "default",
  "utxos": [
    {
      "address_type": "p2wsh",
      "block_height": 1448369,
      "pointer": 475,
      "prevout_script": "522103bad7ac76143368781c4ac3e7afbb63cd6b52f2a923c715576804aa1046cabc1a210264f5fa70969907861ebdb2b2d53beb125523bb5140b90194481e2415ade1787452ae",
      "pt_idx": 1,
      "satoshi": 4989794,
      "script_type": 14,
      "sequence": 4294967293,
      "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
      "subaccount": 0,
      "subtype": 0,
      "txhash": "09933a297fde31e6477d5aab75f164e0d3864e4f23c3afd795d9121a296513c0",
      "user_path": [
        1,
        475
      ]
    },
    {
      "address_type": "p2wsh",
      "block_height": 1448369,
      "pointer": 474,
      "pt_idx": 0,
      "satoshi": 10000,
      "script_type": 14,
      "subaccount": 0,
      "subtype": 0,
      "txhash": "09933a297fde31e6477d5aab75f164e0d3864e4f23c3afd795d9121a296513c0"
    }
  ],
  "memo": ""
  }



.. _send-tx-details:

Send transaction JSON
---------------------

.. code-block:: json

  {
  "addressees": [
    {
      "address": "2NDwUefHRbbHuGsumAWMbRZUzigrtBYkwrq",
      "bip21-params": null,
      "satoshi": 100000
    }
  ],
  "addressees_read_only": false,
  "amount_read_only": false,
  "available_total": 4999588,
  "calculated_fee_rate": 1281,
  "change_address": {
    "address": "2Mtpg961bP6WH9cQvY2qS4rnuceoRBrnutn",
    "address_type": "p2wsh",
    "branch": 1,
    "pointer": 497,
    "script": "52210350683b20cc33983f818c9b50606909622dbc4387a17699e5ae09b9d5d1b3111c21028598a36a99fbda64ff1d942afef40b1ad80050c2f8d7191f2ac302a58d9db40252ae",
    "script_type": 14,
    "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
    "subaccount": 0,
    "subtype": null,
    "user_path": [
      1,
      497
    ]
  },
  "change_amount": 109663,
  "change_index": 1,
  "change_subaccount": 0,
  "error": "",
  "fee": 337,
  "fee_rate": 1000,
  "have_change": true,
  "is_redeposit": false,
  "is_sweep": false,
  "memo": "",
  "network_fee": 0,
  "satoshi": 100000,
  "send_all": false,
  "server_signed": false,
  "subaccount": 0,
  "transaction": "020000000001027ff3490a29a2fe73f07e3d3f8740249d61c0025fdc0819586dd9443bc6a00bd30100000023220020ed1761c2b0035dd221ec0f7f78ad88b44f7575884daa668def774bf4db97696afdffffffc01365291a12d995d7afc3234f4e86d3e064f175ab5a7d47e631de7f293a9309000000002322002012ba0847af1dcfb9a3d112224d6ed60f361cfdce243f98867aa85836f84bf808fdffffff02a08601000000000017a914e2ff64a1ca976947d47b6b2d214af96d5942e1b2875fac01000000000017a914114baed477ca8fb65f856b96f860acc52619a6fc870147304402200333910d9c37f5749298dbf8017e4f9932df2e727eeae907e65e102d267045e40220636500d1db9d92b7ff9f1fe1662d9445acfc322d19575ca1aefc98de9b37967a01014730440220731c09346ddff84673c7eeb64003339bc86a03eee04f49f6f1730884e2a772b002207e6a88797e9e0a76b0d85f55a1de52fcc70f80b9647028cca68b7790c83a6bd5014ea21600",
  "transaction_locktime": 1483342,
  "transaction_outputs": [
    {
      "address": "2NDwUefHRbbHuGsumAWMbRZUzigrtBYkwrq",
      "is_change": false,
      "satoshi": 100000,
      "script": "a914e2ff64a1ca976947d47b6b2d214af96d5942e1b287"
    },
    {
      "address": "2Mtpg961bP6WH9cQvY2qS4rnuceoRBrnutn",
      "address_type": "p2wsh",
      "branch": 1,
      "is_change": true,
      "pointer": 497,
      "satoshi": 109663,
      "script": "a914114baed477ca8fb65f856b96f860acc52619a6fc87",
      "script_type": 14,
      "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
      "subaccount": 0,
      "subtype": null,
      "user_path": [
        1,
        497
      ]
    }
  ],
  "transaction_size": 374,
  "transaction_version": 2,
  "transaction_vsize": 263,
  "transaction_weight": 1052,
  "used_utxos": [
    1,
    0
  ],
  "user_signed": true,
  "utxo_strategy": "default",
  "utxos": [
    {
      "address_type": "p2wsh",
      "block_height": 1448369,
      "pointer": 474,
      "prevout_script": "522102ff54a17dc6efe168673dbf679fe97e06b5cdcaf7dea8ab83dc6732350cd1b4e4210279979574e0743b4659093c005256c812f68f512c50d7d1622650b891de2cd61e52ae",
      "pt_idx": 0,
      "satoshi": 10000,
      "script_type": 14,
      "sequence": 4294967293,
      "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
      "subaccount": 0,
      "subtype": 0,
      "txhash": "09933a297fde31e6477d5aab75f164e0d3864e4f23c3afd795d9121a296513c0",
      "user_path": [
        1,
        474
      ]
    },
    {
      "address_type": "p2wsh",
      "block_height": 0,
      "pointer": 493,
      "prevout_script": "522102c9465e8b6e98848428b90f21291a19c62fcb20d2dbff76217068219cada5f7a921022e831b15a4faa339ed9a09a6f1bc01da9001f86130e010a397603b4b4230a22552ae",
      "pt_idx": 1,
      "satoshi": 200000,
      "script_type": 14,
      "sequence": 4294967293,
      "service_xpub": "tpubEAUTpVqYYmDxumXSPwZEgCRC5HZXagbsATdv3wUMweyDrJY4fVDt89ogtpBxa9ynpXB3AyGen3Ko4S8ewpWkkvQsvYP86oEc8z9B6crQ5gn",
      "subaccount": 0,
      "subtype": 0,
      "txhash": "d30ba0c63b44d96d581908dc5f02c0619d2440873f3d7ef073fea2290a49f37f",
      "user_path": [
        1,
        493
      ]
    },
    {
      "address_type": "p2wsh",
      "block_height": 0,
      "pointer": 494,
      "pt_idx": 0,
      "satoshi": 4789588,
      "script_type": 14,
      "subaccount": 0,
      "subtype": 0,
      "txhash": "d30ba0c63b44d96d581908dc5f02c0619d2440873f3d7ef073fea2290a49f37f"
    }
  ]
  }



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
      "email_outgoing": true
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
    "subtype": null
  }

:subaccount: The value of "pointer" from :ref:`subaccount-list` or :ref:`subaccount-detail` for the subaccount to generate an address for. Default 0.
:address_type: One of "csv", "p2sh", "p2wsh". Default value depends on wallet settings.



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
:last_pointer: The address pointer from which results should be returned. Passing 0 (the default) returns
               the newest generated addresses. The "last_pointer" value from the resulting :ref:`previous-addresses`
               should then be given, until sufficient pages have been fetched or the "last_pointer" value
               is 1 indicating all addresses have been fetched.



.. _previous-addresses:

Previous addresses JSON
-----------------------

Contains a page of previously generated addresses, from newest to oldest.

.. code-block:: json

  {
    "last_pointer": 1,
    "list": [
      {
        "address": "2N52RVsChsCi439PpJ1Hn8fHCiTrRjcAEiL",
        "address_type": "csv",
        "branch": 1,
        "pointer": 2,
        "script": "2102df992d7fa8f012d61048349e366f710aa0168a1c08606d7bebb65f980ccf2616ad2102a503dfc70ad1f1a510f7e3c79ffeebc608f27c6670edfb7b420bd32fdb044b73ac73640380ca00b268",
        "script_type": 15,
        "subaccount": 0,
        "subtype": 51840,
        "tx_count": 0
      },
      {
        "address": "2MzyxeSfodsJkj4YYAyyNpGwqpvdze7qLSf",
        "address_type": "csv",
        "branch": 1,
        "pointer": 1,
        "script": "2102815c7ba597b1e0f08357ddb346dab3952b2a76e189efc9ebde51ec005df0b41cad210328154df2714de6b15e740330b3509ce26bc0a3e21bf77ce0eaefeea0e9e77b59ac73640380ca00b268",
        "script_type": 15,
        "subaccount": 0,
        "subtype": 51840,
        "tx_count": 0
      }
    ],
    "subaccount": 0
  }

:last_pointer: Contains the next_pointer value to pass in :ref:`previous-addresses-request` in a
               subsequent call to `GA_get_previous_addresses` in order to fetch the next page.
               Will be 1 when all addresses have been fetched.
:list: Contains the current page of addresses in :ref:`receive-address-details` format.
:subaccount: The subaccount which the generated addresses belong to.



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


.. _hint:

Reconnect hint JSON
-------------------

.. code-block:: json

   { "hint" : "now" }

.. code-block:: json

   { "hint" : "disable" }

.. code-block:: json

   { "tor_sleep_hint" : "wakeup", "hint": "start" }

.. code-block:: json

   { "tor_sleep_hint" : "sleep" }



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



.. _session-event:

Session event notification JSON
-------------------------------

.. code-block:: json

   {
      "event": "session"
      "session": {"connected": false}
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
      "icons": true,
      "refresh": true
   }


.. _error-details:

Error details JSON
------------------

.. code-block:: json

   {
      "details":"assertion failure: ../src/ga_session.cpp:rename_subaccount:2166:Unknown subaccount"
   }
