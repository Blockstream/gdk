Gdk JSON
========

In this section there are some example JSON used by the lib

.. _net-params:

Connection parameter JSON
-------------------------

.. code-block:: json

   {
      "name": "testnet",
      "log_level": "info",
      "proxy": "localhost:9150",
      "use_tor": true
   }

.. _hw-device:

HW device JSON
--------------

.. code-block:: json

   {
      "device": {
         "name": "Ledger",
         "supports_arbitrary_scripts": true,
         "supports_low_r": false
      }
   }

.. _pin-data:

PIN data JSON
-------------

.. code-block:: json

   {
      "encrypted_data": "0b39c1e90ca6adce9ff35d1780de74b91d46261a7cbf2b8d2fdc21528c068c8e2b26e3bf3f6a2a992e0e1ecfad0220343b9659495e7f4b21ff95c32cee1b2dd6b0f44b3828ccdc73d68d9e4142a25437b0c6b53a056e2415ca23442dd18d11fb5f62ef9155703c36a5b3e10b2d93973602cebb2369559612cb4267f4826028cea7b067d6ec3658cc72155a4b17b4ba277c143d40ce49c407102c62ca759d04e74dd0778ac514292be09f66449993c36b0bc0cb78f41368bc394d0cf444d452bea0e7df5766b92a3c3a3c57169c2529e9aa36e89b3f6dfcfddc6027f3aabd47dedbd9851729a3f6fba899842b1f5e949117c62e94f558da5ebd37feb4927209e2ead2d492c1d647049e8a1347c46c75411a14c5420ef6896cd0d0c6145af76668d9313f3e71e1970de58f674f3b387e4c74d24214fbc1ad7d30b3d2db3d6fb7d9e92dd1a9f836dad7c2713dc6ebfec62f",
      "pin_identifier": "38e2f188-b3a8-4d98-a7f9-6c348cb54cfe",
      "salt": "a99/9Qy6P7ON4Umk2FafVQ=="
   }

.. _subaccount:

Subaccount detail JSON
----------------------

.. code-block:: json

   {
      "name": "subaccount name",
      "type": "2of2"
   }

.. _subaccount-detail:

Subaccount JSON
---------------

.. code-block:: json

   {
     "balance": {
       "bits": "20344.69",
       "btc": "0.02034469",
       "fiat": "0.02",
       "fiat_currency": "EUR",
       "fiat_rate": "1.10000000",
       "mbtc": "20.34469",
       "satoshi": 2034469,
       "sats": "2034469",
       "ubtc": "20344.69"
       },
     "has_transactions": true,
     "name": "",
     "pointer": 0,
     "receiving_id": "GA3wd2nqwZ8FVwrB8GBsDDh4v8AtdV",
     "recovery_chain_code": "",
     "recovery_pub_key": "",
     "type": "2of2"
   }
  


.. _subaccount-list:

Subaccounts list JSON
---------------------

.. code-block:: json

   [
     {
       "balance": {
         "bits": "20344.69",
         "btc": "0.02034469",
         "fiat": "0.02",
         "fiat_currency": "EUR",
         "fiat_rate": "1.10000000",
         "mbtc": "20.34469",
         "satoshi": 2034469,
         "sats": "2034469",
         "ubtc": "20344.69"
         },
       "has_transactions": true,
       "name": "",
       "pointer": 0,
       "receiving_id": "GA3wd2nqwZ8FVwrB8GBsDDh4v8AtdV",
       "recovery_chain_code": "",
       "recovery_pub_key": "",
       "type": "2of2"
     },
     {
       "balance": {
         "bits": "9779.07",
         "btc": "0.00977907",
         "fiat": "0.01",
         "fiat_currency": "EUR",
         "fiat_rate": "1.10000000",
         "mbtc": "9.77907",
         "satoshi": 977907,
         "sats": "977907",
         "ubtc": "9779.07"
         },
       "has_transactions": true,
       "name": "Nuovo",
       "pointer": 1,
       "receiving_id": "GA36xH9spaXv3HCUcjbh7UEPxf1f6t",
       "recovery_chain_code": "",
       "recovery_pub_key": "",
       "type": "2of2"
     }
   ]

.. _tx-list:

Transactions list JSON
----------------------

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
        "created_at": "2019-02-27 15:12:04",
        "fee": 206,
        "fee_rate": 1004,
        "has_payment_request": false,
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
        "instant": false,
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
        "transaction": "02000000000101e8052d983019fa66c10f311d04f5d11e8ceb058f2653a0f4f74f82283119a7f10100000023220020b5117c293841984f37d3c0282404f6d1942baf11ad7c55c121bb073fd149e184fdffffff02400d03000000000017a9146de2cd94e2099356f861e1944d577037c6bbb23f87d7ef18000000000017a914a4fe49c0d25b89245753247e121520a96261dc2f87040047304402200cc587a9c7688bdf6be35067bd9f4b4271e232906d21e4f4a1ef11dbcca6a47402201825fb44368353e03982d5a4713cfef2123c136b8cad1de5d66ae33a729bf275014730440220049c1e16842d853d7fca780e1735779f2cc00f3e9b6caf163161a60ae1aeb19c02207b24a0b920d241be72e9887f6951d81a7230c0aad2e708e8dcc1c78d7a433715014752210316803ed4d0a589e3703efa04fdd09fc355aae4c931dd2bce5d71f2b8f9b17c262102f201a83a892804664d3e574bf23c5bebd0c319ed62111a5120c700039a745e9952aefb9c1600",
        "transaction_locktime": 1481979,
        "transaction_outputs": [],
        "transaction_size": 370,
        "transaction_version": 2,
        "transaction_vsize": 205,
        "transaction_weight": 820,
        "txhash": "fe50531d94fae597d9e209582a401e62b1f705ace93eca94fe2e42f187456e4a",
        "type": "incoming",
        "user_signed": true,
        "vsize": 205
      }
    ]


.. _tx-detail:

Transaction details JSON
------------------------

.. code-block:: json

  {
    "transaction": "02000000000101e8052d983019fa66c10f311d04f5d11e8ceb058f2653a0f4f74f82283119a7f10100000023220020b5117c293841984f37d3c0282404f6d1942baf11ad7c55c121bb073fd149e184fdffffff02400d03000000000017a9146de2cd94e2099356f861e1944d577037c6bbb23f87d7ef18000000000017a914a4fe49c0d25b89245753247e121520a96261dc2f87040047304402200cc587a9c7688bdf6be35067bd9f4b4271e232906d21e4f4a1ef11dbcca6a47402201825fb44368353e03982d5a4713cfef2123c136b8cad1de5d66ae33a729bf275014730440220049c1e16842d853d7fca780e1735779f2cc00f3e9b6caf163161a60ae1aeb19c02207b24a0b920d241be72e9887f6951d81a7230c0aad2e708e8dcc1c78d7a433715014752210316803ed4d0a589e3703efa04fdd09fc355aae4c931dd2bce5d71f2b8f9b17c262102f201a83a892804664d3e574bf23c5bebd0c319ed62111a5120c700039a745e9952aefb9c1600",
    "transaction_locktime": 1481979,
    "transaction_outputs": [],
    "transaction_size": 370,
    "transaction_version": 2,
    "transaction_vsize": 205,
    "transaction_weight": 820,
    "txhash": "fe50531d94fae597d9e209582a401e62b1f705ace93eca94fe2e42f187456e4a"
  }



.. _transaction-details:

Create Transaction JSON
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

Sign Transaction JSON
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
  "satoshi": 100000,
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
      "ga_asset_id": 1,
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
      "ga_asset_id": 1,
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

Send Transaction JSON
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
      "ga_asset_id": 1,
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
      "ga_asset_id": 1,
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
      "ga_asset_id": 1,
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



.. _estimates:

Fee Estimates JSON
------------------

.. code-block:: json

  {"fees":[1000,10070,10070,10070,3014,3014,3014,2543,2543,2543,2543,2543,2543,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499,1499]}

.. _configuration:

Two-Factor Config JSON
----------------------

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
    "data": "test@test.com",
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



.. _settings:

Settings JSON
-------------

.. code-block:: json

  {
    "altimeout": 10,
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



.. _balance-details:

Balance Details JSON
--------------------

.. code-block:: json

  {"subaccount":4,"num_confs":0}



.. _unspent-utxos-details:

Utxos details JSON
------------------

.. code-block:: json

  {"subaccount":3,"num_confs":0}



.. _transactions-details:

Transactions Details JSON
-------------------------

.. code-block:: json

  {"subaccount":0,"first":0,"count":30}



.. _network:

Network JSON
------------

.. code-block:: json

  {
    "address_explorer_url": "http://192.168.56.1:8080/address/",
    "bech32_prefix": "tb",
    "default_peers": [
      "192.168.56.1:19000"
    ],
    "development": true,
    "liquid": false,
    "mainnet": false,
    "name": "Regtest",
    "network": "regtest",
    "p2pkh_version": 111,
    "p2sh_version": 196,
    "service_chain_code": "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04",
    "service_pubkey": "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3",
    "tx_explorer_url": "http://192.168.56.1:8080/tx/",
    "wamp_cert_pins": [],
    "wamp_onion_url": "",
    "wamp_url": "ws://10.0.2.2:8080/v2/ws"
  }


.. _networks-list:

Networks list JSON
------------------

.. code-block:: json

  [
    {
      "address_explorer_url": "https://blockstream.info/address/",
      "bech32_prefix": "bc",
      "default_peers": [],
      "development": false,
      "liquid": false,
      "mainnet": true,
      "name": "Bitcoin",
      "network": "mainnet",
      "p2pkh_version": 0,
      "p2sh_version": 5,
      "service_chain_code": "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d",
      "service_pubkey": "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f",
      "tx_explorer_url": "https://blockstream.info/tx/",
      "wamp_cert_pins": [
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
        "a74b0c32b65b95fe2c4f8f098947a68b695033bed0b51dd8b984ecae89571bb6"
      ],
      "wamp_onion_url": "ws://s7a4rvc6425y72d2.onion/v2/ws/",
      "wamp_url": "wss://prodwss.greenaddress.it/v2/ws"
    },
    {
      "address_explorer_url": "https://blockstream.info/testnet/address/",
      "bech32_prefix": "tb",
      "default_peers": [],
      "development": false,
      "liquid": false,
      "mainnet": false,
      "name": "Testnet",
      "network": "testnet",
      "p2pkh_version": 111,
      "p2sh_version": 196,
      "service_chain_code": "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04",
      "service_pubkey": "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3",
      "tx_explorer_url": "https://blockstream.info/testnet/tx/",
      "wamp_cert_pins": [
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
        "a74b0c32b65b95fe2c4f8f098947a68b695033bed0b51dd8b984ecae89571bb6"
      ],
      "wamp_onion_url": "ws://gu5ke7a2aguwfqhz.onion/v2/ws",
      "wamp_url": "wss://testwss.greenaddress.it/v2/ws"
    }
  ]



.. _transaction-limits:

Transaction Limits JSON
-----------------------

.. code-block:: json

  {"is_fiat":false,"mbtc":"555"}
  {"is_fiat":true,"fiat":"555"}

.. _twofactor-detail:

Two-factor detail JSON
----------------------

.. code-block:: json

  {"confirmed":true,"data":"mail@example.com","enabled":true}

.. _twofactor-status:

Two-factor status JSON
----------------------

.. code-block:: json

  {"action":"disable_2fa","device":null,"methods":["gauth"],"status":"request_code"}

.. _hint:

Reconnect hint JSON
-------------------

.. code-block:: json

   { "hint" : "now" }

.. code-block:: json

   { "hint" : "disable" }



.. _convert:

Convert data JSON
-----------------

.. code-block:: json

  {
    "satoshi": 1120
  }



.. _balance-data:

Balance data JSON
-----------------

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
  }



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



.. _params-data:

HTTP params JSON
----------------

.. code-block:: json

   {
      "uri":"https://assets.blockstream.info"
      "target":"/index.json"
      "proxy":"localhost:9150"
   }



.. _params-proxy:

Proxy connectivity params JSON
------------------------------

.. code-block:: json

   {
      "name":"testnet"
      "use_tor":true
      "proxy":"localhost:9150"
   }




