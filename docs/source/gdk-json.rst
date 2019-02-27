Gdk JSON
========

In this section there are some example JSON used by the lib

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

Subaccount JSON
---------------

.. code-block:: json

   {
      "name": "subaccount name",
      "type": "2of2"
   }

.. _subaccount-detail:

Subaccount detail JSON
----------------------

.. code-block:: json

   {
     "bits": "20344.69",
     "btc": "0.02034469",
     "fiat": "0.02",
     "fiat_currency": "EUR",
     "fiat_rate": "1.10000000",
     "has_transactions": true,
     "is_dirty": false,
     "mbtc": "20.34469",
     "name": "",
     "pointer": 0,
     "receiving_id": "GA3wd2nqwZ8FVwrB8GBsDDh4v8AtdV",
     "recovery_chain_code": "",
     "recovery_pub_key": "",
     "satoshi": 2034469,
     "type": "2of2",
     "ubtc": "20344.69"
   }
  


.. _subaccount-list:

Subaccount list JSON
--------------------

.. code-block:: json

   [
     {
       "bits": "20344.69",
       "btc": "0.02034469",
       "fiat": "0.02",
       "fiat_currency": "EUR",
       "fiat_rate": "1.10000000",
       "has_transactions": true,
       "is_dirty": false,
       "mbtc": "20.34469",
       "name": "",
       "pointer": 0,
       "receiving_id": "GA3wd2nqwZ8FVwrB8GBsDDh4v8AtdV",
       "recovery_chain_code": "",
       "recovery_pub_key": "",
       "satoshi": 2034469,
       "type": "2of2",
       "ubtc": "20344.69"
     },
     {
       "bits": "9779.07",
       "btc": "0.00977907",
       "fiat": "0.01",
       "fiat_currency": "EUR",
       "fiat_rate": "1.10000000",
       "has_transactions": true,
       "is_dirty": false,
       "mbtc": "9.77907",
       "name": "Nuovo",
       "pointer": 1,
       "receiving_id": "GA36xH9spaXv3HCUcjbh7UEPxf1f6t",
       "recovery_chain_code": "",
       "recovery_pub_key": "",
       "satoshi": 977907,
       "type": "2of2",
       "ubtc": "9779.07"
     }
   ]

.. _tx-list:

Transactions list JSON
----------------------

.. code-block:: json

  {
    "list": [
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
    ],
    "next_page_id": 0,
    "page_id": 0
  }



.. _tx-detail:

Transaction detail JSON
-----------------------

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


.. _limits:

Limits JSON
----------------------

.. code-block:: json

  {"is_fiat":false,"mbtc":"555"}

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





