.. _hw-resolve-overview:

GDK Hardware Wallet Interface
=============================

This section details the format of data requests from hardware wallet
interaction during resolution of GA_auth_handler processing when
`GA_auth_handler_get_status` returns the status ``"resolve_code"`` with
a ``"required_data"`` element present.

.. _hw-required-data:

Required Data JSON
------------------

Returned as an element ``"required_data"`` of :ref:`auth-handler-status` when
data is required from a registered hardware device.

.. code-block:: json

     {
       "action": "",
       "device": {
       },
     }

:action: Describes the hardware wallet data requested.
:device: Contains the :ref:`hw-device` originally registered with the session.

Additional fields will be present depending on the action requested, as follows:


.. _hw-action-get-xpubs:

Hardware Get XPubs Action
-------------------------

When ``"action"`` is ``"get_xpubs"``, this describes a request to compute one
or more xpubs from the wallet's master key.

.. code-block:: json

     {
       "paths": [ [], [ 2147501889 ] ]
     }

:paths: An array of unsigned 32-bit integer arrays representing each xpub to
    fetch. The integer values should be interpreted per BIP32, i.e. the topmost
    bit may be set to indicate a private derivation in the path. An empty array
    indicates that the top level xpub should be returned.

**Expected response**:

.. code-block:: json

     {
       "xpubs": [
         "tpubD8G8MPH9RK9uk4EV97RxhzaY8SJPUWXnViHUwji92i8B7vYdht797PPDrJveeathnKxonJe8SbaScAC1YJ8xAzZbH9UvywrzpQTQh5pekkk",
         "tpubD6NzVbkrYhZ4X9jwmpJxg1kjEJTQgkrnHNEWww2e86X1eUfWu1f7hZpgezAyWUk5zRt4fMPHB33CXrvJSYHHAoVMFXrfxpornvJBgbvjvLN"
       ]
     }

:xpubs: An array of base58-encoded BIP32 extended public keys, in the same order
    as the ``"paths"`` elements in the request.


.. _hw-action-get-master-blinding-key:

Hardware Get Master Blinding Key Action
---------------------------------------

When ``"action"`` is ``"get_master_blinding_key"``, this describes a request
to return the wallet's SLIP0077 master blinding key if the user allows this.

.. note:: This action is only returned when using the Liquid network.

No request data is currently associated with this request.

**Expected response**:

.. code-block:: json

     {
       "master_blinding_key": "512cd6c0b73452a2414e9d86d37cdcc8283b44f0b6dd2b1eec23c59ff12b4f7e5949569b3430220dafce1e0e299a2a6f3fb3e62b2e8c860c82512cdf2d8b2fbc"
     }

:master_blinding_key: The 512-bit or 256-bit master blinding key for the wallet, hex-encoded.
    If a 256-bit key is returned, it should be the lower 256-bits of the SLIP0021 derived ``node``
    as specified in https://github.com/satoshilabs/slips/blob/master/slip-0077.md.

.. note:: If the user denies the request to share the key, an empty string should be returned.


.. _hw-action-sign-message:

Hardware Sign Message Action
----------------------------

When ``"action"`` is ``"sign_message"``, this describes a request to sign
a message using the given path.

.. code-block:: json

     {
       "message": "A text message to sign",
       "path": [ 1195487518 ],
       "use_ae_protocol": false,
       "create_recoverable_sig": false
     }

:message: The message to be utf-8 encoded and signed.
:path: The path from the wallet's master key to the key that the message should be signed with.
:use_ae_protocol: ``true`` if the hardware device advertises Anti-Exfil support and it should
    be used for signing, ``false`` otherwise.
:create_recoverable_sig: ``true`` if the signature to produce should be recoverable.
    Default ``false``.

**Expected response**:

.. code-block:: json

     {
       "signature": "304402207c673ef4255873cf095016c98c4982cea9a5133060b66a380f1bf3880e54f6c8022056fd731cbd44cd96366212439717a888470ed481628cba81195c557d5c4fc39c"
     }

:signature: The ECDSA signature corresponding to the given message.
    If ``"create_recoverable_sig"`` is ``false`` it must use DER encoding, otherwise it must be encoded in hex.


.. _hw-action-get-blinding-public-keys:

Hardware Get Blinding Public Keys Action
----------------------------------------

When ``"action"`` is ``"get_blinding_public_keys"``, this describes a request to
compute blinding public keys from wallet scripts.

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

     {
       "scripts": [ "a91403f650e2434916d5b7f124de8f673442b696282887" ]
     }

:scripts: An array of hex-encoded scripts for which a blinding key should be generated.

**Expected response**:

.. code-block:: json

     {
       "public_keys": [ "02045e92b8f68bd066180c05a39969f862a67f4efc8f5d7aeca32c627a463b8f27" ]
     }

:public_keys: An array of hex-encoded compressed public keys for blinding the given scripts.


.. _hw-action-get-blinding-nonces:

Hardware Get Blinding Nonces Action
-----------------------------------

When ``"action"`` is ``"get_blinding_nonces"``, this describes a request to
compute blinding nonces and possibly blinding public keys for the given scripts
and shared public keys.

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

     {
       "blinding_keys_required": true
       "scripts": [ "a91403f650e2434916d5b7f124de8f673442b696282887" ],
       "public_keys": [ "035f242d49b88ca17948b156263e1f0c86d2cc9e9ff316b058dbbdb351e34bc9aa" ]
     }

:blinding_keys_required: ``true`` if the blinding public keys must be returned, ``false`` otherwise.
    Blinding public keys are not requested if the master blinding key has previously been given.
:public_keys: An array of hex-encoded compressed shared public keys for computing the nonces.
:scripts: An array of hex-encoded scripts for which a blinding key should be generated and then
    the nonce computed using the public key given.

**Expected response**:

.. code-block:: json

     {
       "public_keys": [ "02045e92b8f68bd066180c05a39969f862a67f4efc8f5d7aeca32c627a463b8f27" ]
       "nonces": [ "8d940a5ec4ad122394cd2596ecfbf933a8d8fb0196015cc0a35399e3c326758c" ]
     }

:public_keys: An array of hex-encoded compressed public keys for blinding the given scripts.
    Must be present if ``"blinding_keys_required"`` was ``true`` in the request, and absent otherwise.
:nonces: An array of hex-encoded 256 bit blinding nonces.


.. _hw-action-get-blinding-factors:

Hardware Get Blinding Factors Action
------------------------------------

When ``"action"`` is ``"get_blinding_factors"``, this describes a request to
compute asset (ABF) and value (VBF) blinding factors for the given transaction
outputs.

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

    {
      "is_partial": false,
      "transaction_outputs": [],
      "used_utxos": [
        {
          "txhash": "797c40d53c4a5372303f765281bb107c40ed9618646c46851514ff0483bee894"
          "pt_idx": 2,
        },
        {
          "txhash": "9c7cffca5711968a22b8a03cc6d17224d0d85d884a4d2f638371b6fd6d59afdb"
          "pt_idx": 1,
        }
      ]
    }

:is_partial: ``true`` if transaction is incomplete, e.g. one half of a swap transaction.
:transaction_outputs: The transaction output details for the outputs to be blinded, in
    the format returned by `GA_create_transaction`. Any output with a ``"blinding_key"``
    key present requires blinding factors to be returned. When ``"is_partial"``
    is ``false``, the final vbf need not be returned. An empty string should be
    returned for blinding factors that are not required. It is not an error to
    provide blinding factors that are not required; they will be ignored.
:used_utxos: An array of prevout txids and their indices, supplied so the
    request handler can compute hashPrevouts for deterministic blinding.

**Expected response**:

.. code-block:: json

    {
      "amountblinders": [
        "ce8259bd2e7fa7d6695ade7cf8481919612df28e164a9f89cd96aace69a78bb9",
        ""
      ],
      "assetblinders": [
        "5ca806862967cde0d51950dd4e9add68e7cae8cda928750037fca1fb9cfc9e58",
        "5748810a8d2c4d87ea8c3038fb71369d8d9c85f09cfa4f6412359910fce93616"
      ]
    }

:amountblinders: An array of hex-encoded, display format value blinding factors
    (VBFs) to blind the transaction output values. Any non-required values
    should be returned as empty strings.
:assetblinders: An array of hex-encoded, display format asset blinding factors
    (ABFs) to blind the transaction output assets. Any non-required values
    should be returned as empty strings.

.. _hw-action-sign-tx:

Hardware Sign Transaction Action
--------------------------------

When ``"action"`` is ``"sign_tx"``, this describes a request to sign
one or more inputs of a transaction.

.. code-block:: json

     {
       "transaction": "0200000000010135d2bb82963e54a9060567b101760530797590d2b4a636606c4f1e6ac62bed4300000000230000000000000000000000000000000000000000000000000000000000000000000000fdffffff02f8ae00000000000017a9149aaba80ae1e733f8fb4034abcb6bd835608a5c9e87881300000000000017a9148b7f781fc9425ffaeafcd4973d3ae1dc9a09d02b87040048000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e210375d1b5be6c3f60759fd594b27a05459095ce0f371372d2f0297691c39357a60aad2102129801c6d879b59f27472ba1ac3e8b20dd1693885ad0e9640827a4bd475dfeafac73640380ca00b268c9000000"
       "signing_inputs": [],
       "transaction_outputs": [],
       "use_ae_protocol": false,
       "is_partial": false
     }

:transaction: The hex-encoded transaction to sign.
:signing_inputs: Contains details of each of the inputs in the transaction.
:transaction_outputs: The transaction output details for the outputs to be
    signed, in the format returned by `GA_create_transaction`. Any output
    without a ``"skip_signing"`` key present and set to ``true`` requires a
    signature to be returned. An empty string should be returned for
    signatures that are not required.
:use_ae_protocol: ``true`` if the hardware device advertises Anti-Exfil support and it should
    be used for signing, ``false`` otherwise.
:is_partial: ``true`` if transaction is incomplete, e.g. one half of a swap transaction.

**Expected response**:

.. code-block:: json

     {
       "signatures": [ "30440220580c7ef934d5d8f31c1c592fbf0e5bc3267b76995206f0eb61616eb2f8f6e1c4022022e3feaf88469328bdaff3990a6069bda4e320e46e0531ba1e403cd50a9252e901" ]
     }

:signatures: The ECDSA signatures corresponding to each input in the request, hex-encoded from the DER represention plus sighash byte.
