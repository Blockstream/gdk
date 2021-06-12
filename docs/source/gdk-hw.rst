.. _hw-resolve-overview:

GDK Hardware Wallet Interface
=============================

This section details the format of data requests from hardware wallet
interation during resolution of GA_auth_handler processing when
`GA_auth_handler_get_status` returns the status ``"resolve_code"`` with
a ``"required_data"`` element present.

.. _hw-required-data:

Required Data JSON
------------------

Returned as an element ``"required_data"`` of :ref:`twofactor-status` when
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


.. _hw-action-sign-message:

Hardware Sign Message Action
----------------------------

When ``"action"`` is ``"sign_message"``, this describes a request to sign
a message using the given path.

.. code-block:: json

     {
       "message": "A text message to sign",
       "path": [ 1195487518 ],
       "use_ae_protocol": false
     }

:message: The message to be utf-8 encoded and signed.
:path: The path from the wallet's master key to the key that the message should be signed with.
:use_ae_protocol: ``true`` if the hardware device advertises Anti-Exfil support and it should
    be used for signing, ``false`` otherwise.

**Expected response**:

.. code-block:: json

     {
       "signature": "304402207c673ef4255873cf095016c98c4982cea9a5133060b66a380f1bf3880e54f6c8022056fd731cbd44cd96366212439717a888470ed481628cba81195c557d5c4fc39c"
     }

:signature: The hex-encoded ECDSA signature in DER encoding corresponding to the given message.


.. _hw-action-get-receive-address:

Hardware Get Receive Address Action
-----------------------------------

When ``"action"`` is ``"get_receive_address"``, this describes a request to
compute a blinding key for a new wallet address.

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

     {
       "address": {
         "address": "XBiBx41oSSXxuQkmJKbiMKk2tXzTjDLG86",
         "address_type": "p2wsh",
         "blinding_script_hash": "a91403f650e2434916d5b7f124de8f673442b696282887",
         "branch": 1,
         "pointer": 1,
         "script": "5221030361d2b6ea7d5e5237f0647c49a1c519b42173959631d939a28bc64263446e102102d4a348b9f48833dcefffa80305846686d101d02c45a4547b3a5ff6fabb8e2f1f52ae",
         "script_type": 14,
         "subaccount": 1,
         "subtype": null
       },
     }

:address: The address details for which a blinding key should be generated.

**Expected response**:

.. code-block:: json

     {
       "blinding_key": "02045e92b8f68bd066180c05a39969f862a67f4efc8f5d7aeca32c627a463b8f27"
     }

:blinding_key: The hex-encoded compressed public key for blinding the given address.


.. _hw-action-create-transaction:

Hardware Create Transaction Action
----------------------------------

When ``"action"`` is ``"create_transaction"``, this describes a request to
compute blinding keys for the transactions change addresses.

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

     {
       "transaction": {
         "change_address": {
           "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d": {
             "address": "XBiBx41oSSXxuQkmJKbiMKk2tXzTjDLG86",
             "address_type": "p2wsh",
             "blinding_script_hash": "a91403f650e2434916d5b7f124de8f673442b696282887",
             "branch": 1,
             "pointer": 1,
             "script": "5221030361d2b6ea7d5e5237f0647c49a1c519b42173959631d939a28bc64263446e102102d4a348b9f48833dcefffa80305846686d101d02c45a4547b3a5ff6fabb8e2f1f52ae",
             "script_type": 14,
             "subaccount": 1,
             "subtype": null
           }
         }
       }
     }

:change_address: Asset ID keyed address details for which a blinding key should
    be generated. Note that there may be more than one address. Addresses with
    the key ``"is_blinded"`` present and set to ``true`` can be skipped.

**Expected response**:

.. code-block:: json

     {
       "blinding_keys": {
           "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d": "02045e92b8f68bd066180c05a39969f862a67f4efc8f5d7aeca32c627a463b8f27"
       }
     }

:blinding_keys: Asset ID keyed hex-encoded compressed public keys for blinding each address.

Hardware Get Blinding Nonces Action
-----------------------------------

This action describes a request to compute blinding nonces for the given script hashes.
The ``"action"`` element will be one of the following:

- ``"get_balance"``,
- ``"get_subaccount"``,
- ``"get_subaccounts"``,
- ``"get_transactions"``,
- ``"get_unspent_outputs"``,
- ``"get_expired_deposits"``,

.. note:: This action is only returned when using the Liquid network.

.. code-block:: json

     {
       "blinded_scripts": [
         {
           "pubkey": "02045e92b8f68bd066180c05a39969f862a67f4efc8f5d7aeca32c627a463b8f27",
           "script": "a91403f650e2434916d5b7f124de8f673442b696282887"
         }
       ]
     }

:blinded_scripts: An array of public key and script hashes to return the nonces for.
:pubkey: hex-encoded compressed public key.
:script: hex-encoded script hash to compute the nonce for.

**Expected response**:

.. code-block:: json

     {
       "nonces": [
           "8d940a5ec4ad122394cd2596ecfbf933a8d8fb0196015cc0a35399e3c326758c"
       ]
     }

:nonces: An array of hex-encoded 256 bit blinding nonces.
