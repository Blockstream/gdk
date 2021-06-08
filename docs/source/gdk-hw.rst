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
