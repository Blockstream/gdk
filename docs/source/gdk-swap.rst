.. _swap-overview:

GDK Swap Interface
==================

This section details the Liquid swap protocols supported by GDK and
the functions available to run those protocols.

Currently there is only one swap protocol supported, :ref:`liquidex-overview`.

---------------------------------------------------------------------

.. _liquidex-overview:

LiquiDEX
========

.. warning::
    Note that in the current version (1) of the protocol if the swap
    involves inputs or outputs from a ``"2of2_no_recovery"`` account
    is not safe to send the proposal directly to untrusted parties
    (either directly to the Taker, or an untrusted third party).
    Unless you know what you are doing you should not use this
    version of the protocol.

`LiquiDEX`_ is a 2-step swap protocol, to perform a swap of this kind
use ``"swap_type"`` ``"liquidex"``.

.. _LiquiDEX: https://medium.com/blockstream/liquidex-2-step-atomic-swaps-on-the-liquid-network-8a7ff6fb7aa5

The protocol is started by the Maker, who creates a proposal to swap
a certain utxo for a certain amount of another asset.
This action is performed using `GA_create_swap_transaction`.

The proposal is then shared with the Taker, who first validates it
and verifies that it is a swap that it is willing to accept.
This action is performed using `GA_validate`.

If the Taker wants to accept the proposal, they will add more inputs
and outputs to fund and balance the transaction.
This action is performed using `GA_complete_swap_transaction`.

Note that, unlike `GA_create_swap_transaction`,
`GA_complete_swap_transaction` requires the caller to sign the
transaction with `GA_sign_transaction`.
Moreover for ``"2of2_no_recovery"`` (AMP) subaccounts, the caller
should get a delayed signature for the Maker input.

---------------------------------------------------------------------

.. _liquidex-v1-create-details:

LiquiDEX Create Swap transaction JSON
-------------------------------------

``"input_type"`` and ``"output_type"`` must be ``"liquidex_v1"``.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v1",
    "output_type": "liquidex_v1",
    "liquidex_v1": {
      "receive": [{
        "asset_id": "ASSET_ID",
        "satoshi": 1
      }],
      "send": [{}],
    },
  }

:receive/asset_id: The hex-encoded asset id to receive, in display format.
                   This list must have 1 element.
:receive/satoshi: The satoshi amount of the specified asset to receive.
                  This list must have 1 element.
:send: The Maker's UTXO to swap, as returned from `GA_get_unspent_outputs`.
       This list must have 1 element.
       The swapped asset will be received to the same subaccount as the
       utxo provided.

.. _liquidex-v1-create-result:

LiquiDEX Create Swap Transaction Result JSON
--------------------------------------------

Returned when ``"output_type"`` is ``"liquidex_v1"``.

.. code-block:: json

  {
    "liquidex_v1": {
      "proposal": {},
    }
  }

:proposal: The LiquiDEX version 1 proposal to be shared.

.. _liquidex-v1-complete-details:

LiquiDEX Complete Swap transaction JSON
---------------------------------------

``"input_type"`` must be ``"liquidex_v1"``,
and ``"output_type"`` must be ``"transaction"``.

.. code-block:: json

  {
    "swap_type": "liquidex",
    "input_type": "liquidex_v1",
    "output_type": "transaction",
    "utxos": {},
    "liquidex_v1": {
      "proposals": [{}],
    },
  }

:proposals: The LiquiDEX version 1 proposals to take.
