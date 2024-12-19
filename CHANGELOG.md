# Changelog

## Unreleased

### Changed
- Changed bip21 schema for liquid testnet networks, from `liquidtestnet` to 
  `liquidnetwork`.

## Release 0.74.1 - 24-12-13

### Added
- Added an example Dockerfile for building AWS lambda compatible gdk deployments.

### Changed
- Singlesig: Allow some incorrect descriptors/xpubs returned by Ledger HWW.
- GA_create_transaction: Return the currently calculated transaction fee in
  the ``"fee"`` element when an insufficient fee error occurs.

### Fixed
- Singlesig: Prevent the relay fee from falling below the network minimum.
- Liquid: Update the allowed maximum of transaction inputs to 256, not 255.
- Build: Various build fixes for older compilers.


## Release 0.74.0 - 24-11-25

### Added

### Changed
- GA_psbt_sign: Now signs all required inputs and then attempts to finalize.
  If the PSBT is not fully signed, some inputs will remain unfinalized.
- GA_psbt_sign: Now adds any missing inputs scripts when signing.
- OpenSSL: build with PSK support for better static linking compatibility.
- Python: Remove vestigial Python 2 support.
- Dependencies: Update libwally.
- Misc code cleanups and documentation fixes.

### Fixed
- PSBT: When a user signature is present for an input, use it instead of
  asking the signer to re-sign.
- PSBT: Fix user-only signing of multisig inputs, by adding the user
  signature and leaving the input unfinalized for future Green signing.
- PSBT: Fix detection of expired multisig CSV inputs when finalizing v0 PSBTs.
- Python: Fix gdk session cleanup to happen when a session falls out of scope
  or is garbage collected. Previously sessions would generally be cleaned up
  only on program exit, which could lead to excessive resource use.

## Release 0.73.4 - 24-11-12

### Added
- Singlesig(Liquid): Add support for discounted Liquid fees. Discounted fees can
  now be used on the Liquid testnet networks.
- Crypto: Add GA_rsa_verify to verify an RSA challenge.
- Android: Release binaries now support devices with 16k page sizes.

### Changed
- Transactions(Liquid): Use appropriate coin selection criteria when discounted Liquid fees are in use.
- GA_create_transaction: Return the error ``"Fee change below the dust threshold"`` when
  the change output left over from paying fees is below the dust threshold. Previously
  this case returned ``"Insufficient funds for fees"`` (which is still returned if there
  is not enough value in fee UTXOs to pay the transaction fee).
- SPV: Update built-in checkpoints.
- Liquid: Update built-in assets and icons.
- Dependencies: Update tor, rust-tempfile, libwally.

### Fixed
- Transactions: Further fixes for Liquid weight calculations.
- Singlesig(MacOS): Fix occasional localhost proxy resolution issues.

## Release 0.73.3 - 24-10-25

### Added
- GA_create_redeposit_transaction: Add support for ``"expired_at"`` to create
  re-deposit transactions for UTXOs that will expire in the future.
- GA_get_balance/GA_get_unspent_outputs/GA_create_redeposit_transaction: Add
  support for ``"expires_in"`` to support filtering for UTXOs that expire in
  the given number of blocks from the current block height.

### Changed
- Transactions: Improve error messages when too many or duplicate inputs are used.

### Fixed
- Transactions: Fix weight calculation for Liquid when all inputs to a transaction
  are non-segwit (i.e. p2sh, p2pkh). This fix prevents the actual fee rate from
  becoming lower than the desired fee rate.
- Singlesig(Liquid): Prevent returned fee rates from falling below the networks
  real relay fee rate of 0.1 sat/vbyte.

## Release 0.73.2 - 24-10-08

### Added
- Python: Python wheels for Linux and Mac platforms are now published to PyPI.
  Other platforms will be supported in future releases. Please ensure you use
  the `requirements.txt` file provided with each release to ensure that the
  gdk wheel you install is the correct package.

### Changed
- Liquid: Preliminary changes to support discounted Liquid fees. This will
  be available to end users in an upcoming release.
- Dependencies: Update rust dependencies.

### Fixed
- Liquid: Fix errors when listing transactions or fetching balances from
  a subaccount which contains non un-blindable UTXOs.
- Multisig: Fix minor discrepancies between transaction weight and vsize due
  to rounding. Note this fix requires a server release which will be made shortly.
- Build (Windows): Remove duplicated "lib" directory from the library install path.

## Release 0.73.1 - 24-09-27

### Added
- GA_create_redeposit_transaction: Added a new call to create transactions
  that re-deposit wallet funds. For Liquid this call handles multiple-asset
  re-deposits and adds L-BTC fee inputs as required to cover re-deposit fees.

### Changed
- Dependencies: Update libwally.

### Fixed

## Release 0.73.0 - 24-09-18

### Added
- PSBT: Allow PSBT creation from singlesig descriptor watch-only sessions.
- GA_broadcast_transaction: Added support for setting a memo when broadcasting.
- GA_broadcast_transaction: Added support for broadcasting a PSBT/PSET directly.
  The PSBT is automatically finalized; callers no longer need to manually
  finalize and extract before sending a signed PSBT.
- GA_broadcast_transaction: Add support for simulating broadcast. This allows
  the caller to use the library to finalize/extract PSBTs for broadcast elsewhere.

### Changed
- GA_broadcast_transaction: This call has changed to run via an auth handler,
  in order to allow extending its functionality.
- Network: Update esplora connection details to the new official URLs.
- Dependencies: Update ur-c, libwally, rust-miniscript.

### Fixed
- GA_get_unspent_outputs (Multisig): Fix intermittently incorrect nlocktime/expiry details.
- GA_get_unspent_outputs (Multisig): Fix filtering for expired UTXOs to always work correctly.
- GA_get_transactions (Singlesig): Fix returned results when a tx is replaced
  and the replacement tx no longer involves the wallet.
- GA_get_transactions (Singlesig): Fix sync incorrectly returning an empty
  wallet when the first tx is received on the gap-limit address.
- Documentation: Various formatting and consistency fixes.

## Release 0.72.2 - 24-07-31

### Fixed

- Multisig: Fix further issues logging in with old watch only sessions/hardware wallets.
- Build: Re-enable full static library builds.

## Release 0.72.1 - 24-07-29

### Added

- Network: Add missing Google intermediate certificate pins, to mitigate
  potential connection failures should the certificate chain change again.

### Changed

- Documentation: Minor documentation improvements.
- Client blob: Prevent external blobserver use on mainnet while this feature
  is finalized.

### Fixed

- Multisig: Fix login for wallets with very old 2of3 accounts.
- Login: Fix login failures for wallets used with a mixture of hardware and
  software signers.
- GA_create_swap_transaction: Fix missing ``"error"`` element, improve errors.
- LiquiDEX: Fix swap creation with `p2wpkh` maker inputs.

## Release 0.72.0 - 24-07-26

### Added
- Added GA_shutdown for explicit shutdown of library resources. When callers
  opt-in to calling this function by passing ``"with_shutdown"`` as ``true``
  to GA_init, tor sessions can be created and destroyed repeatedly without error.
  Prior to this change, once a tor session was destroyed, no further tor
  connections could be made.
- Singlesig: Add experimental opt-in support for saving encrypted wallet metadata
  to an external server. When enabled, metadata such as subaccount names and
  transaction notes is synced automatically between different wallet installs
  and when restoring a wallet from scratch.
- Add GA_cache_control to enable caller control of cached data. This initial
  implementation supports returning user metadata using the BIP329 data format
  (see https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki for details).
- GA_register_user: Added support for creating watch only users by passing in
  watch only credentials (i.e. ``"username"`` and ``"password"``). This replaces
  the old call GA_set_watch_only and allows for returning more data when a
  watch only session is created.
- Fees: Callers can now override the minimum network fee rate by setting the
  ``"min_fee_rate"`` element in network parameters when calling GA_connect.
  This can be used to create transactions that pay less than the minimum
  fee (for example, for broadcasting later as part of a package).
- Singlesig: Add Signet support.

### Changed
- GA_sign_transaction: Spending expired CSV outputs now always uses the smaller
  and cheaper recovery path, which requires only a single signature and does not
  require two-factor authentication.
- GA_get_subaccount/GA_get_subaccounts: The elements``"recovery_chain_code"``
  and ``"recovery_pub_key"`` are no longer returned. The ``"recovery_xpub"``
  element for ``2of3`` subaccounts now always contains an xpub with the
  recovery pubkey and chain code.
- GA_psbt_from_json: The returned PSBT now includes keypath elements for wallet
  inputs and outputs, correct witness and redeem scripts, and appropriate input
  utxos. This allows wallet input/output identification and signing of the
  resulting PSBT/PSET by external or offline signing devices.
- C/C++: The name of the shared library has changed from from ``libgreenaddress``
  to ``libgreen_gdk``. Applications linking to the shared library should update
  their link commands accordingly.
- Java: The namespace for the interface has changed
  from ``com.blockstream.libgreenaddress`` to ``com.blockstream.green_gdk``. The
  JNI class name has been changed from ``GDKJNI`` to ``GDK``.Additionally, the
  native shared library providing the JNI implementation has been renamed
  from ``libgreenaddress`` to ``libgreen_gdk_java``. Java/Kotlin applications
  should adjust their references to the interface and their final linking
  commands accordingly.
- Python: The Python wheel and package name has been changed
  from ``greenaddress`` to ``green_gdk``. Python applications should update
  their import references and wheel installation commands accordingly.
- Build: The scripts for building library dependencies have been simplified, and
  an example Dockerfile for Android builds using Debian Bookworm is now included.
- Dependencies: Update tor to 0.4.8.9, update libwally to 1.3.0.

### Fixed
- Fixed signing of RBF transactions where one or more expired CSV inputs are
  present to use the optimized signing path, resulting in lower bumping fees.

### Removed
- GA_set_watch_only: This call has been removed. Users should use GA_register_user to
  create watch only sessions as documented above.

## Release 0.71.3 - 24-06-11

### Added

### Changed

### Fixed
- Network: Update certificates for SSL certificate pinning validation.

## Release 0.71.2 - 24-06-01

### Added

### Changed

### Fixed
- GA_get_unspent_outputs(Liquid): Fix results when (1) a filter criteria such
  as ``"expired_at"`` is given, (2) this causes all utxos for an asset id to
  be removed and (3) more than one asset id was present in the results initially.

## Release 0.71.1 - 24-05-22

### Added
- Docs: Document how to disable RBF when creating transactions.
- GA_bcur_decode: add decoding progress in multi-qr process.

### Changed
- GA_validate: do not require session to be logged in.
- GA_bcur_decode: throw an error if qr code not processed correctly.

### Fixed
- GA_get_receive_address: fix an off-by-one error for singlesig.

## Release 0.71.0 - 24-04-10

### Added

### Changed
- GA_create_transaction/GA_convert_amount: In addition to id_invalid_amount returned
  when an amount is malformed, the errors id_amount_above_maximum_allowed, id_amount_below_minimum_allowed,
  and id_amount_below_the_dust_threshold are now returned if the amount is a valid number
  but outside of the acceptable range of values for the amount in question.
- GA_get_subaccounts: Now returns additional metadata such as the subaccount
  descriptors, matching the output of `GA_get_subaccount`.

### Fixed

- Multisig: Regularly update the minimum fee rate and prevent fee estimates
  from falling below it. This prevents unexpected submission errors when the
  mempool is full and the minimum required fee increases/decreases.
- Multisig: Changes to subaccount metadata (``"name"`` and ``"is_hidden"``)
  are now reflected in logged in sessions when changed by another session.
- Build fixes and security updates

### Removed
- GA_rename_subaccount: Has been removed. Please use `GA_update_subaccount`.

## Release 0.70.3 - 24-03-06

### Added

### Changed
- GA_change_settings: Allow watch-only sessions to override the ``"unit"``,
  ``"sound"``, ``"altimeout"`` and ``"required_num_blocks"`` settings locally.

### Fixed

### Removed

## Release 0.70.2 - 24-03-04

### Added

### Changed

### Fixed

- Singlesig: watch-only: make GA_get_assets and GA_refresh_assets work
- Multisig: fix GA_login_user for sessions under 2FA reset
- Multisig: fix for subscribe calls hanging indefinitely in some cases
  under macos.

### Removed

## Release 0.70.1 - 24-02-28

### Added
- GA_login_user: add support for Liquid Electrum watch only. It is now
  possible to login with a list of CT descriptors.
- GA_sign_transaction/GA_send_transaction: Allow Electrum watch-only sessions
  to sign and send sweep transactions using the same flow as full sessions.
- GA_get_subaccount: add core_descriptors for Liquid Electrum sessions.
- Document the settings and pricing source JSON formats.

### Changed
- GA_change_settings: Allow watch-only sessions to override the pricing
  source to use. This overrides only the local settings; it does not
  affect any associated full session or any other watch-only sessions.

### Fixed
- Shared libraries for Android platforms now correctly export C API symbols
  in addition to the Java JNI symbols (this was broken in release 0.69.0).

### Removed

## Release 0.70.0 - 24-02-01

### Added
- GA_sign_transaction: Added opt-in support for spending expired CSV outputs
  using their recovery path (i.e. using only the users signature). This
  results in lower fees and also does not require 2FA for spending.
- GA_sign_transaction/GA_send_transaction: Allow signing/sending transactions
  without requiring 2FA when eligible. Expired inputs, non-wallet inputs,
  and sweep inputs for example will no longer trigger 2FA checks.
- GA_sign_transaction/GA_send_transaction: Allow re-signing/re-sending
  transactions that are already fully or partially signed. 2FA checks are
  not required for re-signing/re-sending already signed inputs.
- GA_sign_transaction/GA_send_transaction: Allow watch-only sessions to sign
  and send sweep transactions using the same flow as full sessions.
- GA_send_transaction: Allow sending transactions that are not wallet-related
  or contain inputs that are not wallet-related. This allows callers to
  always use GA_send_transaction rather than introspecting transactions to
  determine whether to use GA_broadcast_transaction.
- Added a new, experimental API GA_psbt_from_json to create a PSBT/PSET from
  the result of GA_create_transaction/GA_blind_transaction.
- GA_psbt_get_details: Various fixes to returned data to more accurately
  reflect the transaction details. In particular, the returned fee and fee
  rate are now correct.
- BC-UR: Added support for mapping CBOR to JSON for a subset of CBOR. This
  allows decoding Jade-RPC calls into JSON, for example.

### Changed

- GA_create_transaction: A new error `"Insufficient funds for fees"` is
  returned when there are sufficient inputs to pay the sent amount(s), but
  not enough to pay for fees.
- The deprecated ``"script_type"`` element has been removed from returned
  address, UTXO and transaction list JSON.
- GA_psbt_sign/GA_psbt_get_details: The required "utxos" element for signing
  can now be given in the format returned by GA_get_unspent_outputs directly,
  in addition to the existing support for passing it as a flat JSON array.
- GA_login_user: Return a "warnings" array containing any login warnings.
- Build: Updated various third-party dependencies.
- Android: Updated Android NDK to r26b LTS, and API level to 23.

### Fixed

- Fees: Improve fee estimation accuracy, particularly for singlesig. Fees
  will be lower for all transaction types in almost all cases.
- Liquid: Fix "calculated_fee_rate" for Liquid transactions.
- Multisig: Fixed the fee and fee rate becoming incorrect after signing
  only the users inputs.
- Build: Various build process improvements and fixes.

### Removed

## Release 0.69.0 - 23-11-16

### Added

- Add support for BC-UR encoding/decoding negotiated BIP85 generated entropy.
- Add support for enabling phone two-factor as a backup for sms.
- Add support for filtering unspent outputs by address_type.
- Allow cancelling an in-progress GA_connect call from another thread.
- Document two-factor and pricing limit JSON formats.
- Supply Java bindings with the debian build artfacts.

### Changed

- Transaction signing with hardware wallets is now available without setting
  the "enable_ss_liquid_hww" gdk config setting. This setting can be removed
  from the calling application when updating; it is no longer required.
- GA_validate_asset_domain_name: Enable asset domain name validation.

### Fixed

- Fix master fingerprint when decoding BC-UR crypto-account.
- Fix missing descriptor wildcards when decoding BC-UR crypto-account.
- Two-factor: Fix the ``"any_enabled"`` element in two-factor config.
- Singlesig: Return disabled config for two-factor and spending limts.
- Fix macosx_x86_64 python wheel

### Removed

## Release 0.68.4 - 23-10-26

### Fixed

- Liquid: Singlesig: Fix cache re-load.

## Release 0.68.3 - 23-10-25

### Fixed

- Singlesig: Fix incorrectly reported unconfirmed transactions.

## Release 0.68.2 - 23-10-16

### Changed

- GA_create_subaccount: Multisig: emit subaccount "synced" notification when
  a new subaccount is created.

## Release 0.68.1 - 23-10-10

### Fixed

- tor: patch error message to prevent play store flagging a security issue incorrectly.
- Multisig: psbt: detect and mark change outputs when signing PSBT/PSET.
- Fix the mingw compilation/login crash issues.

## Release 0.68.0 - 23-09-27

### Added

- Add new subaccount notifications. These signal the creation of a
  subaccount or if it completed the first sync. Please see the notification
  documentation for details.
- GA_get_unspent_outputs_for_private_key: add support for Electrum
  sessions.
- GA_get_unspent_outputs_for_private_key: rename "compressed" to
  "is_compressed".
- GA_get_unspent_outputs_for_private_key: allow to sweep p2wpkh and
  p2sh-p2wpkkh outputs.
- GA_psbt_sign: Support signing BTC PSBTv0 and PSBTv2 in addition to Liquid PSETs.
- GA_psbt_sign: Support signing PSBT/PSET with hardware wallets.
- GA_psbt_sign: Support two-factor authentication for PSBT/PSET.
- GA_psbt_sign: Support spending limits for PSBTs.
- GA_create_transaction (singlesig): Support creating sweep transactions
  and transactions with mixed sweep and wallet inputs.
- GA_get_transaction_details (singlesig): Support fetching non-wallet
  transactions to match the multisig behaviour.
- GA_sign_transaction: Allow the caller to provide their own Anti-Exfil
  host entropy.
- GA_bcur_decode: Support parsing crypto-psbt, crypto-output and crypto-account.

### Changed

- GA_psbt_get_details: The returned data now matches the existing format
  from GA_create_transaction/GA_sign_transaction.
- GA_get_credentials (Liquid): Now also returns the SLIP77 master blinding
  key when available.
- Documentation: Document the Anti-exfil protocol fields in HWW requests.

### Fixed

- GA_sign_transaction: Always return the transaction txid in the "txhash" element.

### Removed

## Release 0.67.1 - 2023-08-25

### Removed

- GA_sign_message: removed "create_recoverable_sig" flag in the
  hardware wallet interface. Please see the gdk HWW interface
  documentation for details

## Release 0.67.0 - 2023-08-08

### Added

### Changed

- GA_sign_message: rename "recoverable" to "create_recoverable_sig"
  in the hardware wallet interface.

### Fixed

### Removed

## Release 0.0.65 - 2023-07-20

### Added
- Documentation: The JSON examples for many calls are now automatically
  generated so they are always up to date. Additionally, separate examples
  are now available for multisig and singlesig, Bitcoin and Liquid.
- Documentation: The "sign_tx" HWW request is now documented, which
  completes the documentation of all requests in this interface.
- Documentation: Improve the GA_create_transaction documentation.
- GA_validate: Now allows validating addresses for other networks.
- Singlesig: GA_get_receive_address: add new flag "ignore_gap_limit" to
  return addresses beyond the GAP_LIMIT.
- Singlesig: GA_connect: add new option "gap_limit".

### Changed
- Liquid: The hardware wallet capability "supports_external_blinding" now
  defaults to false. Callers should pass this as true for hardware devices
  that can support externally blinded outputs.
- GA_get_transactions: The "transaction_size" element has been removed.
- GA_get_transactions: The "is_fee" Liquid-only element has been removed. The
  fee output in Liquid can be determined instead by "scriptpubkey" being an
  empty string.
- GA_get_receive_address/GA_get_previous_addresses: The "blinding_script"
  element has been removed, and "scriptpubkey" added. For generating SLIP177
  blinding keys, "scriptpubkey" should be used.
- GA_sign_transaction: The "sign_with" element can now be specified as "all"
  to indicate that the user wishes to sign with all keys (i.e. include the
  Green backend if the caller is a multisig wallet).
- GA_sign_transaction: The "signing_inputs" element has been renamed to
  "transaction_inputs" and corresponds exactly with "transaction_inputs"
  from GA_create_transaction".
- HWW: The "sign_tx" HWW request now passes much less data for signing; in
  particular the entire GA_create_transaction JSON is no longer included.
- GA_create_transaction/GA_create_swap_transaction: The JSON interface to
  these calls has changed:
  - Creating a transaction with explicit wallet outputs (i.e. a redeposit,
    consolidation or sweep transaction) now requires that the full metdata
    from GA_get_receive_address is passed. This ensures that wallet outputs
    will be correctly identified. If only the address is passed, the "satoshi"
    summary values returned will likely be incorrect (although the transaction
    itself is correct and can be submitted). This requirement will be removed
    in a future update.
  - The default UTXO selection for Liquid assets now uses a modified
    branch-and-bound selection strategy. Generally this means that fees
    will be lower and the chance of creating a changeless output is
    significantly higher.
  - The top-level "send_all" element has been removed. Callers can now control
    this behavior on a per-asset basis by setting "is_greedy":true in the
    "addressees" elements.
  - The top-level "addressees_read_only" and "amount_read_only" elements have
    been removed. Addressees with "is_greedy":true, and all addressees for
    RBF/CPFP transactions should be considered read only by the caller.
  - The top-level "is_redeposit" element has been removed. Callers should set
    "is_greedy":true on the wallet addressee instead.
  - The "addressees" elements passed in by the caller are no longer reordered
    when the call returns. Each addressee will now have extra data returned
    such as their scriptpubkey and any confidential address information.
  - The "change_index" element has been removed. The amount of any change for
    an asset is available in "change_amount" and the "satoshi" element of the
    "change_address" element, when the change amount is non-zero for the asset.
  - Spurious unused change addresses are no longer created if an asset does
    not require a change output.
  - GA_create/blind/sign/send_transaction: The "used_utxos" element has been
    renamed to "transaction_inputs" to match the element "transaction_outputs".
    This element now contains the complete set of inputs, notably the inputs
    inherited from the previous transaction when bumping the fee via RBF.
- GA_get_unspent_outputs_for_private_key: The interface for this function has
  changed to use an auth handler and take its arguments as JSON.
  Additionally, the returned results are now returned in the same format as
  GA_get_unspent_outputs. Please see the function documentation for details.
- Singlesig: GA_get_receive_address: now returns addressess up to the GAP_LIMIT.
  When the GAP_LIMIT is reached, the last unused address will be returned.
- Java bindings: GDK class renamed GDKJNI, file name changed accordingly,
  from GDK.java to GDKJNI.java

### Fixed
- GA_create_transaction: The top-level "satoshi" summary now correctly gives
  the net effect of the transaction on the wallet. For Liquid, the summary no
  longer includes the fee in order to match the Bitcoin behaviour. Note also
  that redeposits correctly show the net effect as zero.
- GA_create_transaction: The "satoshi" element of "change_address" change
  outputs now contains the correct amount of change for the asset.
- GA_sign_transaction: The HWWI is no longer invoked for transactions which
  have no inputs for the user to sign.
- Singlesig: GA_get_subaccount(s): set "bip44_discovered" correctly for
  subaccounts created but not discovered (including subaccount 0).

### Removed

## Release 0.0.64 - 23-06-05

### Added
- GA_get_unspent_outputs: Singlesig: Liquid: set `is_confidential`.

### Changed
- Singlesig: switch from polling to subscription for transactions data. This
  change is transparent for the caller, but it should improve performances and
  reduce the server load.

## Release 0.0.63 - 23-05-31

### Added
- Liquid: Transaction blinding is now performed using a new call
  GA_blind_transaction, which should be called after creating and before
  signing the tx.
- Liquid: Hardware wallet capability JSON now contains a new field
  "supports_external_blinding". This should be set to true when registering
  a signer that can blind/sign transactions with blinded outputs from
  wallets other than the callers wallet (for example, a 2 step swap).

### Changed
- FFI (validate_call): Input JSON parameters are now moved internally and will be
  empty when an API call returns. This only affects C and C++ callers.
- GA_validate: When validating addressees, the entered amount is also validated
  and converted into satoshis. Additionally, the scriptpubkey and blinding public
  key are extracted from the address and returned where applicable.
- GA_sign_transaction/GA_send_transaction: The "script" element of the returned
  "transaction_outputs" elements has been renamed to "scriptpubkey" to reflect
  its contents more accurately.
- Liquid/JSON: The keys `blinded` and `confidential` in returned JSON have been
  renamed for consistency and to avoid confusion. `is_blinded` now always refers
  to a transaction input or output which has been blinded, i.e. its value and
  asset have been replaced with blinded commitments. `is_blinded` at the
  top-level of transaction JSON indicates that the transaction has been fully
  blinded and is ready for signing. `is_confidential` now always refers to
  an address or addressee element having a confidential address.
- Liquid: update hard-coded asset icons.

### Fixed

### Removed

## Release 0.0.62 - 2023-04-23

### Added

### Changed

### Fixed
- Watch Only: Fix old-style watch-only sessions fetching UTXOs and balances.

### Removed
- GA_create_transaction (and sign/send): The `has_change` element has been removed.
- GA_create_transaction (and blind/sign/send): The `transaction_size` element
  has been removed. It can instead be computed from the `transaction` element.
- GA_sign_transaction (and blind/send): The `utxos` element is now removed when the
  handler returns, as it is only used for transaction creation.
- GA_create_transaction(Liquid/AMP): For transactions involving AMP subaccounts,
  the required blinding nonces for outputs are no longer available in the
  individual "transaction_outputs" elements. Instead they should be fetched from
  "blinding_nonces" in the top-level transaction details if required.

## Release 0.0.61 - 2023-04-18

### Fixed
- Allow GA_decrypt_with_pin to decrypt pin_data created with GA_set_pin.

## Release 0.0.60 - 2023-04-18

### Fixed
- Fix artifacts for OSX builds.

## Release 0.0.59 - 2023-04-12

### Added

- GA_login_user: add support for Electrum watch only. It is now possible to
  login with a list of xpubs or descriptors.
- GA_psbt_sign: add support for Liquid Electrum sessions.

### Changed
- GA_get_twofactor_config: Fiat pricing limits no longer return corresponding
  converted BTC amounts. When "is_fiat" is `true`, the caller should convert
  the amount themselves using GA_convert_amount if desired.
- FFI (All calls): Input JSON parameters are now moved internally and will be
  empty when an API call returns. This only affects C and C++ callers.
- Singlesig: GA_create_transaction now has aligned behavior with multisig:
  previous workarounds to handle the differences between the session types
  can be removed.
- Liquid: Singlesig: Allow 32 bytes master blinding keys, consistently with
  multisig.
- Build: Replace meson with cmake and make sqlite3 an external dependencies,
  check the updated README for the new build instructions.

### Fixed
- GA_sign_transaction/GA_send_transaction: Fixed exception thrown when a fiat
  spending limit is set but cannot be used (for example, because the pricing
  source is unavailable). When this occurs, 2FA will be required.
- GA_get_twofactor_config: Fixed exception thrown when a fiat pricing source
  is unavailable and a fiat spending limit is set.
- Singlesig: Fix handling of some invalid proxies.
- Fix a bug in Android build.
- Fix missing URL overrides in network parameters.

### Removed
- Removed Python wheel for Ubuntu 18.04, replaced with wheel for Ubuntu 20.04

## Release 0.0.58 - 2023-02-06

### Added
- GA_validate: Add support for validating transaction addressees.
- GA_get_unspent_outputs: add a `sort_by` element to return sorted results.
- Added new function GA_sign_message

### Changed
- GA_create_transaction: Sweeping and re-deposit transactions now require the
  caller to provide the recipient address. GA_get_receive_address can be used
  for this purpose.
- GA_create_transaction: If addressees are not provided, some fields of the
  result transaction may not be populated.
- GA_create_transaction: The `addressees_have_assets` element has been removed.
- GA_get_unspent_outputs: The default sorting for multisig non-2of2
  subaccounts has been changed from oldest-first to largest-first.
- Singlesig: GA_change_settings, GA_get_available_currencies and
  GA_convert_amount have now aligned behavior with multisig: all the prices
  and venues are matched and changing settings actually influence the fiat
  currency returned from GA_convert_amount.
- GA_encrypt_with_pin: Add `hmac` field.
- Liquid: update hard-coded asset icons.

### Fixed
- Liquid: Fix the min fee and dust threshold for multi/singlesig respectively.
- Liquid: Respect the dust limit for non-fee L-BTC outputs.
- GA_create_transaction: `id_no_amount_specified` is now returned under all
  circumstances where an amount is not given in an addressee.
- GA_create_transaction: Non-partial transactions where `utxo_strategy` is set
  to `"manual"` now return an error if an asset is provided in `used_utxos`
  that does not correspond to an addressee.
- Singlesig: GA_get_transactions: fix script serialization
- Singlesig: fixes for block and transaction notifications

### Removed

## Release 0.0.57 - 2022-11-23

### Added
- GA_get_subaccount: add user_path, core_descriptor, slip132_extended_pubkey.
- GA_get_assets: add ability to fetch information about Liquid assets by
specifying one or more of the following fields: `names`, `tickers`, `category`.

### Changed

- Singlesig: GA_convert_amount: If a fallback fiat rate is provided the
  function will return that rate immediately instead of waiting for the latest
  rate to be fetched.
- GA_refresh_assets: remove "refresh" parameter. Now every call to
GA_refresh_assets will perform a network call to update the Liquid assets. To
avoid the network call use GA_get_assets. In addition GA_refresh_assets now
does not return any value, to get assets data use GA_get_assets.
- GA_get_assets: it is now possible to fetch information's via the `assets_id`
even before logging into a session.
- Removed support for LiquiDEX v0 for GA_create_swap_transaction,
GA_complete_swap_transaction and GA_validate, which now support LiquiDEX v1
only. LiquiDEX v0 transactions can still be created and completed with
GA_create_transaction.

### Fixed

### Removed

## Release 0.0.56 - 2022-10-03

### Added

- Added new function GA_decrypt_with_pin
- Added new function GA_validate
- Added new functions GA_create_swap_transaction and
  GA_complete_swap_transaction with support for LiquiDEX v0

### Changed

- GA_get_transactions: The input/output "addressee" element is now only populated for now-disabled historical social payments.
- GA_get_transactions: The top-level "satoshi" elements are now signed; negative values represent outgoing amounts.
- Singlesig: Stop stripping the witness from transactions, transaction hex returned from `get_transaction_details` will
return also the witness. Triggers a cache rebuild that could be noticeable from apps, seeing no transactions for a moment.
- GA_convert_amount: This can now be used to convert negative values.
- GA_get_wallet_identifier (and register/login): Now returns a network-agnostic version of "wallet_hash_id" as "xpub_hash_id".
- GA_create_transaction (and sign/send): The top-level "subaccount" type is no longer required or populated, and
"subaccount_type" is also no longer populated. The subaccount(s) the tx refers to are now inferred automatically
from its input UTXOs and output addressees.
- Singlesig: Exchange rates for the BTC-USD currency pair are now fetched from a
  Blockstream service.

### Fixed

- If the network connection drops in the middle of a request the latter will be
  eventually timed out instead of waiting for the connection to be available
  again.
- Fixed an issue where the Liquid asset registry would be re-downloaded
  every time `GA_refresh_assets` was called if the local registry file got corrupted.
- Fixed an issue where `GA_get_assets` would not return any assets if a
  wallet's Liquid cache file got corrupted.
- Singlesig: GA_get_transactions: Correctly handle "mixed" transactions
- Singlesig: Fixed a race condition, now after a block notification, all
  transactions are considering the last height.

### Removed

- JSON: remove "server_signed" from create/sign/send transaction JSON.
- JSON: remove "user_signed" from create/sign/send transaction JSON.
- GA_get_transactions: Remove the top-level "addressees" element. Callers should use the "address" elements of inputs and outputs instead.

## Release 0.0.55 - 2022-07-08

### Added

- Singlesig: Implement GA_get_previous_addresses
- Singlesig: Allow fetching internal addresses in GA_get_receive_address using "is_internal"=true
- Added new function GA_get_credentials, to replace GA_get_mnemonic_passphrase.
- Added new function GA_encrypt_with_pin, to replace GA_set_pin.
- Added new function GA_get_assets to query data related to a set of Liquid
  assets.
- Added bip39 passphrase support.

### Changed

- GA_get_previous_addresses: To get the newest generated addresses, caller should not include "last_pointer" key (instead of passing "last_pointer" 0). If the returned json does not have the "last_pointer" key, it indicates that all addresses have been fetched (previously it had "last_pointer" 1)
- GA_get_previous_addresses: Removed "subaccount" from returned keys.
- Singlesig: Add some missing fields to GA_get_receive_address returned json.
- Singlesig: Remove is_segwit from GA_get_unspent_outputs returned json
- GA_register_user: Change interface to match GA_login_user.
- Update endpoints for new bitcoin multisig backend.

### Fixed

- GA_get_unspent_outputs: fix bug returning utxos from replaced transactions.

### Removed

- Removed GA_get_mnemonic_passphrase, callers should use GA_get_credentials.
- Removed GA_set_pin, callers should use GA_encrypt_with_pin.
- Removed LTO and bitcode building flags.


## Release 0.0.54 - 2022-05-13

### Added

- Watch only: Support Liquid multisig watch-only logins
- Watch only: Allow deleting watch only accounts
- Watch only: Enable local caching for significantly faster performance
- Watch only: Support trust-on-first-use validation for xpubs and address generation
- Watch only: Initial support for transaction proposals (watch only tx creation)

### Changed

- Watch only: Re-enable viewing user metadata (account names, tx notes, hidden accounts) via client blob
- Watch only: Require usernames and passwords to each be at least 8 characters long
- Multisig: Remap non auth_handler call errors to support i18n

### Fixed

- Liquid: Fix unblinding when initially populating the local cache


## Release 0.0.53 - 2022-05-10

### Added

- Add build support for Apple M1

### Changed

- Changed transaction type from "unblindable" to "not unblindable" to reflect its actual meaning
- Move to Android ndk r23b LTS release
- Update openssl to 1.1.1n
- Update libwally to latest
- Rust is now mandatory for building
- Registry: Switched to unified implementation with full asset data. Only Liquid-BTC icon is hard-coded, only asset metadata having icons are hard-coded (38 assets)

### Fixed

- Singlesig: In GA_get_transactions "inputs" and "outputs" elements, set "address" and "address_type" correctly; do not set Liquid fields if not Liquid or not unblindable
- Singlesig: align transaction and block notifications with multisig
- Singlesig: temporarily lock spent utxos in the interval between send/broadcast and the next sync
- Singlesig: fix an error causing "restore" to fail


## Release 0.0.52 - 2022-04-22

### Added

- Support for sending to Liquid taproot addresses
- Documentation for GA_get_unspent_outputs result, including differences between singlesig and multisig.

### Changed

- Multisig: In GA_create_transaction "transaction_outputs" rename "public_key" to "blinding_key" when appropriate.
- Singlesig: In GA_create_transaction "transaction_outputs" make "is_change" equal to "is_internal", not "is_relevant"

### Fixed

- Singlesig: set GA_get_unspent_outputs result correctly and consistently with multisig.


## Release 0.0.51 - 2022-03-30

- SPV: Enable SPV for multisig BTC wallets
- Singlesig: support for HWW signers (Bitcoin only)
- Singlesig: support for GA_http_request
- Singlesig: implement GA_remove_account, see docs for details.


## Release 0.0.50 - 2022-03-08

- Documentation: Improve documentation for connection and network related functions, add documentation of each gdk notification type.
- Networking: Remove GA_disconnect.
- Networking: Multiple small ABI changes, please see the API documentation for details.
- Multisig/networking: Fix a number of bugs that could cause crashes and connection problems including failure to connect/reconnect.
- Singlesig/networking: Update to match the multisig interface, including notifications
- Misc: Various build and bug fixes


## Release 0.0.49 - 2022-01-20

- Singlesig: Improved account discovery
- Multisig: Don't send connection notifications for user-initiated session disconnect/destroy
- Multisig: Remove old support for passing addressee asset_id as asset_tag
- Multisig: Standardize address subtype as always 0 instead of null
- Multisig: Remove range and surjection proofs from returned UTXO data
- Multisig: Fix spending from very old version 0 addresses
- Liquid: Return blinded addresses in tx list results
- Liquid/AMP: Allow alternate blinding keys for AMP assets where required
- HWW interface: Change get_blinding_nonces to also return blinding keys
- Networking: fix some networking related crashes on android and iOS


## Release 0.0.48 - 2021-12-14

- Liquid: New experimental API GA_psbt_sign for partial signing
- Liquid: Update testnet asset registry URL
- Liquid: Disable multi-asset sends on all networks
- Liquid: Fix AMP blinding key upload on new subaccount creation
- Single sig: Randomize secp context before use
- All: Update localization strings
- Misc bug fixes


## Release 0.0.47.post1 - 2021-11-16

- Update Liquid Testnet URLs
- Fix create_subaccount bug


## Release 0.0.47 - 2021-11-04

- Multisig: add support for persistent transactions cache
- Multisig: return unblinded addresses in get_receive_address  and get_previous_addresses
- Singlesig: fix some json inconsistencies in transactions
- Add support for pay to taproot to both multisig and singlesig wallets (unavailable until activation on the main chain)


## Release 0.0.46.post1 - 2021-10-26

- Fix: increase proxy and socks setup timeouts
- Fix: tor wake-up


## Release 0.0.46 - 2021-10-19

- Single sig: Use built-in asset data if the asset registry is unreachable
- Single sig: Align create_transaction and get_transactions data more closely to multisig
- Single sig: Add support for manual coin selection
- Single sig: Improve TLS handling to allow connecting to more electrum servers
- Improve expired certificate handling
- Allow fetching wallet id without login and return it from register. Note the identifier returned by single sig sessions has changed to match multisig behavior
- Fix builds under Python 3.9


## Release 0.0.45.post1 - 2021-09-29

Patched version from v0.0.45 with:

- Remove expired LE certificates


## Release 0.0.45 - 2021-09-22

- ABI: Explicit utxos on create_transaction
- Network: Improved re-login mechanism
- General: Improved call handler resolution to reduce many requests
- General: Improved caching for HWW
- Singlesig: Improved create transaction and support bip21 prefix


## Release 0.0.44 - 2021-09-01

- Single sig: Enable Bitcoin mainnet support
- Liquid: Add support for host unblinding
- Liquid: Provide fallback built-in asset and icon data
- Network: Stability and re-connection improvements
- ABI: Add fiat rate change notifications, remove fee notifications
- ABI: Add GA_get_fee_estimates to fetch fees
- ABI: Add new filter options (dust, expiry, confidential) for balances/UTXOs
- ABI: Remove GA_get_expired_deposits
- ABI: Simplify and document the hardware wallet/auth handler interfaces
- ABI: There are now fewer state changes for some auth handlers
- General: Improved caching to speed up many operations
- General: Various bug fixes and speedups


## Release 0.0.43.post1 - 2021-08-12

Patched version from v0.0.43 with:
- rust: update aes related dependencies
- rust: update MSRV to 1.49.0
- ci: update docker images


## Release 0.0.43 - 2021-06-29

- Single sig: Fix an issue with address generation for p2wpkh/p2pkh that could cause stuck coins
- Single sig: Many important fixes and improvements to upcoming single sig support, including Fee bumping and tx eviction support, improved Liquid fee estimation, faster operation, more consistency with multisig and test improvements
- Single sig: Multiple ABI changes including the location of cached data and settings which will not be carried forward. Please note the single sig code will continue to change rapidly until mainnet release including potentially further ABI changes
- Network: New Liquid Testnet network is now supported
- Network: Add a new certificate chain to replace the current chain which will expire soon
- Network: Upgrade asset registry and backend onion connections to tor v3
- Build: Multiple build fixes and dependency updates
- Build: Add support for building on Apple Big Sur
- ABI: removed GA_check_proxy_connectivity
- ABI: Liquid now uses the networks policy asset id instead of "btc" in returned JSON
- ABI: The sequence of state changes for some auth handlers has changed
- ABI: GA_login_user should be used for all logins. The existing login calls will be removed in the next release
- ABI: Network parameter names and some keys have changed names for consistency.
- General: Various bug fixes and internal consistency improvements


## Release 0.0.42 post1 - 2021-06-01

Patched version from v0.0.42 with:
- rust: fix db dir name
- update meson to 0.58.0
- update boost and autobahn-cpp
- fix builds on darwin system


## Release 0.0.42 - 2021-05-16

- Rust: Add support for multiple accounts and multiple types (p2sh-p2wpkh, p2wpkh, p2pkh)
- Rust: Perform BIP44 account discovery at first login
- Rust: Spend unconfidential utxos by default
- Rust: Add support for proxy network connections
- Rust: Standardize wallet identification and caching behavior
- Rename some electrum network names (breaking change)
- Add GA_login_user to replace other login calls, which are now deprecated.
- Update root certificates for SSL certificate pinning validation
- Networking fixes
- Build and CI fixes


## Release 0.0.41 - 2021-03-29

- Add support for the hardware anti-exfil protocol
- Add support for undoing a two factor reset request
- Add support for multi-server SPV cross-validation under electrum
- Add support for hiding accounts and renaming the main account
- Add support for fetching historical addresses
- Add Python examples for Bitcoin and Liquid AMP assets
- Bug fixes, thread safety improvements and updates


## Release 0.0.40 - 2021-02-12

- Liquid: Fix un-blindable transaction handling
- Show subaccount names and transaction memos for non-blob-upgraded wallets
- Remove the limit on transaction list fetching for large numbers of transactions
- Threading safety improvements, bug fixes


## Release 0.0.39 - 2021-02-02

- add client blob support to store encrypted data on the server, use it to store tx memos and subaccount names
- 2of3: sign recovery key at subaccount creation, later verify it
- handle missing fiat rate
- validate replace transactions
- reformat user agent string


## Release 0.0.38 - 2021-01-14

fiat rate fixes


## Release 0.0.37 - 2021-01-02

updates let's encrypt CA certs


## Release 0.0.36 - 2020-12-03

- fix python builds on OSX builder
- update rust unit test
- correctly initialize logging level
- improve SPV validation
- fix sign_message for hw ack_system_message
- use correct serialization for blinders (breaking change 468197f029484d2060c07c6ab780adde31a2279a)
- fix JNI/clang 11 build
- enable bitcode on libwally build
- bump cache version



## Release 0.0.35 - 2020-10-27

- add support for Electrum sessions (mainnet, testnet, regtest, liquid, liquid regtest)
- fixes for csv type scripts
- add new `set_unspent_outputs_status` call to change a UTXOs status
- update wally to latest


## Release 0.0.34 - 2020-08-26

- update dependencies: sqlite and nlohmann json
- update key "satoshi" in transaction json on asset_tag
- watch-only: handle missing nlocktime_blocks
- remove unnecessary call to get_blinded_scripts
- upload_confidential_addresses: Fix unlocked access, avoid pass-by-value


## Release 0.0.33 - 2020-07-08

- Update login_with_pin() to return a resolver
- On Login, upload "required_ca" confidential addresses
- Allow caller to override GA_http_request timeout
- During liquid create transaction: clear error utxos, add change addresses to tx earlier, get blinding nonces
- Improvements to handling of http requests, allow caller to pass custom root certificates to GA_http_request
- Makes httpget more generally useful with graceful close of tls connection


## Release 0.0.32 - 2020-06-12

- Replace GA_http_get with GA_http_request, which can perform POST as well as
  GET. Urls are specified as a set from which the gdk will choose the most
  appropriate, e.g. if the session is running tor and an onion url is present it
  will get preference over a non-onion url.
- Add GA_generate_mnemonic_12
- Enable ccache by default if ccache is found
- Build improvements
- Bug fixing


## Release 0.0.31 - 2020-05-14

- Allow caller to pass xpub to create a 2of3 account
- Use legacy derivation for 2of3 recovery xpubs
- Disable multi-asset send in liquid mainnet
- Enable setting nlocktime via GA_change_settings
- Refactor appearance settings mapping
- Update openssl to 1.1.1g



## Release 0.0.30 - 2020-04-13

- update travis windows build and osx meson version
- fix sending to liquid blech32 addresses
- update docker images and rust version
- update libwally, tor, openssl, gls library


## Release 0.0.29 - 2020-03-30

Increase rangeproof ct bits from 36 to 52


## Release 0.0.28 - 2020-02-27

- represent missing fiat rate as null in amount json
- gracefully handle invalid value for fiat rate
- asset Id validation on bip21 uri


## Release 0.0.27 - 2020-02-03

- add bip21 uri for liquid
- update swift bindings
- bug fixes
