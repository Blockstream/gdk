"""Example for Bitcoin testnet"""
import greenaddress as gdk
import json

# To install GDK, download the GDK python wheel from:
# https://github.com/Blockstream/gdk/releases
# The 'cp' number refers to the python version you have.
# To install GDK, pip install the .whl file:
# pip install greenaddress-0.0.36-cp37-cp37m-linux_x86_64.whl
# GDK README and reference documentation:
# https://github.com/Blockstream/gdk
# https://gdk.readthedocs.io/en/latest/


def main():

    # Our calls to GDK are wrapped in the gdk_wallet class, which should only be
    # created using either create_new_wallet, login_with_mnemonic or
    # login_with_pin methods. The example uses Bitcoin's testnet.

    # Initialize GDK.
    gdk.init({
        'datadir': '.',     # Use the current directory for any state files
        'log_level': 'warn'
    })

    # Wallet creation and login using Mnemonic
    # ========================================

    # To create a wallet with a Managed Assets account, pass a mnemonic
    # into the following. You can generate a 24 word mnemonic yourself or
    # have GDK generate it for you by leaving mnemonic as None.
    # You can choose to create a wallet that's covered by 2FA or not.
    # 2FA can be activated or deactivated at any point in time.
    """
    wallet = gdk_wallet.create_new_wallet(create_with_2fa_enabled=False, mnemonic=None)
    print(f'\nMnemonic: {wallet.mnemonic}')
    """

    # To login to an existing wallet you can either use the mnemonic or pin.
    # Later we'll see how to use a pin, for now we will use the mnemonic.
    mnemonic = 'your twenty four word mnemonic goes here with single spaced words'
    if not gdk.validate_mnemonic(mnemonic):
        raise Exception("Invalid mnemonic.")

    # Login to a GDK wallet session using the mnemonic.
    wallet = gdk_wallet.login_with_mnemonic(mnemonic)

    # We can now perform calls against the session, such as get balance for
    # the logged in wallet.
    balance = wallet.get_balance()
    print(f'\n{json.dumps(balance, indent=4)}')

    # Using a pin to encrypt the mnemonic and login
    # =============================================

    # You can also login using a pin. Setting the pin for the wallet returns
    # encrypted data that is saved to file. When you login with the pin, the
    # server will give you the key to decrypt the mnemonic which it uses to
    # login. If the pin is entered incorrectly 3 times the server will delete
    # the key and you must use the mnemonic to login.

    """
    # Before setting the pin, login with the wallet's mnemonic.
    wallet = gdk_wallet.login_with_mnemonic(mnemonic)
    # Then set the pin for the wallet, this saves encrypted data to file.
    # Don't use the example value below, set you own.
    pin = 123456
    # You only need to set the pin data once.
    wallet.set_pin(mnemonic, pin)
    # After setting the pin you can then login using pin and do not have to
    # enter the mnemonic again. The pin is used to decrypt the local file.
    wallet.login_with_pin(pin)
    """

    # Two factor authorization
    # ========================

    # You can add Two Factor Authentication (2FA) to a wallet when you create
    # it or enable or disable 2FA at a later date.
    # Check the current 2FA status for the wallet.
    twofactor_status = wallet.get_current_2fa_status()
    print(f'\n{json.dumps(twofactor_status, indent=4)}')

    # The example below will enable 2FA on an existing wallet and uses email by
    # default, which you can amend if you want.
    """
    try:
        wallet.twofactor_auth_enabled(False)
    except RuntimeError as e:
        # Will error if 2FA is already enabled
        print(f'\nError: {e}\n')
    """

    # Getting notification data from GDK to obtain the last block height
    # ==================================================================

    # The fetch_block_height example shows how to handle notification events
    # from Green by processing the notifications queue.
    block_height = wallet.fetch_block_height()
    print(f'\nCurrent Bitcoin block height: {block_height}')

    # Getting a new address
    # =====================

    address_info = wallet.get_new_address()
    print(f'Address: {address_info["address"]}')

    # Getting transaction data from Green using GDK
    # =============================================

    txs = wallet.get_wallet_transactions()
    for tx in txs:
        print(f'TRANSACTION ID      : {tx["txhash"]}')
        print(f'CONFIRMATION STATUS : {tx["confirmation_status"]}')
        print(f'BLOCK HEIGHT        : {tx["block_height"]}')
        print(f'TYPE                : {tx["type"]}')
        print(f'INPUT COUNT         : {len(tx["inputs"])}')
        print(f'OUTPUT COUNT        : {len(tx["outputs"])}\n')

    # Sending assets
    # ==============
    amount_sat = 1001
    address = 'destination address here'
    txid = wallet.send_to_address(amount_sat, address)
    if txid:
        print(f'\nTransaction sent. Txid: {txid}')
    else:
        print(f'\nTransaction failed. See error logging.')


class gdk_wallet:

    """Class method to create and return an instance of gdk_wallet"""
    @classmethod
    def create_new_wallet(cls, create_with_2fa_enabled, mnemonic=None):
        self = cls()
        # You can pass in a mnemonic generated outside GDK if you want, or have
        # GDK generate it for you by omitting it. 2FA is enabled if chosen and
        # can be enabled/disabled at any point.
        self.mnemonic = mnemonic or gdk.generate_mnemonic()
        # Session network name options are: testnet, mainnet.
        self.session = gdk.Session({'name': 'testnet'})
        credentials = {'mnemonic': self.mnemonic}
        self.session.register_user({}, credentials).resolve()
        self.session.login_user({}, credentials).resolve()
        self.fetch_block_height()
        if create_with_2fa_enabled:
            self.twofactor_auth_enabled(True)
        return self

    """Class method to create and return an instance of gdk_wallet"""
    @classmethod
    def login_with_mnemonic(cls, mnemonic):
        self = cls()
        self.mnemonic = mnemonic
        self.session = gdk.Session({'name': 'testnet'})
        credentials = {'mnemonic': self.mnemonic, 'password': ''}
        self.session.login_user({}, credentials).resolve()
        self.fetch_subaccount()
        return self

    """Class method to create and return an instance of gdk_wallet"""
    @classmethod
    def login_with_pin(cls, pin):
        self = cls()
        pin_data = open(self.PIN_DATA_FILENAME).read()
        self.session = gdk.Session({'name': 'testnet'})
        credentials = {'pin': str(pin), 'pin_data': json.loads(pin_data)}
        self.session.login_user({}, credentials).resolve()
        self.fetch_subaccount()
        return self

    """Do not use this to instantiate the object, use create_new_wallet or login_with_*"""
    def __init__(self):
        # 2of2 is the normal account type.
        self.SUBACCOUNT_TYPE = '2of2'
        self.SUBACCOUNT_NAME = ''

        # If you use a pin to login, the encrypted data will be saved and read
        # from this file:
        self.PIN_DATA_FILENAME = 'pin_data.json'

        self.mnemonic = None
        self.session = None
        self.subaccount_pointer = None
        self.last_block_height = 0

    def set_pin(self, mnemonic, pin):
        details = {'pin': str(pin), 'plaintext': {'mnemonic': mnemonic}}
        pin_data = self.session.encrypt_with_pin(details).resolve()["pin_data"]
        open(self.PIN_DATA_FILENAME, 'w').write(json.dumps(pin_data))
        return pin_data

    def get_balance(self):
        return self.session.get_balance({'subaccount': self.subaccount_pointer, 'num_confs': 0}).resolve()

    def get_current_2fa_status(self):
        return self.session.get_twofactor_config()

    def twofactor_auth_enabled(self, enabled):
        # We will use email but others are available ('sms', 'phone', 'gauth').
        # https://gdk.readthedocs.io/en/latest/gdk-json.html#twofactor-detail
        method = 'email'
        if enabled:
            print('\nRequesting email authentication is enabled for this account')
            email = input('\nPlease enter the email address that you will use to authenticate 2FA requests: ')
            details = {'confirmed': False, 'enabled': True, 'data': email}
        else:
            print('\nRequesting email authentication is disabled for this account')
            details = {'confirmed': True, 'enabled': False}
        # The following is an example of how to handle the GDK authentication
        # state machine as it progresses to completion.
        self._gdk_resolve(gdk.change_settings_twofactor(self.session.session_obj, method, json.dumps(details)))

    def _gdk_resolve(self, auth_handler):
        # Processes and handles the state of calls that need authentication.
        # The authentication process works as a state machine and may require
        # input to progress. This example only uses email as a authentication
        # method. If you would like to user other methods such as sms, phone,
        # gauth or a hardware device see:
        # https://github.com/Blockstream/green_cli/blob/842697b1c6e382487a2e00606c17d6637fe62e7b/green_cli/green.py#L75

        while True:
            status = gdk.auth_handler_get_status(auth_handler)
            status = json.loads(status)
            state = status['status']
            if state == 'error':
                raise RuntimeError(f'\nAn error occurred authenticating the call: {status}')
            if state == 'done':
                print('\nAuthentication succeeded or not required\n')
                return status['result']
            if state == 'request_code':
                authentication_factor = 'email'
                print(f'\nCode requested via {authentication_factor}.')
                gdk.auth_handler_request_code(auth_handler, authentication_factor)
            elif state == 'resolve_code':
                resolution = input('\nPlease enter the authentication code you received: ')
                gdk.auth_handler_resolve_code(auth_handler, resolution)
            elif state == 'call':
                gdk.auth_handler_call(auth_handler)

    def fetch_subaccount(self):
        subaccounts = self.session.get_subaccounts().resolve()
        for subaccount in subaccounts['subaccounts']:
            if self.SUBACCOUNT_TYPE == subaccount['type'] and self.SUBACCOUNT_NAME == subaccount['name']:
                self.subaccount_pointer = subaccount['pointer']
                break
        if self.subaccount_pointer is None:
            raise Exception(f'Cannot find the sub account with name: "{self.SUBACCOUNT_NAME}" and type: "{self.SUBACCOUNT_TYPE}"')
        self.fetch_block_height()

    def fetch_block_height(self):
        # New blocks are added to notifications as they are found so we need to
        # find the latest or, if there hasn't been one since we last checked,
        # use the value set during login in the session's login method.
        # The following provides an example of using GDK's notification queue.
        q = self.session.notifications
        while not q.empty():
            notification = q.get(block=True, timeout=1)
            event = notification['event']
            if event == 'block':
                block_height = notification['block']['block_height']
                if block_height > self.last_block_height:
                    self.last_block_height = block_height
        return self.last_block_height

    def get_new_address(self):
        return self.session.get_receive_address({'subaccount': self.subaccount_pointer}).resolve()

    def get_wallet_transactions(self):
        # Get the current block height so we can include confirmation status in
        # the returned data.
        chain_block_height = self.fetch_block_height()
        # We'll use possible statuses of UNCONFIRMED, CONFIRMED, FINAL.
        confirmed_status = None
        depth_from_tip = 0
        all_txs = []
        index = 0
        # You can override the default number (30) of transactions returned:
        count = 10
        while(True):
            # Transactions are returned in the order of most recently seen
            # transaction first. It is possible for a transaction seen less
            # recently to be unconfimred while a more recent transaction is
            # confirmed.
            transactions = self.session.get_transactions({'subaccount': self.subaccount_pointer, 'first': index, 'count': count}).resolve()
            for transaction in transactions['transactions']:
                confirmation_status = 'UNCONFIRMED'
                block_height = transaction['block_height']
                # Unconfirmed txs will have a block_height of 0.
                if block_height > 0:
                    depth_from_tip = chain_block_height - block_height
                    # A transaction with 1 confirmation will have a depth of 0.
                    if depth_from_tip == 0:
                        confirmation_status = 'CONFIRMED'
                    if depth_from_tip > 0:
                        confirmation_status = 'FINAL'
                transaction['confirmation_status'] = confirmation_status
                all_txs.append(transaction)
            if len(transactions['transactions']) < count:
                break
            index = index + 1
        return all_txs

    def send_to_address(self, sat_amount, destination_address):
        details = {
            'subaccount': self.subaccount_pointer,
            'addressees': [{'satoshi': sat_amount, 'address': destination_address}]
        }

        try:
            details = self._gdk_resolve(gdk.create_transaction(self.session.session_obj, json.dumps(details)))
            details = self._gdk_resolve(gdk.sign_transaction(self.session.session_obj, json.dumps(details)))
            details = self._gdk_resolve(gdk.send_transaction(self.session.session_obj, json.dumps(details)))
            return details['txhash']
        except RuntimeError as e:
            print(f'\nError: {e}\n')


if __name__ == "__main__":
    main()

