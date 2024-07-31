import atexit
import json
from ._green_gdk import *
from ._green_gdk import _python_set_callback_handler, _python_destroy_session
try:
    import queue
except:
    import Queue as queue

try:
    basestring
except NameError:
    basestring = str

# Unused: Provided for back compatibility only
GA_MEMO_USER = 0
GA_MEMO_BIP70 = 1

class Call(object):
    """Handler class to process a call potentally requiring twofactor.

    Initialize the class with the auth_handler object returned from
    functions that may require authentication. Then call resolve()
    on the object, optionally passing in callables to select and enter
    twofactor auth methods and codes.

    """

    def __init__(self, call_obj):
        self.call_obj = call_obj

    def status(self):
        return json.loads(auth_handler_get_status(self.call_obj))

    def _select_method(self, methods):
        # Default implementation just uses the first method provided
        return methods[0]

    def _resolve_code(self, method):
        if isinstance(method, dict):
            # Caller must provide their own handler for data requests
            raise RuntimeError(f'Unhandled data request {method}')
        # 2FA: Default implementation just uses localtest dummy 2fa code
        return '555555'

    def request_code(self, method):
        auth_handler_request_code(self.call_obj, method)

    def resolve(self, select_method_fn=None, resolve_code_fn=None):
        select_method_fn = select_method_fn or self._select_method
        resolve_code_fn = resolve_code_fn or self._resolve_code
        while True:
            status = self.status()
            state = status['status']
            if state == 'error':
                self.call_obj = None
                raise RuntimeError(status['error'])
            if state == 'done':
                self.call_obj = None
                return status['result']
            if state == 'request_code':
                method = select_method_fn(status['methods'])
                auth_handler_request_code(self.call_obj, method)
            elif state == 'resolve_code':
                if 'required_data' in status:
                    # Hardware device authorization requested
                    code = resolve_code_fn(status['required_data'])
                elif status['method'] == 'data':
                    # Caller data requested
                    code = resolve_code_fn(status)
                else:
                    # Twofactor authorization requested
                    code = resolve_code_fn(status['method'])
                auth_handler_resolve_code(self.call_obj, code)
            elif state == 'call':
                auth_handler_call(self.call_obj)


class Session(object):
    """A session representing either a Green multisig or a singlesig wallet.

    """

    to_destroy = []

    @staticmethod
    @atexit.register
    def destroy_all():
        while len(Session.to_destroy):
            session = Session.to_destroy.pop()
            session._destroy()

    def __init__(self, net_params):
        self.notifications = queue.Queue()
        self.session_obj = create_session()
        Session.to_destroy.append(self)
        _python_set_callback_handler(self.session_obj, self._callback_handler)
        return self.connect(net_params)

    def _destroy(self):
        if getattr(self, 'session_obj', None):
            obj = self.session_obj
            self.session_obj = None
            _python_set_callback_handler(obj, None)
            _python_destroy_session(obj)

    def destroy(self):
        if self in Session.to_destroy:
            Session.to_destroy.remove(self)
            self._destroy()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.destroy()

    def __del__(self):
        self.destroy()

    def _callback_handler(self, obj, event):
        assert obj is self.session_obj
        try:
            self.callback_handler(json.loads(event))
        except Exception as e:
            print('exception {}\n'.format(e))

    def callback_handler(self, event):
        """Callback handler.

         Override or monkey patch to handle notifications, or read the
         self.notification queue to receive events.

         """
        timeout_seconds = 60
        self.notifications.put(event, timeout_seconds)

    @staticmethod
    def _to_json(obj):
        return obj if isinstance(obj, basestring) else json.dumps(obj)

    def connect(self, net_params):
        return connect(self.session_obj, self._to_json(net_params))

    def disconnect(self):
        raise RuntimeError('use reconnect_hint() to disconnect a session')

    def reconnect_hint(self, hint):
        return reconnect_hint(self.session_obj, self._to_json(hint))

    def get_proxy_settings(self):
        return json.loads(get_proxy_settings(self.session_obj))

    @staticmethod
    def get_wallet_identifier(net_params, params):
        return json.loads(get_wallet_identifier(Session._to_json(net_params), Session._to_json(params)))

    def register_user(self, hw_device, details):
        return Call(register_user(self.session_obj, self._to_json(hw_device), self._to_json(details)))

    def login_user(self, hw_device, details):
        return Call(login_user(self.session_obj, self._to_json(hw_device), self._to_json(details)))

    def get_watch_only_username(self):
        return get_watch_only_username(self.session_obj)

    def remove_account(self):
        return Call(remove_account(self.session_obj))

    def encrypt_with_pin(self, details):
        return Call(encrypt_with_pin(self.session_obj, self._to_json(details)))

    def decrypt_with_pin(self, details):
        return Call(decrypt_with_pin(self.session_obj, self._to_json(details)))

    def disable_all_pin_logins(self):
        return disable_all_pin_logins(self.session_obj)

    def create_subaccount(self, details):
        return Call(create_subaccount(self.session_obj, self._to_json(details)))

    def update_subaccount(self, details):
        return Call(update_subaccount(self.session_obj, self._to_json(details)))

    def get_subaccounts(self, details=None):
        details = details or {}
        return Call(get_subaccounts(self.session_obj, self._to_json(details)))

    def get_subaccount(self, subaccount):
        return Call(get_subaccount(self.session_obj, subaccount))

    def get_transactions(self, details={'subaccount': 0, 'first': 0, 'count': 30}):
        return Call(get_transactions(self.session_obj, self._to_json(details)))

    def get_receive_address(self, details=None):
        details = details or {}
        return Call(get_receive_address(self.session_obj, self._to_json(details)))

    def get_previous_addresses(self, details={'subaccount': 0, 'last_pointer': 0}):
        return Call(get_previous_addresses(self.session_obj, self._to_json(details)))

    def get_unspent_outputs(self, details={'subaccount': 0, 'num_confs': 1}):
        return Call(get_unspent_outputs(self.session_obj, self._to_json(details)))

    def get_unspent_outputs_for_private_key(self, details):
        return Call(get_unspent_outputs_for_private_key(self.session_obj, self._to_json(details)))

    def set_unspent_outputs_status(self, details):
        return Call(set_unspent_outputs_status(self.session_obj, self._to_json(details)))

    def get_transaction_details(self, txhash_hex):
        return json.loads(get_transaction_details(self.session_obj, txhash_hex))

    def convert_amount(self, details):
        return json.loads(convert_amount(self.session_obj, self._to_json(details)))

    def get_balance(self, details={'subaccount': 0, 'num_confs': 0}):
        return Call(get_balance(self.session_obj, self._to_json(details)))

    def get_available_currencies(self):
        return json.loads(get_available_currencies(self.session_obj))

    def create_transaction(self, transaction_details):
        return Call(create_transaction(self.session_obj, self._to_json(transaction_details)))

    def blind_transaction(self, transaction_details):
        return Call(blind_transaction(self.session_obj, self._to_json(transaction_details)))

    def sign_transaction(self, transaction_details):
        return Call(sign_transaction(self.session_obj, self._to_json(transaction_details)))

    def create_swap_transaction(self, swap_details):
        return Call(create_swap_transaction(self.session_obj, self._to_json(swap_details)))

    def complete_swap_transaction(self, swap_details):
        return Call(complete_swap_transaction(self.session_obj, self._to_json(swap_details)))

    def create_redeposit_transaction(self, redeposit_details):
        return Call(create_redeposit_transaction(self.session_obj, self._to_json(redeposit_details)))

    def psbt_sign(self, details):
        return Call(psbt_sign(self.session_obj, self._to_json(details)))

    def psbt_from_json(self, details):
        return Call(psbt_from_json(self.session_obj, self._to_json(details)))

    def psbt_get_details(self, details):
        return Call(psbt_get_details(self.session_obj, self._to_json(details)))

    def send_transaction(self, details):
        return Call(send_transaction(self.session_obj, self._to_json(details)))

    def broadcast_transaction(self, details):
        return Call(broadcast_transaction(self.session_obj, self._to_json(details)))

    def sign_message(self, details):
        return Call(sign_message(self.session_obj, self._to_json(details)))

    def send_nlocktimes(self):
        return send_nlocktimes(self.session_obj)

    def set_csvtime(self, locktime_details):
        return Call(set_csvtime(self.session_obj, self._to_json(locktime_details)))

    def set_nlocktime(self, locktime_details):
        return Call(set_nlocktime(self.session_obj, self._to_json(locktime_details)))

    def set_transaction_memo(self, txhash_hex, memo, memo_type=0):
        return set_transaction_memo(self.session_obj, txhash_hex, memo, memo_type)

    def get_fee_estimates(self):
        return json.loads(get_fee_estimates(self.session_obj))

    def get_credentials(self, details):
        return Call(get_credentials(self.session_obj, self._to_json(details)))

    def get_system_message(self):
        return get_system_message(self.session_obj)

    def ack_system_message(self, message_text):
        return Call(ack_system_message(self.session_obj, message_text))

    def cache_control(self, details):
        return Call(cache_control(self.session_obj, self._to_json(details)))

    def get_twofactor_config(self):
        return json.loads(get_twofactor_config(self.session_obj))

    def change_settings_twofactor(self, method, details):
        return Call(change_settings_twofactor(self.session_obj, method, self._to_json(details)))

    def get_settings(self):
        return json.loads(get_settings(self.session_obj))

    def change_settings(self, settings):
        return Call(change_settings(self.session_obj, self._to_json(settings)))

    def twofactor_reset(self, email, is_dispute):
        return Call(twofactor_reset(self.session_obj, email, is_dispute))

    def twofactor_undo_reset(self, email):
        return Call(twofactor_undo_reset(self.session_obj, email))

    def twofactor_cancel_reset(self):
        return Call(twofactor_cancel_reset(self.session_obj))

    def twofactor_change_limits(self, details):
        return Call(twofactor_change_limits(self.session_obj, self._to_json(details)))

    def bcur_encode(self, details):
        return Call(bcur_encode(self.session_obj, self._to_json(details)))

    def bcur_decode(self, details):
        return Call(bcur_decode(self.session_obj, self._to_json(details)))

    def http_request(self, params):
        return json.loads(http_request(self.session_obj, self._to_json(params)))

    def refresh_assets(self, params):
        return refresh_assets(self.session_obj, self._to_json(params))

    def get_assets(self, params):
        return json.loads(get_assets(self.session_obj, self._to_json(params)))

    def validate_asset_domain_name(self, params):
        return json.loads(validate_asset_domain_name(self.session_obj, self._to_json(params)))

    def validate(self, details):
        return Call(validate(self.session_obj, self._to_json(details)))

_old_get_networks = get_networks
def get_networks():
    return json.loads(_old_get_networks())

_old_register_network = register_network
def register_network(name, details):
    return _old_register_network(name, Session._to_json(details))

_old_get_random_bytes = get_random_bytes
def get_random_bytes(n):
    out = bytearray(n)
    _old_get_random_bytes(n, out)
    return bytes(out)

_old_init = init
def init(config):
    import os, os.path
    if not config.get('datadir', None):
        try:
            datadir = os.path.join(os.path.expanduser('~'), '.blockstream', 'gdk')
            os.makedirs(os.path.join(datadir, 'assets'), exist_ok = True);
            config['datadir'] = datadir
        except:
          pass
    return _old_init(json.dumps(config))
