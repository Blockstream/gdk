# Generate documentation JSON examples from a development localtest setup.
import green_gdk as gdk
import json, shutil, subprocess, sys

# Random mnemonic for keeping the generated addresses the same
MNEMONIC = 'symbol rocket quality brush wagon feed scan afford dose girl replace faith'

UR_DOCS = [
    'ur:crypto-output/taadmutaadeyoyaxhdclaoswaalbmwfpwekijndyfefzjtmdrtketphhktmngrlkwsfnospypsasrhhhjonnvwtsqzwljy',
    'ur:bytes/hdchjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmhjnfhrp',
    'ur:crypto-psbt/hdchjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmhjnfhrp',
    'ur:custom/hdchjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmhjnfhrp',
    'ur:crypto-account/oeadcyemrewytyaolftaadeetaadmutaaddloxaxhdclaxwmfmdeiamecsdsemgtvsjzcncygrkowtrontzschgezokstswkkscfmklrtauteyaahdcxiehfonurdppfyntapejpproypegrdawkgmaewejlsfdtsrfybdehcaflmtrlbdhpamtaaddyoeadlncsdwykaeykaeykaocyemrewytyaycynlytsnyltaadeetaadmhtaadmwtaaddloxaxhdclaostvelfemdyynwydwyaievosrgmambklovabdgypdglldvespsthysadamhpmjeinaahdcxntdllnaaeykoytdacygegwhgjsiyonpywmcmrpwphsvodsrerozsbyaxluzcoxdpamtaaddyoeadlncsehykaeykaeykaocyemrewytyaycypdbskeuyjeaxtsec',
]


def run(command):
    PIPE=subprocess.PIPE
    result = subprocess.run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    return result.stdout


def write_json(j, session_type, name, title_extra=''):
    # Format a JSON dict, wrap it in clickable expanding links and
    # save it to a file for the docs to include.
    json_dumps = lambda d: json.dumps(d, indent=2, sort_keys=True, default=lambda t: f'{t}')
    j = '\n'.join([f'  {l}' for l in json_dumps(j).split('\n')])

    suffix = f'_{session_type}' if session_type else ''
    title = 'Example'
    if session_type:
        title_extra = f' {title_extra}' if title_extra else ''
        title = f'{session_type.replace("_", " ").title()} example{title_extra}'
    with open(f'./docs/source/examples/{name}{suffix}.json', 'w') as f:
        f.write('.. raw:: html\n')
        f.write('\n')
        f.write('  <details>\n')
        f.write(f'  <summary><a>{title}</a></summary>\n')
        f.write('\n')
        f.write('.. code-block:: json\n')
        f.write('\n')
        f.write(f'{j}')
        f.write('\n')
        f.write('\n')
        f.write('.. raw:: html\n')
        f.write('\n')
        f.write('  </details>\n')
        f.write('\n')

def do_2fa(user, method, confirmed, enabled):
    data = '+123456789'
    if method == 'gauth':
        data = user.get_twofactor_config()['gauth']['data']
    if method == 'email':
        data = 'sample_email@my_domain.com'

    cfg = {'confirmed': confirmed, 'enabled': enabled, 'data': data}
    return user.change_settings_twofactor(method, cfg).resolve()

def generate_twofactor_examples(user, session_type):
    # 2fa config (empty)
    config = user.get_twofactor_config()
    write_json(config, session_type, 'get_twofactor_config_none', '(no two-factor methods enabled)')
    # Spending limits
    details = {'is_fiat': True, 'fiat': '1.50', 'fiat_currency': 'USD'}
    set_limits = user.twofactor_change_limits(details).resolve()
    write_json(set_limits, session_type, 'twofactor_change_limits_fiat', '(returned fiat limit)')
    details = {'is_fiat': False, 'satoshi': 50000}
    set_limits = user.twofactor_change_limits(details).resolve()
    write_json(set_limits, session_type, 'twofactor_change_limits_btc', '(returned BTC limit)')
    # unset spending limits
    user.twofactor_change_limits({'is_fiat': False, 'satoshi': 0}).resolve()

    # 2fa config (all enabled)
    for method in config['all_methods']:
        do_2fa(user, method, True, True)
    config = user.get_twofactor_config()
    # Remove telegram until it is available globally
    # FIXME: telegram is not returned in the initial call to get_twofactor_config above
    config['all_methods'] = config['all_methods'][:-1]
    del config['telegram']
    write_json(config, session_type, 'get_twofactor_config_all', '(all two-factor methods enabled)')

def generate_examples(network, session_type, mnemonic):
    user = gdk.Session({'name': network})
    user.register_user({}, {'mnemonic': mnemonic}).resolve()
    login_data = user.login_user({}, {'mnemonic': mnemonic}).resolve()
    # get_receive_address
    addr = user.get_receive_address({'subaccount': 0}).resolve()
    run(f'cli sendtoaddress {addr["address"]} 0.0001234') # Do early to give time to receive
    write_json(addr, session_type, 'get_receive_address')

    # get_settings
    settings = user.get_settings()
    write_json(settings, session_type, 'get_settings')
    # get_previous_addresses
    user.get_receive_address({'subaccount': 0}).resolve()
    prev_addrs = user.get_previous_addresses({'subaccount': 0}).resolve()
    write_json(prev_addrs, session_type, 'get_previous_addresses')
    # get_subaccount
    user.update_subaccount({'subaccount': 0, 'name': 'Example subaccount name'})
    j = user.get_subaccount(0).resolve()
    write_json(j, session_type, 'get_subaccount')
    # get_transactions
    while True:
        # Wait for the tx (lazy, busy-wait impl)
        txs = user.get_transactions({'subaccount': 0, 'first': 0, 'count': 1}).resolve()
        if len(txs['transactions']):
            break
    incoming_txhash = txs['transactions'][0]['txhash']
    user.set_transaction_memo(incoming_txhash, 'Example incoming transaction', 0)
    # TODO: Re-deposit and outgoing txs
    write_json(txs, session_type, 'get_transactions')
    input_ = txs['transactions'][0]['inputs'][0]
    write_json(input_, session_type, 'get_transactions_input')
    outputs = txs['transactions'][0]['outputs']
    output = [o for o in outputs if o['is_relevant']][0]
    write_json(output, session_type, 'get_transactions_output')
    # get_transaction_details
    tx_details = user.get_transaction_details(incoming_txhash)
    if 'liquid' in session_type:
        tx_details['transaction'] = 'Transaction Hex, abbreviated here for length'
    write_json(tx_details, session_type, 'get_transaction_details')
    # get_unspent_outputs
    utxos = user.get_unspent_outputs({'subaccount': 0, 'num_confs': 0}).resolve()
    write_json(utxos, session_type, 'get_unspent_outputs')

    if session_type != 'multisig':
        if session_type == 'singlesig':
            config = user.get_twofactor_config()
            write_json(config, session_type, 'get_twofactor_config',
                       '(two-factor and limits not available)')
        return
    # The following JSON is either multisig specific or the same for all
    # networks. Generate it only for multisig-BTC to avoid repeated work.
    write_json(login_data, '', 'login_user')
    networks = gdk.get_networks()
    write_json(networks, '', 'get_networks')
    network = gdk.get_networks()['mainnet']
    write_json(network, '', 'network')
    # bcur_decode
    for ur in UR_DOCS:
        j = user.bcur_decode({'part': ur}).resolve()
        ur_type = ur.split('/')[0].split(':')[1].replace('-', '_')
        write_json(j, '', f'bcur_decode_{ur_type}')
    # 2fa
    generate_twofactor_examples(user, session_type)

if __name__ == '__main__':
    # Remove any existing session cache from previous runs
    shutil.rmtree('/tmp/gdkdocs', ignore_errors=True)
    gdk.init({'datadir': '/tmp/gdkdocs', 'log_level': 'none'})
    networks = [
        ['localtest', 'multisig'],
        ['electrum-localtest', 'singlesig']
    ]
    if len(sys.argv) > 1 and sys.argv[1] == '--liquid':
        networks = [
            ['localtest-liquid', 'multisig_liquid'],
            ['electrum-localtest-liquid', 'singlesig_liquid']
        ]
    for network, name in networks:
        generate_examples(network, name, MNEMONIC)
    shutil.rmtree('/tmp/gdkdocs', ignore_errors=True)
