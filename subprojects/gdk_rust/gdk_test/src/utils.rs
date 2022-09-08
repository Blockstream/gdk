use std::str::FromStr;
use std::thread;
use std::time::Duration;

use serde_json::Value;

use gdk_common::model::*;
use gdk_common::scripts::ScriptType;
use gdk_common::{NetworkId, NetworkParameters, State};
use gdk_electrum::headers;
use gdk_electrum::{ElectrumSession, Notification, TransactionNotification};

use crate::TestSigner;

// Simulate login through the auth handler
pub fn auth_handler_login(session: &mut ElectrumSession, credentials: &Credentials) {
    let signer =
        TestSigner::new(credentials, session.network.bip32_network(), session.network.liquid);

    // Connect must be done before login
    session.connect(&serde_json::to_value(session.network.clone()).unwrap()).unwrap();

    // Load the rust persisted cache
    let opt = LoadStoreOpt {
        master_xpub: signer.master_xpub(),
    };
    session.load_store(&opt).unwrap();

    // Set the master blinding key if missing in the cache
    if session.network.liquid {
        if session.get_master_blinding_key().unwrap().master_blinding_key.is_none() {
            // Master blinding key is missing
            let master_blinding_key = signer.master_blinding();
            let opt = SetMasterBlindingKeyOpt {
                master_blinding_key,
            };
            session.set_master_blinding_key(&opt).unwrap();
        }
    }

    // Set the account xpubs if missing in the cache
    for account_num in session.get_subaccount_nums().unwrap() {
        // Currently, the resolver always asks for the subaccout xpub
        let opt = GetAccountPathOpt {
            subaccount: account_num,
        };
        let path = session.get_subaccount_root_path(opt).unwrap();
        let xpub = signer.account_xpub(&path.path.into());

        let opt = CreateAccountOpt {
            subaccount: account_num,
            name: "".to_string(),
            xpub: Some(xpub),
            discovered: false,
        };
        session.create_subaccount(opt).unwrap();
    }

    // We got everything from the signer
    session.start_threads().unwrap();
}

pub fn convertutxos(utxos: &GetUnspentOutputs) -> CreateTxUtxos {
    serde_json::to_value(utxos).and_then(serde_json::from_value).unwrap()
}

// Perform BIP44 account discovery as it is performed in the resolver
pub fn discover_subaccounts(session: &mut ElectrumSession, credentials: &Credentials) {
    let signer =
        TestSigner::new(credentials, session.network.bip32_network(), session.network.liquid);

    for script_type in ScriptType::types() {
        loop {
            let opt = GetNextAccountOpt {
                script_type: *script_type,
            };
            let account_num = session.get_next_subaccount(opt).unwrap();
            let opt = GetAccountPathOpt {
                subaccount: account_num,
            };
            let path = session.get_subaccount_root_path(opt).unwrap().path;
            let xpub = signer.account_xpub(&path.into());
            let opt = DiscoverAccountOpt {
                script_type: *script_type,
                xpub,
            };
            if session.discover_subaccount(opt).unwrap() {
                let opt = CreateAccountOpt {
                    subaccount: account_num,
                    xpub: Some(xpub),
                    discovered: true,
                    ..Default::default()
                };
                session.create_subaccount(opt).unwrap();
            } else {
                // Empty subaccount
                break;
            }
        }
    }
}

/// Json of network notification
pub fn ntf_network(current: State, desired: State) -> Value {
    serde_json::to_value(&Notification::new_network(current, desired)).unwrap()
}

/// Json of transaction notification
pub fn ntf_transaction(ntf: &TransactionNotification) -> Value {
    serde_json::to_value(&Notification::new_transaction(ntf)).unwrap()
}

pub fn to_not_unblindable(elements_address: &str) -> String {
    let pk = elements::secp256k1_zkp::PublicKey::from_slice(&[2; 33]).unwrap();
    let mut address = elements::Address::from_str(elements_address).unwrap();
    address.blinding_pubkey = Some(pk);
    address.to_string()
}

pub fn to_unconfidential(elements_address: &str) -> String {
    let mut address_unconf = elements::Address::from_str(elements_address).unwrap();
    address_unconf.blinding_pubkey = None;
    address_unconf.to_string()
}

pub fn spv_verify_tx(
    network: NetworkParameters,
    tip: u32,
    txid: &str,
    height: u32,
    headers_to_download: Option<usize>,
) {
    let id = network.id();
    let common = SPVCommonParams {
        network,
        timeout: None,
        encryption_key: Some("testing".to_string()),
    };
    let param = SPVVerifyTxParams {
        txid: txid.to_string(),
        height,
        params: common.clone(),
    };
    let param_download = SPVDownloadHeadersParams {
        params: common.clone(),
        headers_to_download,
    };

    let mut handle = None;
    if let NetworkId::Bitcoin(_) = id {
        // Liquid doesn't need to download headers chain
        handle = Some(thread::spawn(move || {
            let mut synced = 0;

            while synced < tip {
                if let Ok(result) = headers::download_headers(&param_download) {
                    synced = result.height;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }));
    }

    loop {
        match headers::spv_verify_tx(&param) {
            Ok(SPVVerifyTxResult::InProgress) => {
                thread::sleep(Duration::from_millis(100));
            }
            Ok(SPVVerifyTxResult::Verified) => break,
            Ok(e) => assert!(false, "status {:?}", e),
            Err(e) => assert!(false, "error {:?}", e),
        }
    }

    // second should verify immediately, (and also hit cache)
    assert!(matches!(headers::spv_verify_tx(&param), Ok(SPVVerifyTxResult::Verified)));

    if let Some(handle) = handle {
        handle.join().unwrap();
    }
}

/// wait for the n txs to show up in the given account
pub fn wait_account_n_txs(session: &ElectrumSession, subaccount: u32, n: usize) {
    let mut opt = GetTransactionsOpt::default();
    opt.subaccount = subaccount;
    opt.count = n;
    for _ in 0..10 {
        if session.get_transactions(&opt).unwrap().0.len() >= n {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
    panic!("timeout waiting for {} txs to show up in account {}", n, subaccount);
}
