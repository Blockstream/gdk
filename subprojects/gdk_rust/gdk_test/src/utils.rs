use std::thread;
use std::time::Duration;

use serde_json::Value;

use gdk_common::model::*;
use gdk_common::{NetworkId, NetworkParameters, State};
use gdk_electrum::headers;
use gdk_electrum::{Notification, TransactionNotification};

/// Json of network notification
pub fn ntf_network(current: State, desired: State) -> Value {
    serde_json::to_value(&Notification::new_network(current, desired)).unwrap()
}

/// Json of transaction notification
pub fn ntf_transaction(ntf: &TransactionNotification) -> Value {
    serde_json::to_value(&Notification::new_transaction(ntf)).unwrap()
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
