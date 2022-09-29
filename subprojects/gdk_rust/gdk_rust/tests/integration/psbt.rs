use std::collections::HashMap;
use std::iter::FromIterator;
use std::str::FromStr;

use bitcoin::hashes::hex::FromHex;
use elements::{AssetId, Script};
use serde_json::{json, Map, Value};

use gdk_common::model::*;
use gdk_common::wally;
use gdk_electrum::pset::{self, FromTxParam};
use gdk_test::{utils, TestSession};

const SUBACCOUNT: u32 = 0;

#[test]
fn psbt_simple_liquid() {
    let mut session = TestSession::new(true, |_| {});

    let address = session.get_receive_address(SUBACCOUNT).address;

    let txid = session.node_sendtoaddress(&address, 10_000, None);
    session.wait_tx(vec![SUBACCOUNT], &txid, None, None);

    let (txhex, spent) = {
        let sat = 5000;

        let mut opts = session.create_opt(
            &session.node_getnewaddress(None),
            sat,
            session.asset_id(),
            None,
            SUBACCOUNT,
            session.utxos(SUBACCOUNT),
        );

        let transaction = session.session.create_transaction(&mut opts).unwrap();
        (transaction.hex, sat + transaction.fee)
    };

    let utxos = session.utxos(SUBACCOUNT).0.into_iter().next().unwrap().1;

    let psbt = {
        let params = FromTxParam {
            transaction: txhex,
        };
        let psbt = pset::from_tx(&params).unwrap().psbt_hex;
        let bytes: Vec<u8> = FromHex::from_hex(&psbt).unwrap();
        base64::encode(bytes)
    };

    let params = PsbtGetDetailsParams {
        psbt,
        utxos: utxos.clone(),
    };

    let res = session.session.psbt_get_details(params).unwrap();

    let asset = utxos[0].asset_id.as_ref().and_then(|id| AssetId::from_str(id).ok()).unwrap();

    let balance = HashMap::from_iter([(asset, -(spent as i64))]);

    assert_eq!(net_balance(&res, SUBACCOUNT), balance);
    assert_eq!(net_balance(&res, 1), HashMap::new());
}

fn net_balance(details: &PsbtGetDetailsResult, subaccount: u32) -> HashMap<AssetId, i64> {
    let mut balance = HashMap::<AssetId, i64>::new();

    for input in details.inputs.iter().filter(|input| input.subaccount == subaccount) {
        balance
            .entry(AssetId::from_str(input.asset_id.as_ref().unwrap()).unwrap())
            .and_modify(|v| *v -= input.satoshi as i64)
            .or_insert(-(input.satoshi as i64));
    }

    for output in details.outputs.iter().filter(|input| input.subaccount == subaccount) {
        balance
            .entry(output.asset_id)
            .and_modify(|v| *v += output.satoshi as i64)
            .or_insert(output.satoshi as i64);
    }

    balance
}

#[test]
fn psbt_with_node_liquid() {
    let mut session = TestSession::new(true, |_| {});

    let user_address = setup_user_address(&session, SUBACCOUNT);

    let (user_utxo, node_utxo) = setup_utxos(&session, user_address);

    let psbt_blinded = setup_pset(&session, &user_utxo, node_utxo);

    let params = PsbtGetDetailsParams {
        psbt: psbt_blinded,
        utxos: vec![user_utxo.clone()],
    };

    let res = session.session.psbt_get_details(params).unwrap();

    let policy_asset =
        session.network.policy_asset.map(|id| AssetId::from_str(&id)).unwrap().unwrap();

    let balance = HashMap::from_iter([(policy_asset, -(user_utxo.satoshi as i64))]);

    assert_eq!(net_balance(&res, SUBACCOUNT), balance);
    assert_eq!(net_balance(&res, 1), HashMap::new());
}

fn setup_user_address(session: &TestSession, account: u32) -> AddressPointer {
    let user_address = session.get_receive_address(account);

    let blinding_prv = {
        let master_blinding = session.test_signer().master_blinding();

        let script_pubkey =
            user_address.script_pubkey.as_ref().and_then(|s| Script::from_str(s).ok()).unwrap();

        wally::asset_blinding_key_to_ec_private_key(&master_blinding, &script_pubkey)
    };

    session.node_importaddress(&user_address.address);
    session.node_importblindingkey(&user_address.address, &blinding_prv);

    user_address
}

fn setup_utxos(
    session: &TestSession,
    user_address: AddressPointer,
) -> (UnspentOutput, Map<String, Value>) {
    let node_address = session.node_getnewaddress(None);

    let node_address_unconfidential = utils::to_unconfidential(&node_address);

    let satoshi = 10_000.0;
    let btc = satoshi / 1e8;

    let policy_asset = &**session.network.policy_asset.as_ref().unwrap();
    let amounts = [(&*user_address.address, btc), (&node_address, btc)];
    let assets = [(&*user_address.address, policy_asset), (&node_address, policy_asset)];

    let txid = session.node_sendmany(&amounts, &assets);
    session.wait_tx(vec![SUBACCOUNT], &txid, None, None);
    session.node_generate(1);

    let user_utxo = {
        let opts = GetUnspentOpt::default();
        let mut utxos =
            session.session.get_unspent_outputs(&opts).unwrap().0.remove(policy_asset).unwrap();
        utxos.retain(|utxo| utxo.txhash == txid);
        assert_eq!(1, utxos.len());
        utxos.into_iter().next().unwrap()
    };

    let node_utxo = {
        let mut utxos = session.node_listunspent();
        utxos.retain(|map| {
            (map["txid"].as_str().unwrap() == txid)
                && (map["address"].as_str().unwrap() == node_address_unconfidential)
        });
        assert_eq!(1, utxos.len());
        let mut utxo = utxos.into_iter().next().unwrap();
        let txhash = utxo["txid"].clone();
        let pt_idx = utxo["vout"].clone();
        let satoshi = utxo["amount"].as_f64().map(|amt| (amt * 10e8) as u64).unwrap().into();
        utxo.insert("txhash".into(), txhash);
        utxo.insert("pt_idx".into(), pt_idx);
        utxo.insert("satoshi".into(), satoshi);
        utxo
    };

    (user_utxo, node_utxo)
}

fn setup_pset(
    session: &TestSession,
    user_utxo: &UnspentOutput,
    node_utxo: Map<String, Value>,
) -> String {
    let tot_amount = user_utxo.satoshi + node_utxo["satoshi"].as_u64().unwrap();

    let address = session.node_getnewaddress(None);

    let user_input = json!({
        "txid": user_utxo.txhash,
        "vout": user_utxo.pt_idx,
        "sequence": 0xfffffffd as u32,
    });

    let node_input = json!({
        "txid": node_utxo["txhash"],
        "vout": node_utxo["pt_idx"],
        "sequence": 0xfffffffd as u32,
    });

    let inputs = vec![user_input, node_input];

    let outputs = {
        let fee = 5000.0;
        let policy_asset = &**session.network.policy_asset.as_ref().unwrap();
        json!([
              {
                  address: ((tot_amount as f64 - fee)/1e8).to_string(),
                  "asset": policy_asset,
                  "blinder_index": 0,
              },
              {
                  "fee": fee / 1e8,
                  "asset": policy_asset,
              }
        ])
    };

    let psbt = session.node_createpsbt(inputs.into(), outputs);
    let mut psbt = session.node_walletprocesspsbt(&psbt, false);

    match psbt.remove("psbt").unwrap() {
        serde_json::Value::String(psbt) => return psbt,
        _ => unreachable!(),
    }
}
