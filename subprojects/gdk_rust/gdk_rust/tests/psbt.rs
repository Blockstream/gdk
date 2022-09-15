use std::collections::HashMap;
use std::iter::FromIterator;
use std::str::FromStr;

use bitcoin::hashes::hex::FromHex;
use elements::AssetId;

use gdk_common::model::*;
use gdk_electrum::pset::{self, FromTxParam};
use gdk_test::TestSession;

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
