use crate::error::Error;
use bitcoin::hashes::hex::{FromHex, ToHex};
use elements::encode::{deserialize, serialize};
use elements::pset;
use elements::pset::PartiallySignedTransaction;
use elements::script::Builder;
use elements::Transaction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ExtractTxParam {
    psbt_hex: String,
}
#[derive(Debug, Serialize)]
pub struct ExtractTxResult {
    transaction: String,
}
/// Return the raw tx hex extracted from the given PSET encoded in hex
pub fn extract_tx(param: &ExtractTxParam) -> Result<ExtractTxResult, Error> {
    let mut pset = pset_from_hex(&param.psbt_hex)?;
    let tx = extract_tx_inner(&mut pset)?;
    Ok(ExtractTxResult {
        transaction: serialize(&tx).to_hex(),
    })
}

#[derive(Debug, Deserialize)]
pub struct MergeTxParam {
    psbt_hex: String,
    transaction: String,
}
#[derive(Debug, Serialize)]
pub struct MergeTxResult {
    psbt_hex: String,
}
/// Return the hex PSET merging the witnesses in `tx_hex` inside the given `pset_hex`
pub fn merge_tx(param: &MergeTxParam) -> Result<MergeTxResult, Error> {
    let mut pset = pset_from_hex(&param.psbt_hex)?;
    let pset_tx = extract_tx_inner(&mut pset)?;

    let tx = tx_from_hex(&param.transaction)?;

    compare_except_script_sig_sequence(&pset_tx, &tx)?;

    for (pset_input, tx_input) in pset.inputs_mut().iter_mut().zip(tx.input.iter()) {
        pset_input.final_script_witness = Some(tx_input.witness.script_witness.clone());
        pset_input.final_script_sig = Some(tx_input.script_sig.clone());
    }
    Ok(MergeTxResult {
        psbt_hex: serialize(&pset).to_hex(),
    })
}

#[derive(Debug, Deserialize)]
pub struct FromTxParam {
    transaction: String,
}
#[derive(Debug, Serialize)]
pub struct FromTxResult {
    psbt_hex: String,
}
/// Return a pset built from the given raw tx hex
pub fn from_tx(param: &FromTxParam) -> Result<FromTxResult, Error> {
    let tx = tx_from_hex(&param.transaction)?;
    let mut pset = PartiallySignedTransaction::from_tx(tx);
    for output in pset.outputs_mut().iter_mut() {
        // Elements Core requires the blinder index to be set for each blinded output
        if output.value_rangeproof.is_some() && output.blinder_index.is_none() {
            output.blinder_index = Some(0);
        }
    }

    Ok(FromTxResult {
        psbt_hex: serialize(&pset).to_hex(),
    })
}

fn pset_from_hex(pset_hex: &str) -> Result<pset::PartiallySignedTransaction, Error> {
    let pset_bytes = Vec::<u8>::from_hex(pset_hex)?;
    Ok(deserialize(&pset_bytes)?)
}

fn tx_from_hex(transaction: &str) -> Result<Transaction, Error> {
    let transaction_bytes = Vec::<u8>::from_hex(transaction)?;
    Ok(deserialize(&transaction_bytes)?)
}

fn extract_tx_inner(pset: &mut pset::PartiallySignedTransaction) -> Result<Transaction, Error> {
    for input in pset.inputs_mut().iter_mut() {
        // we want the extracted tx to have the script_sig
        // this breaks p2sh pre-segwit but we don't support those
        if let Some(redeem_script) = input.redeem_script.as_ref() {
            input.final_script_sig =
                Some(Builder::new().push_slice(redeem_script.as_bytes()).into_script());
        }
    }
    let tx = pset.extract_tx()?;
    Ok(tx)
}

fn compare_except_script_sig_sequence(tx1: &Transaction, tx2: &Transaction) -> Result<(), Error> {
    let mut tx1 = tx1.clone();
    let mut tx2 = tx2.clone();
    for inp in tx1.input.iter_mut() {
        inp.sequence = 0;
        inp.script_sig = elements::Script::default();
    }
    for inp in tx2.input.iter_mut() {
        inp.sequence = 0;
        inp.script_sig = elements::Script::default();
    }

    let (tx1_id, tx2_id) = (tx1.txid(), tx2.txid());
    if tx1_id != tx2_id {
        Err(Error::PsetAndTxMismatch(tx1_id, tx2_id))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::pset::*;

    const EMPTY_PSET: &str = "70736574ff01020402000000010401000105010001fb040200000000";
    const EMPTY_TX: &str = "0200000000000000000000";

    const ONE_INPUT_PSET: &str = "70736574ff01020402000000010401010105010001fb040200000000010e200000000000000000000000000000000000000000000000000000000000000000010f040000000000";
    const ONE_INPUT_TX: &str = "02000000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000";

    #[test]
    fn test_extract_tx() {
        //INVALID
        assert_eq!(
            "odd hex string length 1",
            extract_tx(&ExtractTxParam {
                psbt_hex: "X".to_string()
            })
            .unwrap_err()
            .to_string()
        );
        assert_eq!(
            "invalid hex character 88",
            extract_tx(&ExtractTxParam {
                psbt_hex: "XC".to_string()
            })
            .unwrap_err()
            .to_string()
        );
        assert_eq!(
            "a Bitcoin type encoding error: I/O error: failed to fill whole buffer",
            extract_tx(&ExtractTxParam {
                psbt_hex: "aa".to_string()
            })
            .unwrap_err()
            .to_string()
        );

        //VALID
        assert_eq!(
            EMPTY_TX,
            extract_tx(&ExtractTxParam {
                psbt_hex: EMPTY_PSET.to_string()
            })
            .unwrap()
            .transaction
        );
    }

    #[test]
    fn test_merge_tx() {
        let mut pset = pset_from_hex(EMPTY_PSET).unwrap();
        pset.add_input(elements::pset::Input::default());
        assert_eq!(pset.inputs()[0].final_script_witness, None);
        let psbt_hex = serialize(&pset).to_hex();
        assert_eq!(psbt_hex, ONE_INPUT_PSET);
        let tx_hex = extract_tx(&ExtractTxParam {
            psbt_hex: psbt_hex.clone(),
        })
        .unwrap()
        .transaction;
        assert_eq!(tx_hex, ONE_INPUT_TX);

        let mut signed_tx: Transaction =
            deserialize(&Vec::<u8>::from_hex(&tx_hex).unwrap()).unwrap();
        let witness = vec![vec![42u8]];
        signed_tx.input[0].witness.script_witness = witness.clone();
        let pset_merged = merge_tx(&MergeTxParam {
            psbt_hex: psbt_hex.clone(),
            transaction: serialize(&signed_tx).to_hex(),
        })
        .unwrap()
        .psbt_hex;
        let pset_merged = pset_from_hex(&pset_merged).unwrap();
        assert_eq!(pset_merged.inputs()[0].final_script_witness, Some(witness));

        let mut incorrect_tx = signed_tx.clone();
        incorrect_tx.input.push(elements::TxIn {
            previous_output: Default::default(),
            is_pegin: false,
            has_issuance: false,
            script_sig: Default::default(),
            sequence: 0,
            asset_issuance: Default::default(),
            witness: Default::default(),
        });
        assert!(merge_tx(&MergeTxParam {
            psbt_hex,
            transaction: serialize(&incorrect_tx).to_hex()
        })
        .unwrap_err()
        .to_string()
        .starts_with("PSET and Tx mismatch"));
    }

    #[test]
    fn test_rtt() {
        for tx in &[EMPTY_TX, ONE_INPUT_TX] {
            let pset = from_tx(&FromTxParam {
                transaction: tx.to_string(),
            })
            .unwrap();
            let extract = extract_tx(&ExtractTxParam {
                psbt_hex: pset.psbt_hex,
            })
            .unwrap();
            assert_eq!(tx.to_string(), extract.transaction);
        }
    }

    #[test]
    fn test_compare_except_script_sig_sequence() {
        let tx = tx_from_hex(ONE_INPUT_TX).unwrap();
        assert!(compare_except_script_sig_sequence(&tx, &tx).is_ok());

        let mut tx2 = tx.clone();
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_ok());
        tx2.input[0].script_sig = elements::Script::from_hex("00").unwrap();
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_ok());
        tx2.input[0].previous_output.vout = 99;
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_err());

        let mut tx2 = tx.clone();
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_ok());
        tx2.input[0].sequence = 1000;
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_ok());
        tx2.input[0].previous_output.vout = 99;
        assert!(compare_except_script_sig_sequence(&tx, &tx2).is_err());
    }
}
