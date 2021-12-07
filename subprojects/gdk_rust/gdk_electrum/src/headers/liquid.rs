use elements::{self, BlockExtData};

use crate::error::*;
use crate::headers::compute_merkle_root;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Signature};
use bitcoin::PublicKey;
use electrum_client::GetMerkleRes;
use elements::opcodes::{self, Class};
use elements::script::{self, Instruction};
use elements::{BlockHash, BlockHeader, Script, TxMerkleNode, Txid};
use gdk_common::ElementsNetwork;
use log::info;

/// liquid v1 block header verifier, not suitable for dynafed
/// checks the challenge is exactly equal to the one present in block 1
/// checks the solution script against the challenge, verifying signatures
pub struct Verifier {
    challenge: Script,
    genesis: BlockHash,
    is_regtest: bool,
}

const CHALLENGE: &'static str = "5b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375fae";
const LIQUID_GENESIS_HASH: &'static str =
    "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003";
const LIQUID_TESTNET_GENESIS_HASH: &'static str =
    "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
const ELEMENTS_REGTEST_GENESIS_HASH: &'static str =
    "209577bda6bf4b5804bd46f8621580dd6d4e8bfa2d190e1c50e932492baca07d";

impl Verifier {
    pub fn new(network: ElementsNetwork) -> Self {
        let (is_regtest, genesis_hash) = match network {
            ElementsNetwork::Liquid => (false, LIQUID_GENESIS_HASH),
            ElementsNetwork::LiquidTestnet => (false, LIQUID_TESTNET_GENESIS_HASH),
            ElementsNetwork::ElementsRegtest => (true, ELEMENTS_REGTEST_GENESIS_HASH),
        };
        Verifier {
            challenge: Script::from(Vec::<u8>::from_hex(CHALLENGE).unwrap()),
            genesis: BlockHash::from_hex(genesis_hash).unwrap(),
            is_regtest,
        }
    }

    /// verify the given txid and the proof against a given block header (verify header validity also)
    pub fn verify_tx_proof(
        &self,
        txid: &Txid,
        merkle: GetMerkleRes,
        header: &BlockHeader,
    ) -> Result<(), Error> {
        self.verify_header(header)?;
        let root: TxMerkleNode = compute_merkle_root(txid, merkle)?;
        if header.merkle_root == root {
            info!("proof for txid {}, block height {}, merkle root matches", txid, header.height);
            Ok(())
        } else {
            Err(Error::InvalidHeaders)
        }
    }

    /// verify the given liquid header
    fn verify_header(&self, header: &BlockHeader) -> Result<(), Error> {
        let mut stack = vec![];
        let hash = header.block_hash();
        if hash == self.genesis || self.is_regtest {
            // TODO add regtest verification
            return Ok(());
        }

        match &header.ext {
            BlockExtData::Proof {
                challenge,
                solution,
            } => {
                if challenge != &self.challenge {
                    return Err(Error::InvalidHeaders);
                }
                for instr in solution.instructions_minimal().chain(challenge.instructions_minimal())
                {
                    self.process_instr(&instr, &hash, &mut stack)?;
                }
                if stack.is_empty() {
                    Ok(())
                } else {
                    Err(Error::InvalidHeaders)
                }
            }
            _ => Err(Error::InvalidHeaders),
        }
    }

    fn process_instr(
        &self,
        instr: &Result<Instruction, script::Error>,
        hash: &BlockHash,
        stack: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        match instr {
            Ok(Instruction::PushBytes(data)) => Ok(stack.push(data.to_vec())),
            Ok(Instruction::Op(op)) => self.process_op(op, hash, stack),
            Err(_) => Err(Error::InvalidHeaders),
        }
    }

    fn process_op(
        &self,
        op: &opcodes::All,
        hash: &BlockHash,
        stack: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        if let Class::PushNum(val) = op.classify() {
            return Ok(stack.push(vec![val as u8]));
        } else if *op == opcodes::all::OP_CHECKMULTISIG {
            let total_pubkeys = stack.pop().ok_or_else(|| Error::InvalidHeaders)?[0] as usize;
            let mut pubkeys = vec![];
            let start =
                stack.len().checked_sub(total_pubkeys).ok_or_else(|| Error::InvalidHeaders)?;
            for el in stack.drain(start..) {
                pubkeys.push(PublicKey::from_slice(&el).map_err(|_| Error::InvalidHeaders)?);
            }
            let required_sig = stack.pop().ok_or_else(|| Error::InvalidHeaders)?[0] as usize;
            let mut signatures = vec![];
            let start =
                stack.len().checked_sub(required_sig).ok_or_else(|| Error::InvalidHeaders)?;
            for el in stack.drain(start..) {
                signatures.push(Signature::from_der(&el).map_err(|_| Error::InvalidHeaders)?);
            }

            let msg = Message::from_slice(&hash.into_inner()).map_err(|_| Error::InvalidHeaders)?;
            let mut verified = 0;
            let mut pubkey_index = 0usize;
            for signature in signatures.iter() {
                for pubkey in pubkeys[pubkey_index..].iter() {
                    pubkey_index += 1;
                    if crate::EC.verify(&msg, signature, &pubkey.key).is_ok() {
                        verified += 1;
                        break;
                    }
                }
            }
            if verified == required_sig {
                info!("proof for block {} found {} valid signatures", hash, verified);
                stack.pop().ok_or_else(|| Error::InvalidHeaders)?;
                return Ok(());
            }
        }
        Err(Error::InvalidHeaders)
    }
}

#[cfg(test)]
mod test {
    use crate::headers::liquid::Verifier;
    use bitcoin::hashes::hex::FromHex;
    use elements::encode::deserialize;
    use elements::{BlockExtData, BlockHeader, Script};
    use gdk_common::ElementsNetwork;
    use rand::seq::SliceRandom;

    #[test]
    fn test_regtest() {
        let regtest_header : BlockHeader = deserialize(&Vec::<u8>::from_hex("000000a07da0ac2b4932e9501c0e192dfa8b4e6ddd801562f846bd04584bbfa6bd779520a297a6b54050bd32f46e7b738931f2bfc0f9ebc2663e2057dbdf26c5472c73439ee3ec5e01000000022200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332604a00000017a91472c44f957fc011d97e3406667dca5b1c930c4026870151014202fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f00010151").unwrap()).unwrap();

        match regtest_header.ext {
            BlockExtData::Proof {
                challenge: _,
                solution: _,
            } => assert!(false),
            BlockExtData::Dynafed {
                current: _,
                proposed: _,
                signblock_witness: _,
            } => assert!(true),
        }
    }

    #[test]
    fn test_liquid() {
        let verifier = Verifier::new(ElementsNetwork::Liquid);

        // liquid block genesis
        let mut genesis_header : BlockHeader = deserialize(&Vec::<u8>::from_hex("010000000000000000000000000000000000000000000000000000000000000000000000d767f204777d8ebd0825f4f26c3d773c0d3f40268dc6afb3632a0fcbd49fde45dae5494d00000000fd01025b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375fae00").unwrap()).unwrap();
        assert!(verifier.verify_header(&genesis_header).is_ok());
        genesis_header.height = 1;
        assert!(verifier.verify_header(&genesis_header).is_err());

        // liquid block 1
        let block_header : BlockHeader = deserialize(&Vec::<u8>::from_hex("000000200360208a889692372c8d68b084a62efdf60ea1a359a04c94b20d223658276614c8a804bd8a3f6bcfa6f6dc06e596b9b3cab6b57e357185b0e8d0ca3d9da327f25b32ac5b01000000fd01025b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375faefd130300463044022024ec1f6d78bf5cc7364b43e1b5939ea8fa863afeec6ca5d58e204fae7b7ff3af02202f279a21a9efb3fa9dbe43a7f6b814f50e14c5dd4113d9799ec1efb5667aa879463044022044687115bc51db921d6e1a1b9b3542bfa6520bf67c59d7d44af0fa3ea112d566022010fe2da9dc4370b86d4fd58258cae35b61eadf5cbc2bf2572006033b72ee39a8473045022100f95a688a049e7fc956749fa18730b19093f6fa99a49ae8f44071441a7cea2579022039110e0d07d4fc42d669528f8ad82509f1d4ce53d769c27c33ac693e42452266473045022100b745d91095cdff00d691d02bb6a06bc8468d0977cecb4be11189f792392395f20220591d985f45607ea05efe3f696dfb8b0b5cd51bf9c4e26fd7656f0d42408fad5d4630440220377729c8cdd2fd5a2dc7dfcebd9abb1cea541826490f635091a3db4c0487a5bc02207158f761f3188464ff02fa72d75ae03ae196f38f2dfb4b46bb0a453a88bfed954630440220110f034d50f1415b5cd8baf9a39954c9e998e400030c1efd147e7b6cf7735ef102206344118dc9d77a6479a57d8fddbee7dc8ca227b937bcac08f18cc12ded8c0c23463044022055471e35dccd254a00357d7695638cd09f84362cc5b2c42fa1e44964c4483efa022069c038b11cf7fa2285aee29276b893eb288b86af567a7927f5a04fa948c4f7da47304502210083767f0d1347cb409fabb4aa3ac3981a8d7f9d7994c883e53de4d23acf1be9840220339b1683e3aa7cc7e6e32558a2e84c0c2ced04aa4fbff256c0f6372754094e70473045022100f34805c8394c547ceeeff635510d5a581a2a199179acecddac523de0eef61df70220786172710c88342c7e94ac1ada5b96db1bf87044168c143867faa8d2ace4f3874730450221009c9486c87e17b7a9f5217fca9d11a54d2f84bd1902b81f5169c6985f9ae6c3aa02202a3dc55d5f683d1d1b3577110b186b708965de345041256bb3fd0ec2b8165a7a46304402201db14fd5e8ff0a9d962bd98f2da5077500ff0120183a60c5a302dc48543e74d0022055b53a399e22f81571e96b39943fe456c5b8890345848be97d516fe42d522ad0").unwrap()).unwrap();
        assert!(verifier.verify_header(&block_header).is_ok());

        let mut wrong_header = block_header.clone();
        wrong_header.height = 0;
        assert!(verifier.verify_header(&wrong_header).is_err());

        let mut wrong_header = block_header.clone();
        if let BlockExtData::Proof {
            challenge,
            solution: _,
        } = wrong_header.ext
        {
            wrong_header.ext = BlockExtData::Proof {
                challenge,
                solution: Script::default(),
            };
            assert!(
                verifier.verify_header(&wrong_header).is_err(),
                "empty solution should work only on genesis"
            );
        } else {
            assert!(false);
        }

        let mut rng = rand::thread_rng();

        let mut wrong_header = block_header.clone();
        if let BlockExtData::Proof {
            challenge,
            solution,
        } = wrong_header.ext
        {
            let mut challenge_bytes = challenge.into_bytes();
            *challenge_bytes.choose_mut(&mut rng).unwrap() ^= 0xff;
            wrong_header.ext = BlockExtData::Proof {
                challenge: challenge_bytes.into(),
                solution,
            };
            assert!(
                verifier.verify_header(&wrong_header).is_err(),
                "randomly changing a byte in challenge does not err"
            );
        } else {
            assert!(false);
        }

        let mut wrong_header = block_header.clone();
        if let BlockExtData::Proof {
            challenge,
            solution,
        } = wrong_header.ext
        {
            let mut solution_bytes = solution.into_bytes();
            *solution_bytes.choose_mut(&mut rng).unwrap() ^= 0xff;
            wrong_header.ext = BlockExtData::Proof {
                challenge,
                solution: solution_bytes.into(),
            };
            assert!(
                verifier.verify_header(&wrong_header).is_err(),
                "randomly changing a byte in solution does not err"
            );
        } else {
            assert!(false);
        }
    }
}
