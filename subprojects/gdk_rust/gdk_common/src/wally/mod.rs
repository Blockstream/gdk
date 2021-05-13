//!
//! Links to libwally methods used.
//!

use std::ptr;

use bitcoin::secp256k1;
use std::fmt;

use crate::be::AssetId;
use elements::confidential::{Asset, Value};
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub mod ffi;

#[derive(Clone)]
pub struct MasterBlindingKey(pub [u8; 64]);

// need to manually implement Debug cause it's not supported for array>32
impl fmt::Debug for MasterBlindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterBlindingKey ({})", hex::encode(&self.0[..]))
    }
}

/// The max entropy size in bytes for BIP39 mnemonics.
const BIP39_MAX_ENTROPY_BYTES: usize = 32;
/// The size of BIP39-derived seeds in bytes.
const BIP39_SEED_BYTES: usize = 64;

/// Generate a BIP39 mnemonic from entropy bytes.
pub fn bip39_mnemonic_from_bytes(entropy: &[u8]) -> String {
    let mut out = ptr::null();
    let ret = unsafe {
        ffi::bip39_mnemonic_from_bytes(ptr::null(), entropy.as_ptr(), entropy.len(), &mut out)
    };
    assert_eq!(ret, ffi::WALLY_OK);
    read_str(out)
}

/// Validate the validity of a BIP-39 mnemonic.
pub fn bip39_mnemonic_validate(mnemonic: &str) -> bool {
    let c_mnemonic = make_str(mnemonic);
    let ret = unsafe {
        let ret = ffi::bip39_mnemonic_validate(ptr::null(), c_mnemonic);
        let _ = CString::from_raw(c_mnemonic);
        ret
    };
    ret == ffi::WALLY_OK
}

/// Convert the mnemonic back into the entropy bytes.
pub fn bip39_mnemonic_to_bytes(mnemonic: &str) -> Option<Vec<u8>> {
    if !bip39_mnemonic_validate(mnemonic) {
        return None;
    }

    let c_mnemonic = make_str(mnemonic);
    let mut out = Vec::with_capacity(BIP39_MAX_ENTROPY_BYTES);
    let mut written = 0usize;
    let ret = unsafe {
        let ret = ffi::bip39_mnemonic_to_bytes(
            ptr::null(),
            c_mnemonic,
            out.as_mut_ptr(),
            BIP39_MAX_ENTROPY_BYTES,
            &mut written,
        );
        let _ = CString::from_raw(c_mnemonic);
        ret
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert!(written <= BIP39_MAX_ENTROPY_BYTES);
    unsafe {
        out.set_len(written);
    }
    Some(out)
}

/// Convert the mnemonic phrase and passphrase to a binary seed.
pub fn bip39_mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Option<[u8; BIP39_SEED_BYTES]> {
    if !bip39_mnemonic_validate(mnemonic) {
        return None;
    }

    let c_mnemonic = make_str(mnemonic);
    let c_passphrase = make_str(passphrase);
    let mut out = [0u8; BIP39_SEED_BYTES];
    let mut written = 0usize;
    let ret = unsafe {
        let ret = ffi::bip39_mnemonic_to_seed(
            c_mnemonic,
            c_passphrase,
            out.as_mut_ptr(),
            BIP39_SEED_BYTES,
            &mut written,
        );
        let _ = CString::from_raw(c_mnemonic);
        let _ = CString::from_raw(c_passphrase);
        ret
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert_eq!(written, BIP39_SEED_BYTES);
    Some(out)
}

pub fn asset_blinding_key_from_seed(seed: &[u8]) -> MasterBlindingKey {
    assert_eq!(seed.len(), 64);
    let mut out = [0u8; 64];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    MasterBlindingKey(out)
}

pub fn confidential_addr_from_addr(
    address: &str,
    prefix: u32,
    pub_key: secp256k1::PublicKey,
) -> String {
    let mut out = ptr::null();
    let pub_key = pub_key.serialize();

    let c_address = make_str(address);
    let ret = unsafe {
        let ret = ffi::wally_confidential_addr_from_addr(
            c_address,
            prefix,
            pub_key.as_ptr(),
            pub_key.len(),
            &mut out,
        );
        let _ = CString::from_raw(c_address);
        ret
    };
    assert_eq!(ret, ffi::WALLY_OK);
    read_str(out)
}

pub fn asset_blinding_key_to_ec_private_key(
    master_blinding_key: &MasterBlindingKey,
    script_pubkey: &elements::Script,
) -> secp256k1::SecretKey {
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_to_ec_private_key(
            master_blinding_key.0.as_ptr(),
            master_blinding_key.0.len(),
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::SecretKey::from_slice(&out).expect("size is 32")
}

#[allow(clippy::type_complexity)]
pub fn asset_unblind(
    pub_key: secp256k1::PublicKey,
    priv_key: secp256k1::SecretKey,
    proof: Vec<u8>,
    commitment: Vec<u8>,
    extra: elements::Script,
    generator: Vec<u8>,
) -> Result<([u8; 32], [u8; 32], [u8; 32], u64), crate::error::Error> {
    let pub_key = pub_key.serialize();

    let mut asset_out = [0u8; 32];
    let mut abf_out = [0u8; 32];
    let mut vbf_out = [0u8; 32];
    let mut value_out = 0u64;
    let ret = unsafe {
        ffi::wally_asset_unblind(
            pub_key.as_ptr(),
            pub_key.len(),
            priv_key.as_ptr(),
            priv_key.len(),
            proof.as_ptr(),
            proof.len(),
            commitment.as_ptr(),
            commitment.len(),
            extra.as_bytes().as_ptr(),
            extra.as_bytes().len(),
            generator.as_ptr(),
            generator.len(),
            asset_out.as_mut_ptr(),
            asset_out.len(),
            abf_out.as_mut_ptr(),
            abf_out.len(),
            vbf_out.as_mut_ptr(),
            vbf_out.len(),
            &mut value_out,
        )
    };
    if ret != ffi::WALLY_OK {
        crate::error::err("asset_unblind not ok")
    } else {
        Ok((asset_out, abf_out, vbf_out, value_out))
    }
}

pub fn asset_unblind_with_nonce(
    nonce: Vec<u8>,
    proof: Vec<u8>,
    commitment: Vec<u8>,
    extra: elements::Script,
    generator: Vec<u8>,
) -> ([u8; 32], [u8; 32], [u8; 32], u64) {
    let mut asset_out = [0; 32];
    let mut abf_out = [0; 32];
    let mut vbf_out = [0; 32];
    let mut value_out = 0u64;
    let ret = unsafe {
        ffi::wally_asset_unblind_with_nonce(
            nonce.as_ptr(),
            nonce.len(),
            proof.as_ptr(),
            proof.len(),
            commitment.as_ptr(),
            commitment.len(),
            extra.as_bytes().as_ptr(),
            extra.as_bytes().len(),
            generator.as_ptr(),
            generator.len(),
            asset_out.as_mut_ptr(),
            asset_out.len(),
            abf_out.as_mut_ptr(),
            abf_out.len(),
            vbf_out.as_mut_ptr(),
            vbf_out.len(),
            &mut value_out,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    (asset_out, abf_out, vbf_out, value_out)
}

//TODO to be replaced by secp256k1::PublicKey::from_secret_key
pub fn ec_public_key_from_private_key(priv_key: secp256k1::SecretKey) -> secp256k1::PublicKey {
    let mut pub_key = [0; 33];

    let ret = unsafe {
        ffi::wally_ec_public_key_from_private_key(
            priv_key.as_ptr(),
            priv_key.len(),
            pub_key.as_mut_ptr(),
            pub_key.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::PublicKey::from_slice(&pub_key[..]).unwrap() // TODO return Result?
}

pub fn pbkdf2_hmac_sha512_256(password: Vec<u8>, salt: Vec<u8>, cost: u32) -> [u8; 32] {
    let mut tmp = [0; 64];
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_pbkdf2_hmac_sha512(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            0,
            cost,
            tmp.as_mut_ptr(),
            tmp.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    out.copy_from_slice(&tmp[..32]);
    out
}

pub fn asset_generator_from_bytes(asset: &AssetId, abf: &[u8; 32]) -> Asset {
    let mut generator = [0u8; 33];
    let ret = unsafe {
        ffi::wally_asset_generator_from_bytes(
            asset.as_ptr(),
            asset.len(),
            abf.as_ptr(),
            abf.len(),
            generator.as_mut_ptr(),
            generator.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);

    let prefix = generator[0];
    let mut suffix = [0u8; 32];
    suffix.copy_from_slice(&generator[1..]);
    Asset::Confidential(prefix, suffix)
}

pub fn asset_final_vbf(values: Vec<u64>, num_inputs: u32, abf: Vec<u8>, vbf: Vec<u8>) -> [u8; 32] {
    let mut final_vbf = [0u8; 32];

    let ret = unsafe {
        ffi::wally_asset_final_vbf(
            values.as_ptr(),
            values.len(),
            num_inputs,
            abf.as_ptr(),
            abf.len(),
            vbf.as_ptr(),
            vbf.len(),
            final_vbf.as_mut_ptr(),
            final_vbf.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    final_vbf
}

pub fn asset_value_commitment(value: u64, vbf: [u8; 32], generator: Asset) -> Value {
    let mut value_commitment = [0u8; 33];

    let generator = elements::encode::serialize(&generator);
    assert_eq!(generator.len(), 33);

    let ret = unsafe {
        ffi::wally_asset_value_commitment(
            value,
            vbf.as_ptr(),
            vbf.len(),
            generator.as_ptr(),
            generator.len(),
            value_commitment.as_mut_ptr(),
            value_commitment.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    let prefix = value_commitment[0];
    let mut suffix = [0u8; 32];
    suffix.copy_from_slice(&value_commitment[1..]);
    Value::Confidential(prefix, suffix)
}

#[allow(clippy::too_many_arguments)]
pub fn asset_rangeproof(
    value: u64,
    pub_key: secp256k1::PublicKey,
    priv_key: secp256k1::SecretKey,
    asset: AssetId,
    abf: [u8; 32],
    vbf: [u8; 32],
    commitment: Value,
    extra: &elements::Script,
    generator: Asset,
    min_value: u64,
    exp: i32,
    min_bits: i32,
) -> Vec<u8> {
    let mut rangeproof_buffer = [0u8; 5134];
    let mut written = 0usize;
    let pub_key = pub_key.serialize();
    let commitment = elements::encode::serialize(&commitment); // should check commitment and generator are confidential
    let generator = elements::encode::serialize(&generator);

    let ret = unsafe {
        ffi::wally_asset_rangeproof(
            value,
            pub_key.as_ptr(),
            pub_key.len(),
            priv_key.as_ptr(),
            priv_key.len(),
            asset.as_ptr(),
            asset.len(),
            abf.as_ptr(),
            abf.len(),
            vbf.as_ptr(),
            vbf.len(),
            commitment.as_ptr(),
            commitment.len(),
            extra.as_bytes().as_ptr(),
            extra.as_bytes().len(),
            generator.as_ptr(),
            generator.len(),
            min_value,
            exp,
            min_bits,
            rangeproof_buffer.as_mut_ptr(),
            rangeproof_buffer.len(),
            &mut written,
        )
    };

    assert_eq!(ret, ffi::WALLY_OK);
    rangeproof_buffer[0..written].to_vec()
}

pub fn asset_surjectionproof_size(num_inputs: usize) -> usize {
    let mut proof_size = 0usize;
    let ret = unsafe { ffi::wally_asset_surjectionproof_size(num_inputs, &mut proof_size) };
    assert_eq!(ret, ffi::WALLY_OK, "wally_asset_surjectionproof_size({}) fails", num_inputs);
    proof_size
}

#[allow(clippy::too_many_arguments)]
pub fn asset_surjectionproof(
    output_asset: AssetId,
    output_abf: [u8; 32],
    output_generator: Asset,
    bytes: [u8; 32],
    assets: &[u8],
    abfs: &[u8],
    generators: &[u8],
    num_inputs: usize,
) -> Vec<u8> {
    let proof_size = asset_surjectionproof_size(num_inputs);

    let output_generator = elements::encode::serialize(&output_generator);

    let mut proof = [0u8; 8259];
    let mut written = 0usize;

    let ret = unsafe {
        ffi::wally_asset_surjectionproof(
            output_asset.as_ptr(),
            output_asset.len(),
            output_abf.as_ptr(),
            output_abf.len(),
            output_generator.as_ptr(),
            output_generator.len(),
            bytes.as_ptr(),
            bytes.len(),
            assets.as_ptr(),
            assets.len(),
            abfs.as_ptr(),
            abfs.len(),
            generators.as_ptr(),
            generators.len(),
            proof.as_mut_ptr(),
            proof_size,
            &mut written,
        )
    };

    assert_eq!(ret, ffi::WALLY_OK);
    assert_eq!(proof_size, written);
    proof[..proof_size].to_vec()
}

pub fn make_str<'a, S: Into<Cow<'a, str>>>(data: S) -> *mut c_char {
    CString::new(data.into().into_owned()).unwrap().into_raw()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1;
    use elements::Script;
    use hex;
    use std::str::FromStr;

    const _CA_PREFIX_LIQUID: u32 = 0x0c;
    const CA_PREFIX_LIQUID_REGTEST: u32 = 0x04;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // test vector from the BIP spec
        let v_entropy = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c";
        let v_mnem = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        let v_seed = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
        let v_passphrase = "TREZOR";

        let mnemonic = bip39_mnemonic_from_bytes(&hex::decode(v_entropy).unwrap());
        assert_eq!(mnemonic, v_mnem);
        assert!(bip39_mnemonic_validate(&mnemonic));
        assert_eq!(hex::encode(&bip39_mnemonic_to_bytes(&mnemonic).unwrap()), v_entropy);
        let seed = bip39_mnemonic_to_seed(&mnemonic, &v_passphrase).unwrap();
        assert_eq!(v_seed, &hex::encode(&seed[..]));
    }

    #[test]
    /// test vectors taken from libwally-core test_confidential_addr.py test_master_blinding_key
    fn test_elements_master_blinding_key() {
        let mnemonic = "all all all all all all all all all all all all";
        let passphrase = "";
        let seed = bip39_mnemonic_to_seed(mnemonic, passphrase);
        assert!(seed.is_some());
        let seed = seed.unwrap();
        assert_eq!(seed.len(), 64);
        assert_eq!(hex::encode(&seed[..]), "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8");
        let master_blinding_key = asset_blinding_key_from_seed(&seed);
        assert_eq!(
            hex::encode(&master_blinding_key.0[32..]),
            "6c2de18eabeff3f7822bc724ad482bef0557f3e1c1e1c75b7a393a5ced4de616"
        );

        let unconfidential_addr = "2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr";
        let script: Script =
            hex::decode("76a914a579388225827d9f2fe9014add644487808c695d88ac").unwrap().into();
        let blinding_key = asset_blinding_key_to_ec_private_key(&master_blinding_key, &script);
        let public_key = ec_public_key_from_private_key(blinding_key);
        let conf_addr =
            confidential_addr_from_addr(unconfidential_addr, CA_PREFIX_LIQUID_REGTEST, public_key);
        assert_eq!(
            conf_addr,
            "CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ"
        );
        let addr = elements::Address::from_str(&conf_addr);
        assert!(addr.is_ok());
    }

    #[test]
    /// test vectors taken from libwally-core test_elements.py test_asset_unblind
    fn test_elements_unblind() {
        // the private part of our blinding key
        let our_sk = secp256k1::SecretKey::from_slice(
            &hex::decode("e8ba74f899e6b06da05fb255511c7adcea41f186326ef4fc45290fa8043f7af5")
                .unwrap()[..],
        )
        .unwrap();
        // the sender's pubkey used to blind the output
        let sender_pk = secp256k1::PublicKey::from_slice(
            &hex::decode("0378d8b53305ed6482db0c8f5eb8b0ca3d5c314d7773c584faa8cf587ee8137244")
                .unwrap()[..],
        )
        .unwrap();
        // amount rangeproof
        let rangeproof = hex::decode("602300000000000000010d28013bd6c293ff8791d172520c5ecdceb4d4c4bbeac9d1f016cd9069624d606d5fe0641e36cce10328f2c9c481a7342c27ef81b0b8533a72b289dfc18942651c4c31b0497bcc21444fbf73214755791c32dba25508f20f33d2a171fb46f360cfc63677df9f696a4566ce9d305ff47d51a73c3e8ee56cd6b6a1b62bf606068da2145a3805de1dfbe8de65b997d261e27f7ce5a4233b410bb2a17fe903a3a6f5a907d0e2cc1b0c16dde9a4ed99c59b2e3f3db331c4d910ffb87fa7696136c1a7562fa32f84ef4b6e7a298053dc84a851798503200a006cbf403a741a13507c9f2c57ae2139b08974777f0245e5cb5c890626c6041d65bd15c0220f20f3823a88364d9f50dddeae1de77f5015c8749622a1e15d242b029a4810374dfb3297ce87f8e16bd84e4147bc03a7279c9a7cfb85669ea51a2f04e1126b150bd995191284d1ffa5fb904501d0076d179cbef13912bdc9ecd3db4c40ec2ecb1b6987d6d526443d02a35c260d721b321535ff4749bba2cb44a928e96af0955d68159ca501758abb3c97e5781e20d2e74bfdb8f1e342fe7023181006ba3ea3624d9ce831f998c2d9953475250726f940e5543204e447c0afc2e00b7ff08564db6e6933b1a82ce30c7bed97f3b58a154a932fb229533317edcc9bb4b338e43b2ac5a5c27380d7523230f7f99729a4000\
        285b4427c9d79dd6508a81052106107a99b224e2e65fe5b5f94b71323f8cb55f8eda2283e464f35cc00dad0e5d6cfd104eef5c180683eb28040502937d1377d1c07f31d30ba7c3a11a88560078646c0b431fca020dde44b2f6258183aca426f67c3bc235d59a1680d1bc124dac0cbf4a7147d28dc7093e72dcd7259ecc75118d6b6fdcda5c66b761afdc749b8f27bc0d676e719df2850827389809215b96fc19458390892f98cc175e36cab798215f93d473561aaed05536272e97ac25a2e5915b543f058a03c9827d42525ecf6b8bb7f83440a9f2e7f6a672a918e291ec662eb044a76281c35369e1ce1a8fa78751691c3e17e409ea7c4272199aecac2ba51e7493941d5be901ff3daf66714bb066d8c00c25fbef8be50b7edfad99e96a27302f0850db4083a3c2bd7ffa367b3cb36ae3d64ed138a6b9b9da26e4b0d2beb9e6570beca85bdb5fe562122baa2791e34d0f102d15d3dfa293232fd0656012977f71c4e9f7f7579bf1d00cc414dc263a3189d9f508a8b16019f575150a632610a3dc1b50ec880cc8453a55af786ed86c0163501f0709a79565d273851a86ae49273adad202cc0f782f67953da4c442faefd903edbb30efe9489ace0802dd8063fdac5d9a9c9885536f8bfb86de8d65296cab722958366ae74c0e38e0b197eba10a930335d2f0945841cb66eea0958fc1eef40eeff\
        80b6f87f3e46c3990b2ad27b3c7c89ac99f66e84458fc07ff09ed5ee96753b2fcbad4da7d0718fdc455c0fe9ebc614f072fb1da072564ba881044496f8757099663f36a269da6778a3d03904d0fa7619192cf28639cd359e1a7fd5a9a8e207d505c0764602a824d1b1540f17ab75d81e7435501018193fc6cbbee3921c8806b4f81246367fe523d9e32f8e5be8da29041940db0bcf0b2ae604ec665fea1e10b861e2c078aa09dcebb6cc283ab171598a799787a622fc5ea7ed63b558d020ee8c853f5ba888fd35bc851c1a2873531be58f82ef9d443edb5358698f0e6c4a7b133a22e1dbb4a8bd07bca9d08e0735b702acc9d3dfec7708002892676f738197ebf6790e9531727d98bd199883affc879c3579c05400a4db2e214f824e3ae37cdbc825ef2ec58bd861226bdf9be4bd81a1858d63050f58796d739d901ac4a8c0a29fe90db30ad58d075c5944e88ff2d46edac7e678faf889b4b681c6bf0890708f5e60ca80e5195b94cdae5bc3c89963f7634398d595219a6bfa1f512387b2006e85fdade17adce51d42061107b74a69a8961be3c3de86bd6caa77bb88a1f29b572c1c05b423bdde397cf238746b63f12b7a867baba644c3718acfc963ea2b9c0c96c493ed2fc1e2103c57fdb60dba24f94df7d008f96aaa6bd9f598eaab71c8d597224dd6259ce24b531def3b0c964c9a29f1833\
        11f5e30b76f667bba242ae11ab40f2e325a63cfcd4fe90f495d9533ef5307938ce2800fe9dfd6ce27590abf0c7e37639befb5751a950552cf19dc968c24dc727ca16cdaabf73ab7fcb14f5d5bd0a8735dd2b6957cd21b3a22c24641d215f5b60e79a5adc1aa06697a1adbc4d375798b586bf954af251c0f3aed359371fc7699a02824801edff2fe5fa63d7d94bae1b8ab02f49917ffadebb6fc8064484178313ce34d0a59ea07026ca5abcf6424e181954383ea820e77f01dc1807aebfde103aab79d49de697b640a2a41dcb3a69f340eb7f98b543694abfc93d35b4153d779811a313b335dac71b3512c4414082b15626a37f0fb82efd62cd23692e88d75501f1ab68a712bae7061a201e6b0caac0de300ea93ff6d52161ea13724d946ae0d3fc0aae0d1987d03a549ea481007546d5c3b89245d8eea2d8fce5b5ac8bde15b327fbc62bef5cd20b09bc5c6de1316a99a9d55c3f462dbe21860f43bca336f7e03c7e1a39af397ebd83571e2a0003be52b7d88404f1e1300dcd8fdd20e740ea0e5b58613dd0b19e219c05ff7d31c3f0c86a1f83b02c2d5e382e27d476f44b484e0dd9e82dfc1567e44e045482938100354722e57a36769d8b91b1d4064cb08c233519d636adf31fa49c75b067437b0ac52152079575b3d2b672433a1b865b5e8d82ad18980adad6cd26224859082e487e0573a8e\
        24cb9f3e08dd02da28d70f6dd8cb1a029c175776d0db4f40102812fe9d1a32778317b61f27a96a6689ad1787a8b7a3672f9568a3b9f456039243202a1ef55f3a5c64dae11d58dbf931eceab8a21de2e7aaef7f47938d34240999ac3f66fcae1afbbdccffb56e4fbea05b14a6f64da770b3ff95471ce73d26f96b1549a9641d085af574fd9a2dc037382417dbd15c3b4c5c67c91b73fda65be7828e1045b1631a330882180068ad9fced2c8cb154281e584f63966c7ac5127397a10e4de98c6daec5676689db46c2950ebb84fc84d42a30c603df31f7bd1f44f6354217845b25219bf3a4e01674a7404add024bb2d5184582d8ea0a1005aa8e3abd24b0e4069de87c1ccb1654613a4e734eea3b6045025e5902c3e74796ba0911e40c4d814076422ffdb2eb9faf5079638a59d188304ffdd8b1635b585c881c37434e256c6df5193c3720c7973b14541ae7681214bd9387bbcdea3ecafd1103050371224ba5b9992058e7114502886b3dddd2901612a699713f2e0b659c1ffbe04b29971dd277971848c769dfaaa3b96a93b47e7f46e002c3f0ffa3937c36bb4bd034a5dd252ad9d39c70e9862390f5eb2d8aba7a15d6b77b5b027531af282e2cccac117548a8b5ca415595d2e8a2ae400366cfa5400c5bf51a729fd22ed50752b2b03d959bc3f0bef52c17e61ae16536d1d019454d9f6b9a38ff\
        bc70706ab7fe4908c0bea9427547c8c9d9c4fdb4f25f1f26ea7f0a4a2a487c7639138de55bb2bc6e7d47a0241fbf347dd714767198fe85a0d294b938699f139e6a6f66e6916b566584811115591fa1f5e8561369b07c9155d28619df2537e651fcb4667f07ea5fd884779c7bb81af74b0987125aa915644a17b852b465661d0fcdb108ca76b51350635660f61e3b46df74b6b9877dbfab79fda8191e12a0f51fca7081cc5b91c576a99cba868c034ea04e0b4c2ccabada556187970fe0100f647301958c9771517a558ad6183a3f912b94030561948de2d2c44a3117e489de7b0568eee8bc15820a734a3b745eff696732fb660958b7f15b4298ed683b99dadcf4fbc002ead43fb792922c6a1ad69aa626fc4893daaa3c2ad0f90784f5872a115222472c6b2d1308f0b88486701566c86ee2ad03b3ce06206bfc6b205084469a84dfa7a7861889a5d5990a5f7a5177497e11f95c8af5fd192349b02b66af842f2eb6964b7ce201ecce6e3373e320e316a2844bcf121d409a4f8e3f7e73b02f93ff3601f7c1957aa8c3a34b7\
        ").unwrap();
        // scriptPubKey of the output
        let script: Script =
            hex::decode("76a9145976d83033bde4f12713ae3706b25e92fb608b9188ac").unwrap().into();
        let asset_commitment =
            hex::decode("0b9d043d60286407330e12001e539559f6227c9999abf251b7497bba53ac20cd70")
                .unwrap();
        let value_commitment =
            hex::decode("09b67565b370abf41d81fe0ed6378e7228e9ae01d1b72b69582f83db1fca522148")
                .unwrap();

        let (asset, abf, vbf, value) = asset_unblind(
            sender_pk,
            our_sk,
            rangeproof,
            value_commitment,
            script,
            asset_commitment,
        )
        .unwrap();

        assert_eq!(
            asset.to_vec(),
            hex::decode("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a")
                .unwrap()
        );
        assert_eq!(
            abf.to_vec(),
            hex::decode("3f2f58e80fbe77e8aad8268f1baebc3548c777ba8271f99ce73210ad993d907d")
                .unwrap()
        );
        assert_eq!(
            vbf.to_vec(),
            hex::decode("51f109e34d0282b6efac36d118131060f7f79b867b67a95bebd087eda2ccd796")
                .unwrap()
        );
        assert_eq!(value, 80_000_000);
    }

    #[test]
    fn test_elements_asset_unblind_with_nonce() {
        let tx_hex =
            include_str!("5cd7f370af84c03f19eec4695c40de923ef1eb5f4952af2fa4907da620b7d16a.hex");
        assert_eq!(13286, tx_hex.len());
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let tx: elements::Transaction = elements::encode::deserialize(&tx_bytes).unwrap();
        let txid_str = "5cd7f370af84c03f19eec4695c40de923ef1eb5f4952af2fa4907da620b7d16a";
        assert_eq!(format!("{}", tx.txid()), txid_str);

        // output #1 is my change
        let change = tx.output[1].clone();

        // from the node recover confidential_key
        // ./src/elements-cli -chain=liquidv1 getaddressinfo Gt4eUKv82VuFPExmX5mqEDXkKuQ1Euzb6J | jq -r .confidential
        // VJLAMi52eUDE8SKYc7u1Zryg2MDcoNAMhYLf5BVvtpX8J1h9JrNsc2B9gqPa627SWQLzJqAWbUQceizq
        // ./src/elements-cli -chain=liquidv1 getaddressinfo $CONF_ADDR | jq -r .confidential_key
        // 02b19255e05b1f0d063b4b62ccfb2d66c2f8c40cbabafe70292eb4d50759014c64
        // ./src/elements-cli -chain=liquidv1 dumpblindingkey VJLAMi52eUDE8SKYc7u1Zryg2MDcoNAMhYLf5BVvtpX8J1h9JrNsc2B9gqPa627SWQLzJqAWbUQceizq
        // REDACTED
        // let blinding_private_key_hex = "REDACTED";
        //let blinding_public_key_hex = "02b19255e05b1f0d063b4b62ccfb2d66c2f8c40cbabafe70292eb4d50759014c64";

        //let blinding_private_key =  secp256k1::SecretKey::from_slice(&hex::decode(blinding_private_key_hex).unwrap()).unwrap();
        //let blinding_public_key = ec_public_key_from_private_key(blinding_private_key.clone());
        //assert_eq!(blinding_public_key_hex, hex::encode( &blinding_public_key.serialize()[..]));

        //let sender_public_key_bytes = elements::encode::serialize(&change.nonce);
        //assert_eq!(sender_public_key_bytes.len(), 33);
        //let sender_public_key = secp256k1::PublicKey::from_slice(&sender_public_key_bytes).unwrap();
        //let sender_public_key_hex = "027eddd9a667b17f047a548d4c251dcbc7c682c43c161c2875f603045b1acab5c6";
        //assert_eq!(hex::encode(sender_public_key_bytes), sender_public_key_hex);

        //let blinding_nonce = sha256::Hash::hash( secp256k1::ecdh::SharedSecret::new(&sender_public_key, &blinding_private_key).as_ref());
        //assert_eq!("d0cc21df08e33340042c17899ee20939cedb71a820bac322591a41265ea14cd2", hex::encode(blinding_nonce.as_ref()));

        let blinding_nonce =
            hex::decode("d0cc21df08e33340042c17899ee20939cedb71a820bac322591a41265ea14cd2")
                .unwrap();

        let rangeproof = change.witness.rangeproof.clone();
        let value_commitment = elements::encode::serialize(&change.value);
        let asset_commitment = elements::encode::serialize(&change.asset);
        let script = change.script_pubkey.clone();
        let (asset, abf, vbf, value) = asset_unblind_with_nonce(
            blinding_nonce.to_vec(),
            rangeproof,
            value_commitment,
            script,
            asset_commitment,
        );
        assert_eq!(value, 9972);
        assert_eq!(
            hex::encode(&asset[..]),
            "6d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f"
        );
        assert_eq!(
            hex::encode(&abf[..]),
            "7719338beae503b90f672366cfa32c6791c08f061df419fdcaddb1ff5bf693b8"
        );
        assert_eq!(
            hex::encode(&vbf[..]),
            "1ace094a11fb12b82d8c1e7d4e1abfebc087a3cf90369d65b54379f40feb3190"
        );
    }

    #[test]
    fn test_blind() {
        // from libwally test_assets.js
        let vec = hex::decode("8b5d87d94b9f54dc5dd9f31df5dffedc974fc4d5bf0d2ee1297e5aba504ccc26")
            .unwrap();
        let mut vbf = [0u8; 32];
        vbf.copy_from_slice(&vec[..]);

        let vec = hex::decode("0ba4fd25e0e2108e55aec683810a8652f9b067242419a1f7cc0f01f92b4b078252")
            .unwrap();
        let generator: elements::confidential::Asset = elements::encode::deserialize(&vec).unwrap();

        let commitment = asset_value_commitment(10000, vbf, generator);
        assert_eq!(
            hex::encode(elements::encode::serialize(&commitment)),
            "08a9de5e391458abf4eb6ff0cc346fa0a8b5b0806b2ee9261dde54d436423c1982"
        );

        let ones = [0x17u8; 32];
        let values = [20000u64, 4910, 13990, 1100].to_vec();
        let asset = ones.clone();
        let abf = ones.clone();
        let abfs = hex::decode("7fca161c2b849a434f49065cf590f5f1909f25e252f728dfd53669c3c8f8e37100000000000000000000000000000000000000000000000000000000000000002c89075f3c8861fea27a15682d664fb643bc08598fe36dcf817fcabc7ef5cf2efdac7bbad99a45187f863cd58686a75135f2cc0714052f809b0c1f603bcdc574").unwrap();
        let vbfs = hex::decode("1c07611b193009e847e5b296f05a561c559ca84e16d1edae6cbe914b73fb6904000000000000000000000000000000000000000000000000000000000000000074e4135177cd281b332bb8fceb46da32abda5d6dc4d2eef6342a5399c9fb3c48").unwrap();

        let _generator = asset_generator_from_bytes(&asset, &abf);
        let vbf = asset_final_vbf(values.clone(), 1, abfs, vbfs);
        assert_eq!(
            hex::encode(&vbf[..]),
            "6996212c70fa85b82d4fd76bd262e0cebc5d8f52350a73af8d2b881a30442b9d"
        );
    }

    #[test]
    fn test_sur_size() {
        let mut proof_size = 0usize;
        let num_inputs = 1;
        let ret = unsafe { ffi::wally_asset_surjectionproof_size(num_inputs, &mut proof_size) };
        assert_eq!(ret, ffi::WALLY_OK);
        assert_eq!(proof_size, 67);
    }

    #[test]
    fn test_rangeproofsize() {
        //from test_elements_tx.c
        let tx_hex =
            include_str!("2f3ea53c0caf358604dad126523ad8a71b1e2550011bcb85b41af54faa737af2.hex")
                .trim();

        let tx: elements::Transaction =
            elements::encode::deserialize(&hex::decode(tx_hex).unwrap()).unwrap();
        println!("{}", tx.txid());
        for output in tx.output {
            println!("surj size: {}", output.witness.surjection_proof.len());
            println!("rangeproof size: {}", output.witness.rangeproof.len());
        }
    }

    #[test]
    fn test_pbkdf2() {
        // abandon abandon ... about
        // expected value got from a session with server_type green
        let xpub = bitcoin::util::bip32::ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4XYa9MoLt4BiMZ4gkt2faZ4BcmKu2a9te4LDpQmvEz2L2yDERivHxFPnxXXhqDRkUNnQCpZggCyEZLBktV7VaSmwayqMJy1s").unwrap();
        let password = xpub.encode().to_vec();
        let salt = "testnet".as_bytes().to_vec();
        let cost = 2048;
        let bytes = pbkdf2_hmac_sha512_256(password, salt, cost);
        assert_eq!(
            hex::encode(bytes),
            "657a9de33d1f7753edbb86c90b0ba064bd1b986570f1a5019ed80459877b013b"
        );
    }
}
