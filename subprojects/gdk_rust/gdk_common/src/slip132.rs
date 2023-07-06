use std::convert::TryInto;

use bitcoin::base58;
use bitcoin::bip32::{ChildNumber, ExtendedPubKey};

use crate::error::Error;
use crate::scripts::ScriptType;

const VERSION_XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e]; // mainnet p2pkh
const VERSION_YPUB: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2]; // mainnet p2sh-p2wpkh
const VERSION_ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46]; // mainnet p2wpkh
const VERSION_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf]; // testnet p2pkh
const VERSION_UPUB: [u8; 4] = [0x04, 0x4a, 0x52, 0x62]; // testnet p2sh-p2wpkh
const VERSION_VPUB: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6]; // testnet p2wpkh

pub fn slip132_version(is_mainnet: bool, script_type: ScriptType) -> [u8; 4] {
    match (is_mainnet, script_type) {
        (true, ScriptType::P2pkh) => VERSION_XPUB,
        (true, ScriptType::P2shP2wpkh) => VERSION_YPUB,
        (true, ScriptType::P2wpkh) => VERSION_ZPUB,
        (false, ScriptType::P2pkh) => VERSION_TPUB,
        (false, ScriptType::P2shP2wpkh) => VERSION_UPUB,
        (false, ScriptType::P2wpkh) => VERSION_VPUB,
    }
}

fn decode_slip132_version(bytes: &[u8; 4]) -> Result<(bool, ScriptType), Error> {
    match bytes {
        &VERSION_XPUB => Ok((true, ScriptType::P2pkh)),
        &VERSION_YPUB => Ok((true, ScriptType::P2shP2wpkh)),
        &VERSION_ZPUB => Ok((true, ScriptType::P2wpkh)),
        &VERSION_TPUB => Ok((false, ScriptType::P2pkh)),
        &VERSION_UPUB => Ok((false, ScriptType::P2shP2wpkh)),
        &VERSION_VPUB => Ok((false, ScriptType::P2wpkh)),
        _ => Err(Error::InvalidSlip132Version),
    }
}

pub fn decode_from_slip132_string(s: &str) -> Result<(bool, ScriptType, ExtendedPubKey), Error> {
    let mut bytes = base58::decode_check(s)?;
    if bytes.len() < 4 {
        return Err(Error::InvalidSlip132Version);
    }
    let (is_mainnet, script_type) = decode_slip132_version(&bytes[0..4].try_into()?)?;
    let bip32_version = if is_mainnet {
        VERSION_XPUB
    } else {
        VERSION_TPUB
    };
    bytes[0..4].copy_from_slice(&bip32_version);
    let xpub = ExtendedPubKey::decode(&bytes)?;
    Ok((is_mainnet, script_type, xpub))
}

/// We expect that the xpub child number is `bip32_account'`
pub fn extract_bip32_account(xpub: &ExtendedPubKey) -> Result<u32, Error> {
    match xpub.child_number {
        ChildNumber::Hardened {
            index: n,
        } => Ok(n),
        _ => Err(Error::UnexpectedChildNumber),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_slip132() {
        let upub0 = "upub5D9ydiUdMxX8TAV2amCA42JwN94xHEC5sUzJJMrZRhyaQZJ9BNmVPsYdAkGgZX3QD1pgxK1y8TiG4m185nTWGt742zJfmRk3wirRTnuQjxm";
        let upub1 = "upub5D9ydiUdMxX8VDwAAx2HvGKTdNZS7K6hB9qSpNWMykzbAp6RgMqGsCocHTo1UNwMYa31TvK7tnxVkoYUJ7tbcuxRmrFiCGdDZiJVGaKaetb";
        let vpub0 = "vpub5XzEwP9YWe4cJQ3cjoiB9ZmMMQ1dzNygJUD2K2xKgzGRqFdiJSgXHeCVdK6JQugqkPoR5WWTYnHXrcbA4ppXzn1wCBDsd5zfSSdq3X6Vw3v";
        let vpub1 = "vpub5XzEwP9YWe4cMj59y4bTfPrS1akQWAyMhLYxgCPMZAdNnigxcyG4SKkjPgcQscuw8yk6vKmHjULHU5XF13h6U9ESF1q5PqTaNMwPe1GToHc";
        let tpub0 = "tpubDC2Q4xK4XH72HeV8i1wzpYqdSJq2pW24FCAaLxTEbQ2JL2ArB5NrGjFSGkTpMaQPViLBHJipgosUhkKpRpmR2vfwy2pYkpnx6E5j6VBf8Di";
        let tpub1 = "tpubDC2Q4xK4XH72KGQWGBDPPgT6LQpaHQMqfFCTDgsXaR4objnmduzxcdJfy6BBnpWBbYQs4jRP7tZWcJ4J44E5MVA3jDRy7rNygmLYzheF284";
        let ypub1 = "ypub6We8xsTdpgW69bD4PGaWUPkkCxXkgqdm4Lrb51DG7fNnhft8AS3VzDXR32pwdM9kbzv6wVbkNoGRKwT16krpp82bNTGxf4Um3sKqwYoGn8q";

        let args = [
            (upub0, ScriptType::P2shP2wpkh, VERSION_UPUB, false, 0),
            (upub1, ScriptType::P2shP2wpkh, VERSION_UPUB, false, 1),
            (vpub0, ScriptType::P2wpkh, VERSION_VPUB, false, 0),
            (vpub1, ScriptType::P2wpkh, VERSION_VPUB, false, 1),
            (tpub0, ScriptType::P2pkh, VERSION_TPUB, false, 0),
            (tpub1, ScriptType::P2pkh, VERSION_TPUB, false, 1),
            (ypub1, ScriptType::P2shP2wpkh, VERSION_YPUB, true, 1),
        ];
        for (ext_key, script_type, version, is_mainnet, n) in args {
            let (m, t, xpub) = decode_from_slip132_string(ext_key).unwrap();
            assert_eq!(m, is_mainnet);
            assert_eq!(t, script_type);
            let prefix = &xpub.to_string()[..4];
            if is_mainnet {
                assert_eq!(prefix, "xpub");
            } else {
                assert_eq!(prefix, "tpub");
            }
            assert_eq!(slip132_version(is_mainnet, script_type), version);
            assert_eq!(extract_bip32_account(&xpub).unwrap(), n)
        }

        assert!(decode_from_slip132_string("foobar").is_err());

        let tpub_err = "tpubDC2Q4xJvBca46ZxTdaQEB1pT6j9fuPG5HnrP5chgWPFh1EjfaCt8f5v6b68M5D7xBBF4Md2MCFi2KBDYPLHy6QhBLuifUTPRSDnMWDYUWAy";
        let (_, _, xpub) = decode_from_slip132_string(tpub_err).unwrap();
        assert!(extract_bip32_account(&xpub).is_err());
    }
}
