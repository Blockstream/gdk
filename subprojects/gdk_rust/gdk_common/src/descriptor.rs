use crate::error::Error;
use crate::scripts::ScriptType;
use bitcoin::bip32::{ChildNumber, ExtendedPubKey, Fingerprint};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey, ShInner};

/// Make sure the key origin is in the expected format
/// and return the bip32 account number
fn match_key_origin(v: &Vec<ChildNumber>, purpose: u32, coin_type: u32) -> Result<u32, Error> {
    match (v.get(0), v.get(1), v.get(2), v.get(3)) {
        (
            Some(ChildNumber::Hardened {
                index: p,
            }),
            Some(ChildNumber::Hardened {
                index: c,
            }),
            Some(ChildNumber::Hardened {
                index: n,
            }),
            None,
        ) if (*p == purpose && *c == coin_type) => Ok(*n),
        _ => Err(Error::UnsupportedDescriptor),
    }
}

/// Check that the xpub child number matches the bip32 account number
fn check_xpub_consitency(
    script_type: ScriptType,
    xpub: ExtendedPubKey,
    bip32_account: u32,
    fingerprint: Fingerprint,
) -> Result<(ScriptType, ExtendedPubKey, u32, Fingerprint), Error> {
    match xpub.child_number {
        ChildNumber::Hardened {
            index: n,
        } if n == bip32_account => Ok((script_type, xpub, n, fingerprint)),
        _ => Err(Error::UnsupportedDescriptor),
    }
}

/// Parse a descriptor and fail if it's not one of the supported types,
pub fn parse_single_sig_descriptor(
    s: &str,
    coin_type: u32,
) -> Result<(ScriptType, ExtendedPubKey, u32, Fingerprint), Error> {
    let (desc, _) =
        Descriptor::parse_descriptor(&crate::EC, s).map_err(|_| Error::UnsupportedDescriptor)?;
    if !desc.has_wildcard() {
        return Err(Error::UnsupportedDescriptor);
    }

    if let Descriptor::Sh(sh) = desc {
        if let ShInner::Wpkh(wpkh) = sh.as_inner() {
            if let DescriptorPublicKey::XPub(descriptorxkey) = wpkh.as_inner() {
                if let Some((f, p)) = &descriptorxkey.origin {
                    let n = match_key_origin(&p.clone().into(), 49, coin_type)?;
                    return check_xpub_consitency(
                        ScriptType::P2shP2wpkh,
                        descriptorxkey.xkey,
                        n,
                        *f,
                    );
                }
            }
        }
    } else if let Descriptor::Wpkh(wpkh) = desc {
        if let DescriptorPublicKey::XPub(descriptorxkey) = wpkh.as_inner() {
            if let Some((f, p)) = &descriptorxkey.origin {
                let n = match_key_origin(&p.clone().into(), 84, coin_type)?;
                return check_xpub_consitency(ScriptType::P2wpkh, descriptorxkey.xkey, n, *f);
            }
        }
    } else if let Descriptor::Pkh(pkh) = desc {
        if let DescriptorPublicKey::XPub(descriptorxkey) = pkh.as_inner() {
            if let Some((f, p)) = &descriptorxkey.origin {
                let n = match_key_origin(&p.clone().into(), 44, coin_type)?;
                return check_xpub_consitency(ScriptType::P2pkh, descriptorxkey.xkey, n, *f);
            }
        }
    }
    Err(Error::UnsupportedDescriptor)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_descriptor() {
        let coin_type = 1;
        let tpub = "tpubDC2Q4xK4XH72J7Lkp6kAvY2Q5x4cxrKgrevkZKC2FwWZ9A9qA5eY6kvv6QDHb6iJtByzoC5J8KZZ29T45CxFz2Gh6m6PQoFF3DqukrRGtj5";
        let tpub_1 = "tpubDC2Q4xK4XH72LKPujd1d7X8YzuwWAemRQhcYpNqduZzpvqvR3DP3bEUJWELoPG8EEsmvQzYZ3Pw81oYrcwnJ5rmVRvm2zdyT2h7mMNJArtJ";
        let shp2wpkh = format!("sh(wpkh([00000000/49'/1'/0']{}/0/*))", tpub);
        let shp2wpkh_change = format!("sh(wpkh([00000000/49'/1'/0']{}/1/*))", tpub);
        let p2wpkh = format!("wpkh([00000000/84'/1'/0']{}/0/*)", tpub);
        let p2wpkh_1 = format!("wpkh([00000000/84'/1'/1']{}/0/*)", tpub_1);
        let p2wpkh_inc = format!("wpkh([00000000/84'/1'/0']{}/0/*)", tpub_1);
        let p2pkh = format!("pkh([00000000/44'/1'/0']{}/0/*)", tpub);
        let shmulti = format!("sh(multi(2,{}/0/*,{}/1/*))", tpub, tpub);
        let shp2wkh_no_wildcard = format!("sh(wpkh([00000000/49'/1'/0']{}/0))", tpub);
        let shp2wkh_no_key_origin = format!("sh(wpkh({}/0/*))", tpub);
        let p2wpkh_incorrect_key_origin1 = format!("sh(wpkh([00000000/44'/1'/0']{}/0/*))", tpub);
        let p2wpkh_incorrect_key_origin2 = format!("sh(wpkh([00000000/84'/1'/0'/0']{}/0/*))", tpub);

        // Valid cases
        let (t, shp2wpkh_xpub_external, bip32_account, f) =
            parse_single_sig_descriptor(&shp2wpkh, coin_type).unwrap();
        assert_eq!(t, ScriptType::P2shP2wpkh);
        assert_eq!(bip32_account, 0);
        assert_eq!(f, Fingerprint::default());
        let (t, shp2wpkh_xpub_internal, bip32_account, f) =
            parse_single_sig_descriptor(&shp2wpkh_change, coin_type).unwrap();
        assert_eq!(t, ScriptType::P2shP2wpkh);
        assert_eq!(bip32_account, 0);
        assert_eq!(f, Fingerprint::default());
        let (t, p2wpkh_xpub, bip32_account, f) =
            parse_single_sig_descriptor(&p2wpkh, coin_type).unwrap();
        assert_eq!(t, ScriptType::P2wpkh);
        assert_eq!(bip32_account, 0);
        assert_eq!(f, Fingerprint::default());
        let (t, p2wpkh_xpub_1, bip32_account, f) =
            parse_single_sig_descriptor(&p2wpkh_1, coin_type).unwrap();
        assert_eq!(t, ScriptType::P2wpkh);
        assert_eq!(bip32_account, 1);
        assert_eq!(f, Fingerprint::default());
        let (t, p2pkh_xpub, bip32_account, f) =
            parse_single_sig_descriptor(&p2pkh, coin_type).unwrap();
        assert_eq!(t, ScriptType::P2pkh);
        assert_eq!(bip32_account, 0);
        assert_eq!(f, Fingerprint::default());

        // Invalid cases
        let err_str = Error::UnsupportedDescriptor.to_string();
        let f = |(s, t)| parse_single_sig_descriptor(s, t).unwrap_err().to_string();
        assert_eq!(f((tpub, coin_type)), err_str);
        assert_eq!(f((tpub, 0)), err_str);
        assert_eq!(f((&shmulti, coin_type)), err_str);
        assert_eq!(f((&shp2wkh_no_wildcard, coin_type)), err_str);
        assert_eq!(f((&shp2wkh_no_key_origin, coin_type)), err_str);
        assert_eq!(f((&p2wpkh_inc, coin_type)), err_str);
        assert_eq!(f((&p2wpkh_incorrect_key_origin1, coin_type)), err_str);
        assert_eq!(f((&p2wpkh_incorrect_key_origin2, coin_type)), err_str);

        // Note that external and internal descriptors yield to the same xpub
        assert_eq!(shp2wpkh_xpub_external.to_string(), tpub);
        assert_eq!(shp2wpkh_xpub_internal.to_string(), tpub);
        assert_eq!(p2wpkh_xpub.to_string(), tpub);
        assert_eq!(p2wpkh_xpub_1.to_string(), tpub_1);
        assert_eq!(p2pkh_xpub.to_string(), tpub);
    }
}
