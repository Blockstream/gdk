use super::BETxid;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum BEOutPoint {
    Bitcoin(bitcoin::OutPoint),
    Elements(elements::OutPoint),
}

impl From<bitcoin::OutPoint> for BEOutPoint {
    fn from(o: bitcoin::OutPoint) -> Self {
        BEOutPoint::new_bitcoin(o.txid, o.vout)
    }
}

impl From<elements::OutPoint> for BEOutPoint {
    fn from(o: elements::OutPoint) -> Self {
        BEOutPoint::new_elements(o.txid, o.vout)
    }
}

impl BEOutPoint {
    pub fn new_bitcoin(txid: bitcoin::Txid, vout: u32) -> Self {
        BEOutPoint::Bitcoin(bitcoin::OutPoint {
            txid,
            vout,
        })
    }

    pub fn new_elements(txid: elements::Txid, vout: u32) -> Self {
        BEOutPoint::Elements(elements::OutPoint {
            txid,
            vout,
        })
    }

    pub fn txid(&self) -> BETxid {
        match self {
            Self::Bitcoin(outpoint) => outpoint.txid.into(),
            Self::Elements(outpoint) => outpoint.txid.into(),
        }
    }

    pub fn vout(&self) -> u32 {
        match self {
            Self::Bitcoin(outpoint) => outpoint.vout,
            Self::Elements(outpoint) => outpoint.vout,
        }
    }
}
