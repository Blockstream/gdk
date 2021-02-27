use bitcoin::hashes::hex::ToHex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum BEScript {
    Bitcoin(bitcoin::Script),
    Elements(elements::Script),
}

impl BEScript {
    pub fn to_hex(&self) -> String {
        match self {
            Self::Bitcoin(script) => script.to_hex(),
            Self::Elements(script) => script.to_hex(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Bitcoin(script) => script.is_empty(),
            Self::Elements(script) => script.is_empty(),
        }
    }
    pub fn ref_bitcoin(&self) -> Option<&bitcoin::Script> {
        match self {
            Self::Bitcoin(script) => Some(script),
            Self::Elements(_) => None,
        }
    }
    pub fn ref_elements(&self) -> Option<&elements::Script> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(script) => Some(script),
        }
    }
}

pub trait BEScriptConvert {
    fn into_bitcoin(self) -> bitcoin::Script;
    fn into_elements(self) -> elements::Script;
    fn into_be(self) -> BEScript;
}

impl BEScriptConvert for BEScript {
    fn into_bitcoin(self) -> bitcoin::Script {
        match self {
            Self::Bitcoin(script) => script,
            Self::Elements(script) => script.into_bitcoin(),
        }
    }
    fn into_elements(self) -> elements::Script {
        match self {
            Self::Bitcoin(script) => script.into_elements(),
            Self::Elements(script) => script,
        }
    }
    fn into_be(self) -> Self {
        self
    }
}

impl BEScriptConvert for bitcoin::Script {
    fn into_bitcoin(self) -> bitcoin::Script {
        self
    }
    fn into_elements(self) -> elements::Script {
        elements::Script::from(self.into_bytes())
    }
    fn into_be(self) -> BEScript {
        self.into()
    }
}

impl BEScriptConvert for elements::Script {
    fn into_bitcoin(self) -> bitcoin::Script {
        bitcoin::Script::from(self.into_bytes())
    }
    fn into_elements(self) -> elements::Script {
        self
    }
    fn into_be(self) -> BEScript {
        self.into()
    }
}

impl BEScriptConvert for &elements::Script {
    fn into_bitcoin(self) -> bitcoin::Script {
        self.clone().into_bitcoin()
    }
    fn into_elements(self) -> elements::Script {
        self.clone().into_elements()
    }
    fn into_be(self) -> BEScript {
        self.clone().into()
    }
}

impl BEScriptConvert for &bitcoin::Script {
    fn into_bitcoin(self) -> bitcoin::Script {
        self.clone().into_bitcoin()
    }
    fn into_elements(self) -> elements::Script {
        self.clone().into_elements()
    }
    fn into_be(self) -> BEScript {
        self.clone().into()
    }
}

impl ToString for BEScript {
    fn to_string(&self) -> String {
        match self {
            BEScript::Bitcoin(script) => script.to_string(),
            BEScript::Elements(script) => script.to_string(),
        }
    }
}

impl From<bitcoin::Script> for BEScript {
    fn from(script: bitcoin::Script) -> BEScript {
        BEScript::Bitcoin(script)
    }
}

impl From<elements::Script> for BEScript {
    fn from(script: elements::Script) -> BEScript {
        BEScript::Elements(script)
    }
}
impl From<&bitcoin::Script> for BEScript {
    fn from(script: &bitcoin::Script) -> BEScript {
        script.clone().into()
    }
}

impl From<&elements::Script> for BEScript {
    fn from(script: &elements::Script) -> BEScript {
        script.clone().into()
    }
}
