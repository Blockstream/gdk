use std::fmt;

// This doesn't do validation, but we could?
#[derive(Eq, Clone, PartialEq)]
pub struct Mnemonic(String);

impl Mnemonic {
    // to_string would display REDACTED from the Display trait
    pub fn get_mnemonic_str(self) -> String {
        self.0
    }
}

impl serde::ser::Serialize for Mnemonic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("Mnemonic(REDACTED)")
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic(REDACTED)")
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<String> for Mnemonic {
    fn from(s: String) -> Self {
        Mnemonic(s)
    }
}

#[test]
fn mnemonic_show_redacted() {
    let mnemonic = Mnemonic("secret sauce".into());
    let format = format!("{}", mnemonic);

    assert_eq!(format, "Mnemonic(REDACTED)");
    assert_eq!(mnemonic.get_mnemonic_str(), "secret sauce");
}
