use std::fmt;

// This doesn't do validation, but we could?
pub struct Password(String);

impl Password {
    // to_string would display REDACTED from the Display trait
    pub fn get_password_str(self) -> String {
        self.0
    }
}

impl serde::ser::Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("Password(REDACTED)")
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Password(REDACTED)")
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        Password(s)
    }
}

#[test]
fn password_show_redacted() {
    let mnemonic = Password("secret sauce".into());
    let format = format!("{}", mnemonic);

    assert_eq!(format, "Password(REDACTED)");
    assert_eq!(mnemonic.get_password_str(), "secret sauce");
}
