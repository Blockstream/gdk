use core::fmt;

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Disconnected,
    Connected,
}

impl From<bool> for State {
    fn from(b: bool) -> Self {
        if b {
            State::Connected
        } else {
            State::Disconnected
        }
    }
}

impl From<State> for bool {
    fn from(s: State) -> Self {
        match s {
            State::Connected => true,
            State::Disconnected => false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            State::Disconnected => write!(f, "disconnected"),
            State::Connected => write!(f, "connected"),
        }
    }
}
