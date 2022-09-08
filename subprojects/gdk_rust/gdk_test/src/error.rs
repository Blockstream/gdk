pub type Result<T> = std::result::Result<T, Error>;

pub type Error = Box<dyn std::error::Error>;
