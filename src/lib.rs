use std::fmt::{Display, Formatter};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::digest::Update;
use sha2::{Digest, Sha256};

#[derive(Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "sqlx_0_7_4", derive(sqlx_0_7_4::FromRow))]
pub struct HashedPassword(String);

impl HashedPassword {
    fn salt() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect()
    }

    fn hash<T: AsRef<[u8]>>(s: T) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_ref());
        let result = hasher.finalize();
        let result = &result[..];

        hex::encode(result)
    }

    /// convert `plain` to [HashedPassword], with `secret`
    pub fn from_plain<T: AsRef<str>, S: AsRef<[u8]>>(plain: T, secret: S) -> Self {
        let salt = Self::salt();
        Self::hash_with_salt(plain, secret, salt)
    }

    fn hash_with_salt<T, S, V>(plain: T, secret: S, salt: V) -> Self
    where
        T: AsRef<str>,
        S: AsRef<[u8]>,
        V: AsRef<str>,
    {
        let row = format!("{}{}{}", salt.as_ref(), plain.as_ref(), hex::encode(secret));
        let hash = Self::hash(&row);

        Self(format!("{}${}", salt, hash))
    }

    /// To validate `plain` is the plain password or not.
    pub fn validate<T: AsRef<str>, S: AsRef<[u8]>>(&self, plain: T, secret: S) -> bool {
        let plain = plain.as_ref();
        let mut split = plain.splitn(2, '$');

        let (size, _) = split.size_hint();
        if size != 2 {
            // invalid hashed password
            return false;
        }

        let salt = split.next().unwrap(); // safe unwrap
        let hash = split.next().unwrap(); // safe unwrap

        let result = Self::hash_with_salt(plain, secret, salt);
        result.0 == hash
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for HashedPassword {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }    
}
