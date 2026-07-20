use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

const MAX_TOKEN_BYTES: usize = 255;

/// Error returned when a protocol token is empty, oversized, or unsafe.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TokenError {
    /// The token was empty.
    #[error("token must not be empty")]
    Empty,
    /// The token exceeded the protocol limit.
    #[error("token is {actual} bytes; maximum is {limit}")]
    TooLong {
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Maximum permitted byte length.
        limit: usize,
    },
    /// The token contained a character outside the stable token alphabet.
    #[error("token contains invalid character {character:?} at byte {index}")]
    InvalidCharacter {
        /// Byte offset of the invalid character.
        index: usize,
        /// Invalid character.
        character: char,
    },
}

fn validate_token(value: &str) -> Result<(), TokenError> {
    if value.is_empty() {
        return Err(TokenError::Empty);
    }
    if value.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::TooLong {
            actual: value.len(),
            limit: MAX_TOKEN_BYTES,
        });
    }
    for (index, character) in value.char_indices() {
        if !(character.is_ascii_alphanumeric()
            || matches!(character, '.' | '_' | '-' | ':' | '/' | '@'))
        {
            return Err(TokenError::InvalidCharacter { index, character });
        }
    }
    Ok(())
}

macro_rules! token_type {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        $(#[$meta])*
        #[doc = $description]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated token.
            ///
            /// # Errors
            ///
            /// Returns [`TokenError`] when the value is empty, longer than 255
            /// bytes, or contains a character outside the stable ASCII token
            /// alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
                let value = value.into();
                validate_token(&value)?;
                Ok(Self(value))
            }

            /// Returns the token text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes this token and returns its text.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = TokenError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

token_type!(RequestId, "NQ-owned identity of one collection request.");
token_type!(
    InstanceId,
    "NQ-owned identity of one deployed watcher instance."
);
token_type!(ProfileId, "Stable identity of a compiled semantic profile.");
token_type!(
    ProfileVersion,
    "Exact version of a compiled semantic profile."
);
token_type!(SubjectId, "Profile-validated subject identity.");
token_type!(ObservationKind, "Profile-controlled observation kind.");
token_type!(CoverageKind, "Profile-controlled coverage dimension.");
token_type!(
    Capability,
    "Named execution capability granted to a helper."
);
token_type!(
    ImplementationName,
    "Untrusted helper implementation lineage name."
);
token_type!(ScopeKind, "Profile-controlled scope binding kind.");
token_type!(VantageKind, "Profile-controlled vantage binding kind.");
token_type!(
    ErrorCode,
    "Profile-controlled structured report error code."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_accepts_stable_ascii_vocabulary() {
        let value = ProfileId::new("nq.smart/device@host:1").expect("valid token");
        assert_eq!(value.as_str(), "nq.smart/device@host:1");
    }

    #[test]
    fn token_rejects_whitespace() {
        let error = ProfileId::new("nq smart").expect_err("space must fail");
        assert!(matches!(error, TokenError::InvalidCharacter { .. }));
    }
}
