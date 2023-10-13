use core::str::FromStr;

use sqlx::*;

use ockam_core::async_trait;
use ockam_core::compat::string::{String, ToString};
use ockam_core::compat::sync::Arc;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::Result;

use crate::database::{FromSqlxError, SqlxDatabase, SqlxType, ToSqlxType, ToVoid};
use crate::identity::IdentityConstants;
use crate::models::{Identifier, PurposeKeyAttestation};
use crate::purpose_keys::storage::{PurposeKeysReader, PurposeKeysRepository, PurposeKeysWriter};
use crate::Purpose;

/// Storage for own [`super::super::super::purpose_key::PurposeKey`]s
#[derive(Clone)]
pub struct PurposeKeysSqlxDatabase {
    database: Arc<SqlxDatabase>,
}

#[async_trait]
impl PurposeKeysRepository for PurposeKeysSqlxDatabase {
    fn as_reader(&self) -> Arc<dyn PurposeKeysReader> {
        Arc::new(self.clone())
    }

    fn as_writer(&self) -> Arc<dyn PurposeKeysWriter> {
        Arc::new(self.clone())
    }
}

impl PurposeKeysSqlxDatabase {
    /// Create a new database for purpose keys
    pub fn new(database: Arc<SqlxDatabase>) -> Self {
        Self { database }
    }

    /// Create a new in-memory database for purpose keys
    pub fn create() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(SqlxDatabase::in_memory())))
    }
}

#[async_trait]
impl PurposeKeysWriter for PurposeKeysSqlxDatabase {
    async fn set_purpose_key(
        &self,
        subject: &Identifier,
        purpose: Purpose,
        purpose_key_attestation: &PurposeKeyAttestation,
    ) -> Result<()> {
        let query = query("INSERT OR REPLACE INTO purpose_key VALUES (?, ?, ?)")
            .bind(subject.to_sql())
            .bind(purpose.to_sql())
            .bind(minicbor::to_vec(purpose_key_attestation)?.to_sql());
        query.execute(&self.database.pool).await.void()
    }

    async fn delete_purpose_key(&self, subject: &Identifier, purpose: Purpose) -> Result<()> {
        let query = query("DELETE FROM purpose_key WHERE identifier = ? and purpose = ?")
            .bind(subject.to_sql())
            .bind(purpose.to_sql());
        query.execute(&self.database.pool).await.void()
    }
}

#[async_trait]
impl PurposeKeysReader for PurposeKeysSqlxDatabase {
    async fn retrieve_purpose_key(
        &self,
        identifier: &Identifier,
        purpose: Purpose,
    ) -> Result<Option<PurposeKeyAttestation>> {
        let query = query_as("SELECT * FROM purpose_key WHERE identifier=$1 and purpose=$2")
            .bind(identifier.to_sql())
            .bind(purpose.to_sql());
        let row: Option<PurposeKeyRow> = query
            .fetch_optional(&self.database.pool)
            .await
            .into_core()?;
        Ok(row.map(|r| r.purpose_key_attestation()).transpose()?)
    }
}

#[derive(FromRow)]
pub(crate) struct PurposeKeyRow {
    // The identifier who is using this key
    identifier: String,
    // Purpose of the key (signing, encrypting, etc...)
    purpose: String,
    // Attestation that this key is valid
    purpose_key_attestation: Vec<u8>,
}

impl PurposeKeyRow {
    #[allow(dead_code)]
    pub(crate) fn identifier(&self) -> Result<Identifier> {
        Identifier::from_str(&self.identifier)
    }

    #[allow(dead_code)]
    pub(crate) fn purpose(&self) -> Result<Purpose> {
        match self.purpose.as_str() {
            IdentityConstants::SECURE_CHANNEL_PURPOSE_KEY => Ok(Purpose::SecureChannel),
            IdentityConstants::CREDENTIALS_PURPOSE_KEY => Ok(Purpose::Credentials),
            _ => Err(ockam_core::Error::new(
                Origin::Api,
                Kind::Serialization,
                format!("unknown purpose {}", self.purpose),
            )),
        }
    }

    pub(crate) fn purpose_key_attestation(&self) -> Result<PurposeKeyAttestation> {
        Ok(minicbor::decode(self.purpose_key_attestation.as_slice())?)
    }
}

impl ToSqlxType for Purpose {
    fn to_sql(&self) -> SqlxType {
        match self {
            Purpose::SecureChannel => {
                SqlxType::Text(IdentityConstants::SECURE_CHANNEL_PURPOSE_KEY.to_string())
            }
            Purpose::Credentials => {
                SqlxType::Text(IdentityConstants::CREDENTIALS_PURPOSE_KEY.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::NamedTempFile;

    use ockam_vault::ECDSASHA256CurveP256Signature;

    use crate::models::PurposeKeyAttestationSignature;

    use super::*;

    #[tokio::test]
    async fn test_purpose_keys_repository() -> Result<()> {
        let db_file = NamedTempFile::new().unwrap();
        let repository = create_repository(db_file.path()).await?;

        let identity1 = Identifier::try_from("Ie86be15e83d1c93e24dd1967010b01b6df491b45").unwrap();

        // A purpose key can be stored and retrieved
        let attestation = PurposeKeyAttestation {
            data: vec![1, 2, 3],
            signature: PurposeKeyAttestationSignature::ECDSASHA256CurveP256(
                ECDSASHA256CurveP256Signature([1; 64]),
            ),
        };
        repository
            .set_purpose_key(&identity1, Purpose::Credentials, &attestation)
            .await?;

        let result = repository
            .get_purpose_key(&identity1, Purpose::Credentials)
            .await?;
        assert_eq!(result, attestation);

        Ok(())
    }

    /// HELPERS
    async fn create_repository(path: &Path) -> Result<Arc<dyn PurposeKeysRepository>> {
        let db = SqlxDatabase::create(path).await?;
        Ok(Arc::new(PurposeKeysSqlxDatabase::new(Arc::new(db))))
    }
}
