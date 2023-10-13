use std::str::FromStr;
use std::sync::Arc;

use sqlx::sqlite::SqliteRow;
use sqlx::FromRow;
use sqlx::*;
use time::OffsetDateTime;

use ockam::identity::Identifier;
use ockam::{FromSqlxError, SqlxDatabase, ToSqlxType, ToVoid};
use ockam_core::async_trait;

use crate::cli_state::CliState;
use crate::cli_state::Result;

impl CliState {
    pub async fn is_default_identity_enrolled(&self) -> Result<bool> {
        self.enrollment_repository()
            .await?
            .is_default_identity_enrolled()
            .await
    }

    pub async fn get_identity_enrollments(
        &self,
        enrollment_status: EnrollmentStatus,
    ) -> Result<Vec<IdentityEnrollment>> {
        let repository = self.enrollment_repository().await?;
        match enrollment_status {
            EnrollmentStatus::Enrolled => repository.get_enrolled_identities().await,
            EnrollmentStatus::Any => repository.get_all_identities_enrollments().await,
        }
    }
}

#[async_trait]
pub trait EnrollmentsRepository {
    async fn enroll_identity(&self, identifier: &Identifier) -> Result<()>;
    async fn get_enrolled_identities(&self) -> Result<Vec<IdentityEnrollment>>;
    async fn get_all_identities_enrollments(&self) -> Result<Vec<IdentityEnrollment>>;
    async fn is_default_identity_enrolled(&self) -> Result<bool>;
}

pub struct EnrollmentsSqlxDatabase {
    database: Arc<SqlxDatabase>,
}

impl EnrollmentsSqlxDatabase {
    pub fn new(database: Arc<SqlxDatabase>) -> Self {
        Self { database }
    }

    /// Create a new in-memory database
    pub fn create() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(SqlxDatabase::in_memory())))
    }
}

#[async_trait]
impl EnrollmentsRepository for EnrollmentsSqlxDatabase {
    async fn enroll_identity(&self, identifier: &Identifier) -> Result<()> {
        let query = query("INSERT OR REPLACE INTO identity_enrollment VALUES (?, ?)")
            .bind(identifier.to_sql())
            .bind(OffsetDateTime::now_utc().to_sql());
        Ok(query.execute(&self.database.pool).await.void()?)
    }

    async fn get_enrolled_identities(&self) -> Result<Vec<IdentityEnrollment>> {
        let query = query_as(
            r#"
            SELECT
              identity.identifier, identity.name,
              identity_enrollment.enrolled_at
            FROM identity
            INNER JOIN identity_enrollment ON
              identity.identifier = identity_enrollment.identifier
            "#,
        )
        .bind(None as Option<i64>);
        let result: Vec<EnrollmentRow> = query.fetch_all(&self.database.pool).await.into_core()?;
        result
            .into_iter()
            .map(|r| r.identity_enrollment())
            .collect::<Result<Vec<_>>>()
    }

    async fn get_all_identities_enrollments(&self) -> Result<Vec<IdentityEnrollment>> {
        let query = query_as(
            r#"
            SELECT
              identity.identifier, identity.name,
              identity_enrollment.enrolled_at
            FROM identity
            LEFT JOIN identity_enrollment ON
              identity.identifier = identity_enrollment.identifier
            "#,
        );
        let result: Vec<EnrollmentRow> = query.fetch_all(&self.database.pool).await.into_core()?;
        result
            .into_iter()
            .map(|r| r.identity_enrollment())
            .collect::<Result<Vec<_>>>()
    }

    async fn is_default_identity_enrolled(&self) -> Result<bool> {
        let query = query(
            r#"
            SELECT
              identity_enrollment.enrolled_at
            FROM identity
            INNER JOIN identity_enrollment ON
              identity.identifier = identity_enrollment.identifier AND
              identity.is_default = ?
            "#,
        )
        .bind(true.to_sql());
        let result: Option<SqliteRow> = query
            .fetch_optional(&self.database.pool)
            .await
            .into_core()?;
        Ok(result.map(|_| true).unwrap_or(false))
    }
}

pub enum EnrollmentStatus {
    Enrolled,
    Any,
}

pub struct IdentityEnrollment {
    identifier: Identifier,
    name: Option<String>,
    enrolled_at: Option<OffsetDateTime>,
}

impl IdentityEnrollment {
    pub fn identifier(&self) -> Identifier {
        self.identifier.clone()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }

    #[allow(dead_code)]
    pub fn enrolled_at(&self) -> Option<OffsetDateTime> {
        self.enrolled_at
    }
}

#[derive(FromRow)]
pub struct EnrollmentRow {
    identifier: String,
    name: Option<String>,
    enrolled_at: Option<i64>,
}

impl EnrollmentRow {
    fn identity_enrollment(&self) -> Result<IdentityEnrollment> {
        let identifier = Identifier::from_str(self.identifier.as_str())?;
        Ok(IdentityEnrollment {
            identifier,
            name: self.name.clone(),
            enrolled_at: self.enrolled_at(),
        })
    }

    fn enrolled_at(&self) -> Option<OffsetDateTime> {
        self.enrolled_at
            .map(|at| OffsetDateTime::from_unix_timestamp(at).unwrap_or(OffsetDateTime::now_utc()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::NamedTempFile;

    use ockam::identity::models::ChangeHistory;
    use ockam::identity::{IdentitiesRepository, IdentitiesSqlxDatabase, Identity, Vault};

    use super::*;

    #[tokio::test]
    async fn test_identities_enrollment_repository() -> Result<()> {
        let db_file = NamedTempFile::new().unwrap();
        let identity1 = create_identity1(db_file.path(), "identity1").await?;
        create_identity2(db_file.path(), "identity2").await?;
        let repository = create_repository(db_file.path()).await?;

        // an identity can be enrolled
        repository.enroll_identity(identity1.identifier()).await?;

        // retrieve the identities and their enrollment status
        let result = repository.get_all_identities_enrollments().await?;
        assert_eq!(result.len(), 2);

        // retrieve only the enrolled identities
        let result = repository.get_enrolled_identities().await?;
        assert_eq!(result.len(), 1);

        // the first identity has been set as the default one
        let result = repository.is_default_identity_enrolled().await?;
        assert!(result);

        Ok(())
    }

    /// HELPERS
    async fn create_identity1(path: &Path, name: &str) -> Result<Identity> {
        let change_history = ChangeHistory::import(&hex::decode("81a201583ba20101025835a4028201815820530d1c2e9822433b679a66a60b9c2ed47c370cd0ce51cbe1a7ad847b5835a96303f4041a64dd4060051a77a94360028201815840042fff8f6c80603fb1cec4a3cf1ff169ee36889d3ed76184fe1dfbd4b692b02892df9525c61c2f1286b829586d13d5abf7d18973141f734d71c1840520d40a0e").unwrap())?;
        let identity = Identity::import_from_change_history(
            None,
            change_history,
            Vault::create_verifying_vault(),
        )
        .await
        .unwrap();
        store_identity(path, name, identity).await
    }

    async fn create_identity2(path: &Path, name: &str) -> Result<Identity> {
        let change_history = ChangeHistory::import(&hex::decode("81a201583ba20101025835a4028201815820afbca9cf5d440147450f9f0d0a038a337b3fe5c17086163f2c54509558b62ef403f4041a64dd404a051a77a9434a0282018158407754214545cda6e7ff49136f67c9c7973ec309ca4087360a9f844aac961f8afe3f579a72c0c9530f3ff210f02b7c5f56e96ce12ee256b01d7628519800723805").unwrap())?;
        let identity = Identity::import_from_change_history(
            None,
            change_history,
            Vault::create_verifying_vault(),
        )
        .await
        .unwrap();
        store_identity(path, name, identity).await
    }

    async fn store_identity(path: &Path, name: &str, identity: Identity) -> Result<Identity> {
        let identities_repository = create_identities_repository(path).await?;
        identities_repository.store_identity(&identity).await?;
        identities_repository
            .name_identity(identity.identifier(), name)
            .await?;
        if name == "identity1" {
            identities_repository
                .set_as_default(identity.identifier())
                .await?;
        }
        Ok(identity)
    }

    async fn create_repository(path: &Path) -> Result<Arc<dyn EnrollmentsRepository>> {
        let db = SqlxDatabase::create(path).await?;
        Ok(Arc::new(EnrollmentsSqlxDatabase::new(Arc::new(db))))
    }

    async fn create_identities_repository(path: &Path) -> Result<Arc<dyn IdentitiesRepository>> {
        let db = SqlxDatabase::create(path).await?;
        Ok(Arc::new(IdentitiesSqlxDatabase::new(Arc::new(db))))
    }
}
