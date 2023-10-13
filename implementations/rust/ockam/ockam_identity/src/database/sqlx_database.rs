use std::ops::Deref;
use std::path::Path;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, SqlitePool};
use tokio_retry::strategy::{jitter, FixedInterval};
use tokio_retry::Retry;
use tracing::debug;
use tracing::log::LevelFilter;

use ockam_core::errcode::{Kind, Origin};
use ockam_core::{Error, Result};

/// We use sqlx as our primary interface for interacting with the database
/// The database driver is currently Sqlite
pub struct SqlxDatabase {
    /// Pool of connections to the database
    pub pool: SqlitePool,
}

impl Deref for SqlxDatabase {
    type Target = SqlitePool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

impl SqlxDatabase {
    /// Constructor for a database persisted on disk
    pub async fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Not sure we need this
        // creating a new database might be failing a few times
        // if the files are currently being held by another pod which is shutting down.
        // In that case we retry a few times, between 1 and 10 seconds.
        let retry_strategy = FixedInterval::from_millis(1000)
            .map(jitter) // add jitter to delays
            .take(10); // limit to 10 retries

        Retry::spawn(retry_strategy, || async {
            Self::create_and_migrate(path.as_ref()).await
        })
        .await
    }

    /// Constructor for an in-memory database
    pub fn in_memory() -> Self {
        futures::executor::block_on(async {
            debug!("create an in memory database");
            let pool = Self::create_in_memory_connection_pool()
                .await
                .expect("creating an in-memory connection should work");
            let db = SqlxDatabase { pool };
            db.migrate().await.expect("the migration should work");
            db
        })
    }

    async fn create_and_migrate(path: &Path) -> Result<Self> {
        debug!("create a database at {}", path.display());
        // Creates database file if it doesn't exist
        let pool = Self::create_connection_pool(path).await?;
        let db = SqlxDatabase { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn create_connection_pool(path: &Path) -> Result<SqlitePool> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .log_statements(LevelFilter::Debug);
        let pool = SqlitePool::connect_with(options)
            .await
            .map_err(Self::map_sql_err)?;
        Ok(pool)
    }

    async fn create_in_memory_connection_pool() -> Result<SqlitePool> {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .map_err(Self::map_sql_err)?;
        Ok(pool)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./src/database/migrations")
            .run(&self.pool)
            .await
            .map_err(Self::map_migrate_err)
    }

    /// Map a sqlx error into an ockam error
    pub fn map_sql_err(err: sqlx::Error) -> Error {
        Error::new(Origin::Application, Kind::Io, err)
    }

    /// Map a sqlx migration error into an ockam error
    pub fn map_migrate_err(err: sqlx::migrate::MigrateError) -> Error {
        Error::new(Origin::Application, Kind::Io, err)
    }

    /// Map a minicbor decode error into an ockam error
    pub fn map_decode_err(err: minicbor::decode::Error) -> Error {
        Error::new(Origin::Application, Kind::Io, err)
    }
}

/// This trait provides some syntax for transforming sqlx errors into ockam errors
pub trait FromSqlxError<T> {
    /// Make an ockam core Error
    fn into_core(self) -> Result<T>;
}

impl<T> FromSqlxError<T> for core::result::Result<T, sqlx::error::Error> {
    fn into_core(self) -> Result<T> {
        self.map_err(|e| Error::new(Origin::Api, Kind::Internal, e.to_string()))
    }
}

/// This trait provides some syntax to shorten queries execution returning ()
pub trait ToVoid<T> {
    /// Return a () value
    fn void(self) -> Result<()>;
}

impl<T> ToVoid<T> for core::result::Result<T, sqlx::error::Error> {
    fn void(self) -> Result<()> {
        self.map(|_| ()).into_core()
    }
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqliteQueryResult;
    use sqlx::FromRow;
    use tempfile::NamedTempFile;

    use crate::database::ToSqlxType;

    use super::*;

    /// This is a sanity check to test that the database can be created with a file path
    /// and that migrations are running ok, at least for one table
    #[tokio::test]
    async fn test_create_identity_table() -> Result<()> {
        // let db = create_database().await?;
        // let inserted = insert_identity(&db).await.unwrap();
        let db_file = NamedTempFile::new().unwrap();
        let db = SqlxDatabase::create(db_file.path()).await?;

        let inserted = insert_identity(&db).await.unwrap();

        assert_eq!(inserted.rows_affected(), 1);
        Ok(())
    }

    /// This test checks that we can run a query and return an entity
    #[tokio::test]
    async fn test_query() -> Result<()> {
        let db_file = NamedTempFile::new().unwrap();
        let db = SqlxDatabase::create(db_file.path()).await?;

        insert_identity(&db).await.unwrap();

        // successful query
        let result: Option<IdentifierRow> =
            sqlx::query_as("SELECT identifier FROM identity WHERE identifier=?1")
                .bind("Ifa804b7fca12a19eed206ae180b5b576860ae651")
                .fetch_optional(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            result,
            Some(IdentifierRow(
                "Ifa804b7fca12a19eed206ae180b5b576860ae651".into()
            ))
        );

        // failed query
        let result: Option<IdentifierRow> =
            sqlx::query_as("SELECT identifier FROM identity WHERE identifier=?1")
                .bind("x")
                .fetch_optional(&db.pool)
                .await
                .unwrap();
        assert_eq!(result, None);
        Ok(())
    }

    /// HELPERS
    async fn insert_identity(db: &SqlxDatabase) -> Result<SqliteQueryResult> {
        Ok(sqlx::query("INSERT INTO identity VALUES (?1, ?2, ?3, ?4)")
            .bind("Ifa804b7fca12a19eed206ae180b5b576860ae651")
            .bind("123".as_bytes())
            .bind("123".to_sql())
            .bind(true.to_sql())
            .execute(&db.pool)
            .await
            .into_core()?)
    }

    #[derive(FromRow, PartialEq, Eq, Debug)]
    struct IdentifierRow(String);
}
