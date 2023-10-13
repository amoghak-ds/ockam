use sqlx::*;

use ockam_core::async_trait;
use ockam_core::compat::sync::Arc;
use ockam_core::compat::vec::Vec;
use ockam_core::Result;
use ockam_identity::database::{FromSqlxError, SqlxDatabase, SqlxType, ToSqlxType, ToVoid};

use crate::{Action, Expr, PoliciesRepository, Resource};

#[derive(Clone)]
pub struct PolicySqlxDatabase {
    database: Arc<SqlxDatabase>,
}

impl PolicySqlxDatabase {
    /// Create a new database for policies keys
    pub fn new(database: Arc<SqlxDatabase>) -> Self {
        Self { database }
    }

    /// Create a new in-memory database for policies
    pub fn create() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(SqlxDatabase::in_memory())))
    }
}

#[async_trait]
impl PoliciesRepository for PolicySqlxDatabase {
    async fn get_policy(&self, resource: &Resource, action: &Action) -> Result<Option<Expr>> {
        let query = query_as("SELECT * FROM policy WHERE resource=$1 and action=$2")
            .bind(resource.to_sql())
            .bind(action.to_sql());
        let row: Option<PolicyRow> = query
            .fetch_optional(&self.database.pool)
            .await
            .into_core()?;
        Ok(row.map(|r| r.expression()).transpose()?)
    }

    async fn set_policy(
        &self,
        resource: &Resource,
        action: &Action,
        expression: &Expr,
    ) -> Result<()> {
        let query = query("INSERT OR REPLACE INTO policy VALUES (?, ?, ?)")
            .bind(resource.to_sql())
            .bind(action.to_sql())
            .bind(minicbor::to_vec(expression)?.to_sql());
        query.execute(&self.database.pool).await.void()
    }

    async fn delete_policy(&self, resource: &Resource, action: &Action) -> Result<()> {
        let query = query("DELETE FROM policy WHERE resource = ? and action = ?")
            .bind(resource.to_sql())
            .bind(action.to_sql());
        query.execute(&self.database.pool).await.void()
    }

    async fn get_policies_by_resource(&self, resource: &Resource) -> Result<Vec<(Action, Expr)>> {
        let query = query_as("SELECT * FROM policy where resource = $1").bind(resource.to_sql());
        let row: Vec<PolicyRow> = query.fetch_all(&self.database.pool).await.into_core()?;
        row.into_iter()
            .map(|r| r.expression().map(|e| (r.action(), e)))
            .collect::<Result<Vec<(Action, Expr)>>>()
    }
}

impl ToSqlxType for Resource {
    fn to_sql(&self) -> SqlxType {
        SqlxType::Text(self.as_str().to_string())
    }
}

impl ToSqlxType for Action {
    fn to_sql(&self) -> SqlxType {
        SqlxType::Text(self.as_str().to_string())
    }
}

#[derive(FromRow)]
pub(crate) struct PolicyRow {
    resource: String,
    action: String,
    expression: Vec<u8>,
}

impl PolicyRow {
    #[allow(dead_code)]
    pub(crate) fn resource(&self) -> Resource {
        Resource::from(self.resource.clone())
    }

    pub(crate) fn action(&self) -> Action {
        Action::from(self.action.clone())
    }

    pub(crate) fn expression(&self) -> Result<Expr> {
        Ok(minicbor::decode(self.expression.as_slice())?)
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;
    use std::path::Path;

    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn test_repository() -> Result<()> {
        let file = NamedTempFile::new().unwrap();
        let repository = create_repository(file.path()).await?;

        let r = Resource::from("1");
        let a = Action::from("2");
        let e = Expr::from_str("345")?;
        repository.set_policy(&r, &a, &e).await?;
        assert!(
            repository.get_policy(&r, &a).await?.unwrap().equals(&e)?,
            "Verify set and get"
        );

        let policies = repository.get_policies_by_resource(&r).await?;
        assert_eq!(policies.len(), 1);

        let a = Action::from("3");
        repository.set_policy(&r, &a, &e).await?;
        let policies = repository.get_policies_by_resource(&r).await?;
        assert_eq!(policies.len(), 2);

        repository.delete_policy(&r, &a).await?;
        let policies = repository.get_policies_by_resource(&r).await?;
        assert_eq!(policies.len(), 1);

        Ok(())
    }

    /// HELPERS
    async fn create_repository(path: &Path) -> Result<Arc<dyn PoliciesRepository>> {
        let db = SqlxDatabase::create(path).await?;
        Ok(Arc::new(PolicySqlxDatabase::new(Arc::new(db))))
    }
}
