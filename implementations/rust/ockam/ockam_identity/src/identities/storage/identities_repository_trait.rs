use ockam_core::compat::sync::Arc;
use ockam_core::compat::vec::Vec;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::Result;
use ockam_core::{async_trait, Error};

use crate::models::{ChangeHistory, Identifier};
use crate::{AttributesEntry, Identity};

/// Repository for data related to identities: key changes and attributes
#[async_trait]
pub trait IdentitiesRepository:
    IdentityAttributesReader + IdentityAttributesWriter + IdentitiesReader + IdentitiesWriter
{
    /// Restrict this repository as a reader for attributes
    fn as_attributes_reader(&self) -> Arc<dyn IdentityAttributesReader>;

    /// Restrict this repository as a writer for attributes
    fn as_attributes_writer(&self) -> Arc<dyn IdentityAttributesWriter>;

    /// Restrict this repository as a reader for identities
    fn as_identities_reader(&self) -> Arc<dyn IdentitiesReader>;

    /// Restrict this repository as a writer for identities
    fn as_identities_writer(&self) -> Arc<dyn IdentitiesWriter>;
}

/// Trait implementing read access to attributes
#[async_trait]
pub trait IdentityAttributesReader: Send + Sync + 'static {
    /// Get the attributes associated with the given identity identifier
    async fn get_attributes(&self, identity: &Identifier) -> Result<Option<AttributesEntry>>;

    /// List all identities with their attributes
    async fn list(&self) -> Result<Vec<(Identifier, AttributesEntry)>>;
}

/// Trait implementing write access to attributes
#[async_trait]
pub trait IdentityAttributesWriter: Send + Sync + 'static {
    /// Set the attributes associated with the given identity identifier.
    /// Previous values gets overridden.
    async fn put_attributes(&self, identity: &Identifier, entry: AttributesEntry) -> Result<()>;

    /// Store an attribute name/value pair for a given identity
    async fn put_attribute_value(
        &self,
        subject: &Identifier,
        attribute_name: Vec<u8>,
        attribute_value: Vec<u8>,
    ) -> Result<()>;

    /// Remove all attributes for a given identity identifier
    async fn delete(&self, identity: &Identifier) -> Result<()>;
}

/// Trait implementing write access to identities
#[async_trait]
pub trait IdentitiesWriter: Send + Sync + 'static {
    /// Store changes if there are new key changes associated to that identity
    async fn store_identity(&self, identity: &Identity) -> Result<()>;

    /// Associate a name to an identity
    async fn name_identity(&self, identifier: &Identifier, name: &str) -> Result<()>;

    /// Set an identity as the default one
    async fn set_as_default(&self, identifier: &Identifier) -> Result<()>;

    /// Set an identity as the default one, given its name
    async fn set_as_default_by_name(&self, name: &str) -> Result<()>;

    /// Store changes if there are new key changes associated to that identity
    async fn update_identity(&self, identity: &Identity) -> Result<()>;

    /// Delete an identity given its identifier
    async fn delete_identity(&self, identifier: &Identifier) -> Result<()>;

    /// Delete an identity given its name
    async fn delete_identity_by_name(&self, name: &str) -> Result<()>;
}

/// Trait implementing read access to identities
#[async_trait]
pub trait IdentitiesReader: Send + Sync + 'static {
    /// Return the change history of a persisted identity
    async fn get_change_history_optional(
        &self,
        identifier: &Identifier,
    ) -> Result<Option<ChangeHistory>>;

    /// Return the change history of a persisted identity
    async fn get_change_history(&self, identifier: &Identifier) -> Result<ChangeHistory> {
        match self.get_change_history_optional(identifier).await? {
            Some(change_history) => Ok(change_history),
            None => Err(Error::new(
                Origin::Core,
                Kind::NotFound,
                format!("identity not found for identifier {}", identifier),
            )),
        }
    }

    /// Return the identifier associated to a named identity
    async fn get_identifier_by_name(&self, name: &str) -> Result<Option<Identifier>>;

    /// Return the default identifier if there is one
    async fn get_default_identifier(&self) -> Result<Option<Identifier>>;

    /// Return identities which are associated with a name
    async fn get_named_identities(&self) -> Result<Vec<NamedIdentity>>;

    /// Return the named identity with a specific name
    async fn get_named_identity(&self, name: &str) -> Result<Option<NamedIdentity>>;

    /// Return the default named identity
    async fn get_default_named_identity(&self) -> Result<Option<NamedIdentity>>;

    /// Return the name of the default identity if there is one
    async fn get_default_identity_name(&self) -> Result<Option<String>>;

    /// Return true if there is an identity with this name and it is the default one
    async fn is_default_identity_by_name(&self, name: &str) -> Result<bool>;
}

/// A named identity associates a name with a persisted identity.
/// This is a convenience for users since they can refer to an identity by the name "alice"
/// instead of the identifier "I1234561234561234561234561234561234561234"
///
/// Additionally one identity can be marked as being the default identity and taken to
/// establish a secure channel or create credentials without having to specify it.
pub struct NamedIdentity {
    identifier: Identifier,
    change_history: ChangeHistory,
    name: String,
    is_default: bool,
}

impl NamedIdentity {
    /// Create a new named identity
    pub fn new(
        identifier: Identifier,
        change_history: ChangeHistory,
        name: String,
        is_default: bool,
    ) -> Self {
        Self {
            identifier,
            change_history,
            name,
            is_default,
        }
    }

    /// Return the identity identifier
    pub fn identifier(&self) -> Identifier {
        self.identifier.clone()
    }

    /// Return the identity change history
    pub fn change_history(&self) -> ChangeHistory {
        self.change_history.clone()
    }

    /// Return the identity name
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Return true if this identity is the default one
    pub fn is_default(&self) -> bool {
        self.is_default
    }
}
