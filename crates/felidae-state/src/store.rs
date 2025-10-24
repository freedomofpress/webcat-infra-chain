#![allow(unused)]

use cnidarium::{RootHash, Snapshot, StateDelta, StateRead, StateWrite, Storage};
use color_eyre::{Report, eyre};
use felidae_proto::DomainType;
use futures::{Stream, stream::StreamExt};
use std::any::Any;
use std::fmt::{Debug, Display};
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use tendermint::AppHash;
use tokio::sync::RwLock;

use crate::State;

#[derive(Debug, Clone)]
pub struct Store {
    pub storage: Storage,
    pub state: Arc<RwLock<State<StateDelta<Snapshot>>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Substore {
    Internal,
    Canonical,
}

pub struct RootHashes {
    pub internal: RootHash,
    pub canonical: RootHash,
    pub app_hash: AppHash,
}

impl Display for Substore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Substore::Internal => write!(f, "internal"),
            Substore::Canonical => write!(f, "canonical"),
        }
    }
}

impl Substore {
    pub fn prefix(&self, key: &str) -> String {
        format!("{}/{}", self, key)
    }

    pub fn prefix_bytes(&self, key: &[u8]) -> Vec<u8> {
        let mut prefix = format!("{}/", self).into_bytes();
        prefix.extend_from_slice(key);
        prefix
    }

    pub fn unprefix<'a>(&self, prefixed_key: &'a str) -> Option<&'a str> {
        let prefix = format!("{}/", self);
        prefixed_key.strip_prefix(&prefix)
    }

    pub fn unprefix_bytes<'a>(&self, prefixed_key: &'a [u8]) -> Option<&'a [u8]> {
        let prefix = format!("{}/", self).into_bytes();
        if prefixed_key.starts_with(&prefix) {
            Some(&prefixed_key[prefix.len()..])
        } else {
            None
        }
    }
}

impl Store {
    pub async fn init(path: PathBuf) -> Result<Self, Report> {
        tokio::fs::create_dir_all(&path)
            .await
            .or_else(|e| eyre::bail!("could not create storage directory: {e}"))?;
        const SUBSTORES: [&str; 2] = ["internal", "canonical"];
        let storage = Storage::init(path, SUBSTORES.map(Into::into).to_vec())
            .await
            .map_err(|e| eyre::eyre!(e))?;
        Ok(Self::new(storage))
    }

    fn new(storage: Storage) -> Self {
        Self {
            state: Arc::new(RwLock::new(State {
                store: StateDelta::new(storage.latest_snapshot()),
            })),
            storage,
        }
    }

    pub async fn root_hash(&self, substore: Option<Substore>) -> Result<RootHash, Report> {
        let snapshot = self.storage.latest_snapshot();
        if let Some(substore) = substore {
            snapshot.prefix_root_hash(&substore.to_string()).await
        } else {
            snapshot.root_hash().await
        }
        .map_err(|e| eyre::eyre!(e))
    }

    /// Get the 3 root hashes: internal, canonical, and app hash (hash of internal and canonical).
    pub async fn root_hashes(&self) -> Result<RootHashes, Report> {
        let internal = self.root_hash(Some(Substore::Internal)).await?;
        let canonical = self.root_hash(Some(Substore::Canonical)).await?;
        let app_hash = AppHash::try_from(self.root_hash(None).await?.0.to_vec())?;
        Ok(RootHashes {
            internal,
            canonical,
            app_hash,
        })
    }

    /// Commit all pending changes to the underlying storage.
    pub async fn commit(&mut self) -> Result<(), Report> {
        // Pull out the current state and replace it with a new, empty one:
        let state = mem::replace(
            &mut *self.state.write().await,
            State {
                store: StateDelta::new(self.storage.latest_snapshot()),
            },
        );

        // Commit the pulled-out delta to storage:
        self.storage
            .commit(state.store)
            .await
            .map_err(|e| eyre::eyre!(e))?;

        // Update the state to use the new latest snapshot:
        self.state.write().await.store = StateDelta::new(self.storage.latest_snapshot());

        // NOTE: without the final step above, the state would continue to refer to the snapshot
        // *before* the commit, which would lead to errors on subsequent reads/writes.

        Ok(())
    }

    /// Discard all pending changes.
    pub fn abort(&mut self) {
        self.state = Arc::new(RwLock::new(State {
            store: StateDelta::new(self.storage.latest_snapshot()),
        }));
    }

    /// Create a logical fork of the store.
    pub async fn fork(&mut self) -> Self {
        let fork = self.state.write().await.store.fork();
        Self {
            storage: self.storage.clone(),
            state: Arc::new(RwLock::new(State { store: fork })),
        }
    }
}

impl<T> StateReadExt for T where T: StateRead + Send + Sync + 'static {}

pub trait StateReadExt: StateRead + Send + Sync + 'static {
    /// Get a value from the state by key, decoding it into the given domain type.
    async fn get<V: DomainType>(&self, substore: Substore, key: &str) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .get_raw(&substore.prefix(key))
            .await
            .map_err(|e| eyre::eyre!(e))?;
        if let Some(bytes) = bytes {
            let v = V::decode(bytes.as_ref())?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    /// Get a stream over all keys in the state.
    async fn prefix_keys(
        &self,
        substore: Substore,
        prefix: &str,
    ) -> impl Stream<Item = Result<String, Report>> {
        StateRead::prefix_keys(self, &substore.prefix(prefix)).map(move |res| match res {
            Ok(key) => Ok(substore
                .unprefix(&key)
                .expect("key from wrong substore")
                .to_string()),
            Err(e) => Err(eyre::eyre!(e)),
        })
    }

    /// Get a stream over all key-value pairs in the state with the given prefix, decoding the
    /// values into the given domain type.
    async fn prefix<V: DomainType>(
        &self,
        substore: Substore,
        prefix: impl AsRef<str>,
    ) -> impl Stream<Item = Result<(String, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.prefix_raw(&substore.prefix(prefix.as_ref()))
            .map(move |res| match res {
                Ok((key, bytes)) => {
                    let v = V::decode(bytes.as_ref())?;
                    Ok((
                        substore
                            .unprefix(&key)
                            .expect("key from wrong substore")
                            .to_string(),
                        v,
                    ))
                }
                Err(e) => Err(eyre::eyre!(e)),
            })
    }

    /// Get a value from the index by key, decoding it into the given domain type.
    async fn index_get<V: DomainType>(
        &self,
        substore: Substore,
        key: &[u8],
    ) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .nonverifiable_get_raw(&substore.prefix_bytes(key))
            .await
            .map_err(|e| eyre::eyre!(e))?;
        if let Some(bytes) = bytes {
            let v = V::decode(bytes.as_ref())?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    /// Get a stream over all keys and values in the index with the given prefix, decoding the
    /// values into the given domain type.
    async fn index_prefix<V: DomainType>(
        &self,
        substore: Substore,
        prefix: &[u8],
    ) -> impl Stream<Item = Result<(Vec<u8>, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.nonverifiable_prefix_raw(&substore.prefix_bytes(prefix))
            .map(move |res| match res {
                Ok((key, bytes)) => {
                    let v = V::decode(bytes.as_ref())?;
                    Ok((
                        substore
                            .unprefix_bytes(&key)
                            .expect("key from wrong substore")
                            .to_vec(),
                        v,
                    ))
                }

                Err(e) => Err(eyre::eyre!(e)),
            })
    }
}

impl<T> StateWriteExt for T where T: StateWrite + Send + Sync + 'static {}
pub trait StateWriteExt: StateWrite + Send + Sync + 'static {
    /// Set a value in the state by key, encoding it from the given domain type.
    async fn put<V: DomainType + Debug>(&mut self, substore: Substore, key: &str, value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.put_raw(substore.prefix(key), bytes);
    }

    /// Delete a value from the state by key.
    async fn delete(&mut self, substore: Substore, key: &str) {
        StateWrite::delete(self, substore.prefix(key));
    }

    /// Set a value in the index by key, encoding it from the given domain type.
    async fn index_put<V: DomainType>(&mut self, substore: Substore, key: &[u8], value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.nonverifiable_put_raw(substore.prefix_bytes(key), bytes);
    }

    /// Delete a value from the index by key.
    async fn index_delete(&mut self, substore: Substore, key: &[u8]) {
        self.nonverifiable_delete(substore.prefix_bytes(key));
    }
}
