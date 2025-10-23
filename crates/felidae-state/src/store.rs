#![allow(unused)]

use cnidarium::{RootHash, Snapshot, StateDelta, StateRead, StateWrite, Storage};
use color_eyre::{Report, eyre};
use felidae_proto::DomainType;
use futures::{Stream, stream::StreamExt};
use std::fmt::{Debug, Display};
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Store {
    storage: Storage,
    delta: Arc<RwLock<StateDelta<Snapshot>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Substore {
    Internal,
    Canonical,
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
        const SUBSTORES: [&str; 2] = ["internal", "canonical"];
        let storage = Storage::init(path, SUBSTORES.map(Into::into).to_vec())
            .await
            .map_err(|e| eyre::eyre!(e))?;
        Ok(Self::new(storage))
    }

    fn new(storage: Storage) -> Self {
        Self {
            delta: Arc::new(RwLock::new(StateDelta::new(storage.latest_snapshot()))),
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

    /// Commit all pending changes to the underlying storage.
    pub async fn commit(&mut self) -> Result<(), Report> {
        // Pull out the current delta and replace it with a new, empty one:
        let delta = mem::replace(
            &mut *self.delta.write().await,
            StateDelta::new(self.storage.latest_snapshot()),
        );

        // Commit the pulled-out delta to storage:
        self.storage
            .commit(delta)
            .await
            .map_err(|e| eyre::eyre!(e))?;

        // Update the delta to use the new latest snapshot:
        *self.delta.write().await = StateDelta::new(self.storage.latest_snapshot());

        // NOTE: without the final step above, the delta would continue to refer to the snapshot
        // *before* the commit, which would lead to errors on subsequent reads/writes.

        Ok(())
    }

    /// Discard all pending changes.
    pub fn abort(&mut self) {
        self.delta = Arc::new(RwLock::new(StateDelta::new(self.storage.latest_snapshot())));
    }

    /// Create a logical fork of the store.
    pub async fn fork(&self) -> Self {
        let fork = self.delta.write().await.fork();
        Self {
            storage: self.storage.clone(),
            delta: Arc::new(RwLock::new(fork)),
        }
    }

    /// Get a value from the state by key, decoding it into the given domain type.
    pub async fn get<V: DomainType>(
        &self,
        substore: Substore,
        key: &str,
    ) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .delta
            .read()
            .await
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

    /// Set a value in the state by key, encoding it from the given domain type.
    pub async fn put<V: DomainType + Debug>(&mut self, substore: Substore, key: &str, value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.delta
            .write()
            .await
            .put_raw(substore.prefix(key), bytes);
    }

    /// Delete a value from the state by key.
    pub async fn delete(&mut self, substore: Substore, key: &str) {
        self.delta.write().await.delete(substore.prefix(key));
    }

    /// Get a stream over all keys in the state.
    pub async fn prefix_keys(
        &self,
        substore: Substore,
        prefix: &str,
    ) -> impl Stream<Item = Result<String, Report>> {
        self.delta
            .read()
            .await
            .prefix_keys(&substore.prefix(prefix))
            .map(move |res| match res {
                Ok(key) => Ok(substore
                    .unprefix(&key)
                    .expect("key from wrong substore")
                    .to_string()),
                Err(e) => Err(eyre::eyre!(e)),
            })
    }

    /// Get a stream over all key-value pairs in the state with the given prefix, decoding the
    /// values into the given domain type.
    pub async fn prefix<V: DomainType>(
        &self,
        substore: Substore,
        prefix: impl AsRef<str>,
    ) -> impl Stream<Item = Result<(String, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.delta
            .read()
            .await
            .prefix_raw(&substore.prefix(prefix.as_ref()))
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
    pub async fn index_get<V: DomainType>(
        &self,
        substore: Substore,
        key: &[u8],
    ) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .delta
            .read()
            .await
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

    /// Set a value in the index by key, encoding it from the given domain type.
    pub async fn index_put<V: DomainType>(&mut self, substore: Substore, key: &[u8], value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.delta
            .write()
            .await
            .nonverifiable_put_raw(substore.prefix_bytes(key), bytes);
    }

    /// Delete a value from the index by key.
    pub async fn index_delete(&mut self, substore: Substore, key: &[u8]) {
        self.delta
            .write()
            .await
            .nonverifiable_delete(substore.prefix_bytes(key));
    }

    /// Get a stream over all keys and values in the index with the given prefix, decoding the
    /// values into the given domain type.
    pub async fn index_prefix<V: DomainType>(
        &self,
        substore: Substore,
        prefix: &[u8],
    ) -> impl Stream<Item = Result<(Vec<u8>, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.delta
            .read()
            .await
            .nonverifiable_prefix_raw(&substore.prefix_bytes(prefix))
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
