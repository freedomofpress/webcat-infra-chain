#![allow(unused)]

use cnidarium::{RootHash, Snapshot, StateDelta, StateRead, StateWrite, Storage};
use color_eyre::{Report, eyre};
use felidae_proto::DomainType;
use futures::{Stream, stream::StreamExt};
use std::fmt::Debug;
use std::mem;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Store {
    storage: Storage,
    delta: Arc<RwLock<StateDelta<Snapshot>>>,
}

impl Store {
    pub fn new(storage: Storage) -> Self {
        Self {
            delta: Arc::new(RwLock::new(StateDelta::new(storage.latest_snapshot()))),
            storage,
        }
    }

    pub async fn root_hash(&self) -> Result<RootHash, Report> {
        self.storage
            .latest_snapshot()
            .root_hash()
            .await
            .map_err(|e| eyre::eyre!(e))
    }

    /// Commit all pending changes to the underlying storage.
    pub async fn commit(&mut self) -> Result<(), Report> {
        info!("Before commit - root hash: {:?}", self.root_hash().await);

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

        info!("After commit - root hash: {:?}", self.root_hash().await);

        Ok(())
    }

    /// Discard all pending changes.
    pub fn abort(&mut self) {
        self.delta = Arc::new(RwLock::new(StateDelta::new(self.storage.latest_snapshot())));
    }

    /// Get a value from the state by key, decoding it into the given domain type.
    pub async fn get<V: DomainType>(&self, key: &str) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .delta
            .read()
            .await
            .get_raw(key)
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
    pub async fn put<V: DomainType + Debug>(&mut self, key: &str, value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        trace!(?key, ?value, "put");
        let bytes = value.encode_to_vec();
        self.delta.write().await.put_raw(key.to_string(), bytes);
    }

    /// Delete a value from the state by key.
    pub async fn delete(&mut self, key: &str) {
        self.delta.write().await.delete(key.to_string());
    }

    /// Get a stream over all keys in the state.
    pub async fn prefix_keys(
        &self,
        prefix: &str,
    ) -> impl Stream<Item = Result<String, Report>> + '_ {
        self.delta
            .read()
            .await
            .prefix_keys(prefix)
            .map(|res| match res {
                Ok(key) => Ok(key),
                Err(e) => Err(eyre::eyre!(e)),
            })
    }

    /// Get a stream over all key-value pairs in the state with the given prefix, decoding the
    /// values into the given domain type.
    pub async fn prefix<V: DomainType>(
        &self,
        prefix: &str,
    ) -> impl Stream<Item = Result<(String, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.delta
            .read()
            .await
            .prefix_raw(prefix)
            .map(|res| match res {
                Ok((key, bytes)) => {
                    let v = V::decode(bytes.as_ref())?;
                    Ok((key, v))
                }
                Err(e) => Err(eyre::eyre!(e)),
            })
    }

    /// Get a value from the index by key, decoding it into the given domain type.
    pub async fn index_get<V: DomainType>(&self, key: &[u8]) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self
            .delta
            .read()
            .await
            .nonverifiable_get_raw(key)
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
    pub async fn index_put<V: DomainType>(&mut self, key: &[u8], value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.delta
            .write()
            .await
            .nonverifiable_put_raw(key.to_vec(), bytes);
    }

    /// Delete a value from the index by key.
    pub async fn index_delete(&mut self, key: &[u8]) {
        self.delta.write().await.nonverifiable_delete(key.to_vec());
    }

    /// Get a stream over all keys and values in the index with the given prefix, decoding the
    /// values into the given domain type.
    pub async fn index_prefix<V: DomainType>(
        &self,
        prefix: &[u8],
    ) -> impl Stream<Item = Result<(Vec<u8>, V), Report>> + '_
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        self.delta
            .read()
            .await
            .nonverifiable_prefix_raw(prefix)
            .map(|res| match res {
                Ok((key, bytes)) => {
                    let v = V::decode(bytes.as_ref())?;
                    Ok((key, v))
                }

                Err(e) => Err(eyre::eyre!(e)),
            })
    }
}
