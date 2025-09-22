use cnidarium::{RootHash, Snapshot, StateDelta, StateRead, StateWrite, Storage};
use color_eyre::{Report, eyre};
use felidae_proto::DomainType;
use futures::{Stream, stream::StreamExt};
use std::mem;

pub struct Store {
    storage: Storage,
    delta: StateDelta<Snapshot>,
}

impl Store {
    pub fn new(storage: Storage) -> Self {
        Self {
            delta: StateDelta::new(storage.latest_snapshot()),
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
        let delta = mem::replace(
            &mut self.delta,
            StateDelta::new(self.storage.latest_snapshot()),
        );
        self.storage
            .commit(delta)
            .await
            .map_err(|e| eyre::eyre!(e))?;
        Ok(())
    }

    /// Discard all pending changes.
    pub fn abort(&mut self) {
        self.delta = StateDelta::new(self.storage.latest_snapshot());
    }

    /// Get a value from the state by key, decoding it into the given domain type.
    pub async fn get<V: DomainType>(&self, key: &str) -> Result<Option<V>, Report>
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = self.delta.get_raw(key).await.map_err(|e| eyre::eyre!(e))?;
        if let Some(bytes) = bytes {
            let v = V::decode(bytes.as_ref())?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    /// Get a stream over all keys in the state.
    pub async fn prefix_keys(
        &self,
        prefix: &str,
    ) -> impl Stream<Item = Result<String, Report>> + '_ {
        self.delta.prefix_keys(prefix).map(|res| match res {
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
        self.delta.prefix_raw(prefix).map(|res| match res {
            Ok((key, bytes)) => {
                let v = V::decode(bytes.as_ref())?;
                Ok((key, v))
            }
            Err(e) => Err(eyre::eyre!(e)),
        })
    }

    /// Set a value in the state by key, encoding it from the given domain type.
    pub async fn put<V: DomainType>(&mut self, key: &str, value: V)
    where
        Report: From<<V as TryFrom<V::Proto>>::Error>,
    {
        let bytes = value.encode_to_vec();
        self.delta.put_raw(key.to_string(), bytes);
    }
}
