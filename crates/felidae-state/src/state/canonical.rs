use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the canonical hash for a given subdomain, if it exists.
    pub async fn canonical_hash(&self, subdomain: Domain) -> Result<Option<[u8; 32]>, Report> {
        let key = PrefixOrderDomain {
            name: subdomain.name.clone(),
        }
        .to_string();

        if let Some(bytes) = self.store.get::<Bytes>(Canonical, &key).await? {
            let hash = <[u8; 32]>::try_from(&bytes[..])
                .map_err(|_| eyre!("canonical hash for {} has invalid length", subdomain))?;
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    /// Get a stream of the canonical hashes for every subdomain under a registered domain,
    /// not including the registered domain itself.
    pub async fn canonical_strict_subdomains_hashes(
        &self,
        registered_domain: Domain,
    ) -> impl Stream<Item = Result<(Domain, [u8; 32]), Report>> + 'static {
        let mut prefix = PrefixOrderDomain {
            name: registered_domain.name.clone(),
        }
        .to_string();

        // Add a trailing dot to only get subdomains, not the registered domain itself, *UNLESS* the
        // registered domain being queried is the root domain, in which case it already ends with a
        // dot, so we shouldn't add one!
        if registered_domain.name != FQDN::default() {
            prefix.push('.'); // e.g. ".com.example."
        }

        self.store.prefix::<Bytes>(Canonical, prefix).map(|result| {
            let (key, bytes) = result?;
            let prefix_ordered = PrefixOrderDomain::from_str(&key)?;
            let domain = Domain {
                name: prefix_ordered.name,
            };
            let hash = <[u8; 32]>::try_from(&bytes[..])
                .map_err(|_| eyre!("canonical hash for {} has invalid length", domain))?;
            Ok((domain, hash))
        })
    }

    /// Get a stream of the canonical hashes for every subdomain including the registered domain
    /// itself.
    pub async fn canonical_subdomains_hashes(
        &self,
        registered_domain: Domain,
    ) -> Result<impl Stream<Item = Result<(Domain, [u8; 32]), Report>> + 'static, Report> {
        let subdomains = self
            .canonical_strict_subdomains_hashes(registered_domain.clone())
            .await;

        let domain = self.canonical_hash(registered_domain.clone()).await?;
        let domain = if let Some(domain) = domain {
            futures::stream::once(async move { Ok((registered_domain, domain)) }).boxed()
        } else {
            futures::stream::empty().boxed()
        };

        Ok(domain.chain(subdomains))
    }

    /// Returns a count of all subdomains including the registered domain itself in the canonical
    /// state.
    pub async fn canonical_subdomains(
        &self,
        registered_domain: Domain,
    ) -> Result<Vec<Domain>, Report> {
        let mut subdomains = self
            .canonical_strict_subdomains(registered_domain.clone())
            .await?;
        if self
            .canonical_hash(registered_domain.clone())
            .await?
            .is_some()
        {
            subdomains.push(registered_domain.clone());
        }
        Ok(subdomains)
    }

    /// Returns a count of all subdomains under a registered domain in the canonical state.
    ///
    /// This does not include the registered domain itself, only its subdomains.
    pub async fn canonical_strict_subdomains(
        &self,
        registered_domain: Domain,
    ) -> Result<Vec<Domain>, Report> {
        let mut prefix = PrefixOrderDomain {
            name: registered_domain.name.clone(),
        }
        .to_string();
        prefix.push('.'); // e.g. ".com.example."

        let mut subdomains = Vec::new();
        let mut stream = Box::pin(StateReadExt::prefix_keys(&self.store, Canonical, &prefix));
        while let Some(Ok(subdomain)) = stream.next().await {
            let prefix_ordered = PrefixOrderDomain::from_str(&subdomain)?;
            let subdomain = Domain {
                name: prefix_ordered.name,
            };
            subdomains.push(subdomain);
        }
        Ok(subdomains)
    }

    /// Update the canonical hash for a given subdomain.
    pub(crate) async fn update_canonical(
        &mut self,
        subdomain: Domain,
        hash_observed: HashObserved,
    ) -> Result<(), Report> {
        // We store subdomains in prefix order, e.g. ".com.example" instead of "example.com", to
        // allow prefix search for subdomains.
        let key = PrefixOrderDomain {
            name: subdomain.name.clone(),
        }
        .to_string(); // notice that we do not add a trailing dot here!

        if let HashObserved::Hash(hash) = hash_observed {
            info!(
                domain = %subdomain.name,
                hash = hex::encode(hash),
                "updating canonical hash"
            );
            self.store.put(Canonical, &key, Vec::from(hash));
        } else {
            info!(domain = key, "deleting canonical hash");
            StateWriteExt::delete(&mut self.store, Canonical, &key);
        }
        Ok(())
    }
}
