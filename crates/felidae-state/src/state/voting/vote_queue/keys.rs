use super::*;

/// Helper functions to construct and parse state keys for the vote queue.
impl<S, K, V: DomainType> VoteQueue<'_, S, K, V>
where
    Report: From<<V as TryFrom<V::Proto>>::Error>,
{
    pub(super) fn votes_by_key_party_timestamp(
        &self,
        key: &str,
        party: &str,
        time: Time,
    ) -> String {
        format!(
            "{}{}",
            self.votes_by_key_party_prefix(key, party, true),
            // Deliberately truncate to the second:
            Time::from_unix_timestamp(time.unix_timestamp(), 0).expect("valid timestamp"),
        )
    }

    pub(super) fn parse_votes_by_key_party_timestamp<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, &'a str, Time), Report> {
        let remainder = self.strip_key_prefix(key, "votes_by_key")?;
        let parts: Vec<&str> = remainder.split('/').collect();
        if parts.len() != 3 {
            return Err(eyre!("invalid votes_by_key_party_time key format"));
        }
        let time = Self::parse_time_from_rfc3339(parts[2])?;
        Ok((parts[0], parts[1], time))
    }

    pub(super) fn votes_by_key_party_prefix(&self, key: &str, party: &str, exact: bool) -> String {
        format!(
            "{}/votes_by_key/{}/{}{}",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
            key,
            party,
            if exact { "/" } else { "" }
        )
    }

    pub(super) fn votes_by_key_prefix(&self, key: &str, exact: bool) -> String {
        format!(
            "{}/votes_by_key/{}{}",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
            key,
            if exact { "/" } else { "" }
        )
    }

    pub(super) fn index_votes_by_timestamp_key_party(
        &self,
        timestamp: Time,
        key: &str,
        party: &str,
    ) -> Vec<u8> {
        let full_key = format!(
            "{}/votes_by_timestamp/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
        );
        let mut full_key = full_key.into_bytes();
        full_key.extend_from_slice(&timestamp.unix_timestamp().to_be_bytes());
        full_key.push(b'/');
        full_key.extend_from_slice(key.as_bytes());
        full_key.push(b'/');
        full_key.extend_from_slice(party.as_bytes());
        full_key
    }

    pub(super) fn parse_index_votes_by_timestamp_key_party<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<(Time, &'a str, &'a str), Report> {
        let (time, remainder) = self.parse_timestamp_index_key(key, "votes_by_timestamp")?;
        let parts: Vec<&str> = remainder.split('/').collect();
        if parts.len() < 2 {
            return Err(eyre!("invalid votes_by_timestamp key format"));
        }
        Ok((time, parts[0], parts[1]))
    }

    pub(super) fn votes_by_timestamp_all_prefix(&self) -> Vec<u8> {
        format!(
            "{}/votes_by_timestamp/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
        )
        .into_bytes()
    }

    pub(super) fn pending_by_key_timestamp(&self, key: &str, time: Time) -> String {
        format!(
            "{}{}",
            self.pending_by_key_prefix(key, true),
            // Deliberately truncate to the second:
            Time::from_unix_timestamp(time.unix_timestamp(), 0).expect("valid timestamp"),
        )
    }

    pub(super) fn parse_pending_by_key_timestamp<'a>(
        &self,
        key: &'a str,
    ) -> Result<(&'a str, Time), Report> {
        let remainder = self.strip_key_prefix(key, "pending_by_key")?;
        let time_separator = remainder
            .rfind('/')
            .ok_or_else(|| eyre!("invalid pending_by_key key format"))?;
        let time_str = &remainder[time_separator + 1..];
        let time = Self::parse_time_from_rfc3339(time_str)?;
        let key_str = &remainder[..time_separator];
        Ok((key_str, time))
    }

    pub(super) fn pending_by_key_prefix(&self, key: &str, exact: bool) -> String {
        format!(
            "{}/pending_by_key/{}{}",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
            key,
            if exact { "/" } else { "" }
        )
    }

    pub(super) fn index_pending_by_timestamp_key(&self, timestamp: Time, key: &str) -> Vec<u8> {
        let full_key = format!(
            "{}/pending_by_timestamp/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
        );
        let mut full_key = full_key.into_bytes();
        full_key.extend_from_slice(&timestamp.unix_timestamp().to_be_bytes());
        full_key.push(b'/');
        full_key.extend_from_slice(key.as_bytes());
        full_key
    }

    pub(super) fn parse_index_pending_by_timestamp_key<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<(Time, &'a str), Report> {
        self.parse_timestamp_index_key(key, "pending_by_timestamp")
    }

    pub(super) fn index_pending_by_timestamp_all_prefix(&self) -> Vec<u8> {
        format!(
            "{}/pending_by_timestamp/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
        )
        .into_bytes()
    }

    // Helper functions for parsing
    fn strip_key_prefix<'a>(&self, key: &'a str, key_type: &str) -> Result<&'a str, Report> {
        let prefix = format!(
            "{}/{}/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
            key_type
        );
        key.strip_prefix(&prefix)
            .ok_or_else(|| eyre!("key does not start with expected prefix"))
    }

    fn parse_time_from_rfc3339(time_str: &str) -> Result<Time, Report> {
        Time::parse_from_rfc3339(time_str).map_err(|e| eyre!("invalid time format: {e}"))
    }

    fn parse_timestamp_index_key<'a>(
        &self,
        key: &'a [u8],
        key_type: &str,
    ) -> Result<(Time, &'a str), Report> {
        let prefix = format!(
            "{}/{}/",
            self.internal_state_prefix
                .strip_suffix('/')
                .unwrap_or(self.internal_state_prefix),
            key_type
        );
        let prefix_bytes = prefix.as_bytes();

        if key.len() < prefix_bytes.len() + 8 + 1 {
            return Err(eyre!("invalid {} key length", key_type));
        }

        if !key.starts_with(prefix_bytes) {
            return Err(eyre!("key does not start with expected prefix"));
        }

        let ts_start = prefix_bytes.len();
        let ts_bytes = &key[ts_start..ts_start + 8];
        let ts = i64::from_be_bytes(ts_bytes.try_into().expect("8 bytes"));
        let time = Time::from_unix_timestamp(ts, 0).map_err(|e| eyre!("invalid timestamp: {e}"))?;

        let rest_start = ts_start + 8 + 1; // +1 for the '/' separator
        let rest = std::str::from_utf8(&key[rest_start..])
            .context("invalid utf-8 in timestamp index key")?;
        Ok((time, rest))
    }
}
