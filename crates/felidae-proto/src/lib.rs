mod traverse;

pub mod transaction {
    include!(concat!(env!("OUT_DIR"), "/felidae.transaction.rs"));

    use aws_lc_rs::{
        digest::{Context, Digest},
        signature::{Ed25519KeyPair, EdDSAParameters, KeyPair, UnparsedPublicKey},
    };
    use prost::Message as _;
    use std::any::Any;

    use super::traverse::TraverseMut;

    #[derive(thiserror::Error, Debug)]
    pub enum SignError {
        #[error("No keypair available for public key in transaction")]
        MissingKeypair,
        #[error("Provided keypair does not match public key in transaction")]
        WrongKeypair,
        #[error("Transaction already contains a signature")]
        AlreadySigned,
    }

    impl Transaction {
        /// Compute the hash of the transaction as a protobuf message.
        ///
        /// The hash is computed after removing all signatures from the transaction, so that it can
        /// be computed as an *input* to signing.
        pub fn hash(&self, mut context: Context) -> Digest
        where
            Self: prost::Message + Sized,
        {
            let mut unbound = self.clone();
            unbound.unbind();
            context.update(&unbound.encode_to_vec());
            context.finish()
        }

        /// Fill in every blank signature with a valid signature over the hash of the transaction.
        pub fn sign_all(
            self,
            keypairs: &impl Fn(&[u8]) -> Option<&Ed25519KeyPair>,
            context: Context,
        ) -> Result<Self, SignError>
        where
            Self: prost::Message + Sized,
        {
            let digest = self.hash(context);
            self.bind(keypairs, digest)
        }

        /// Verify every signature in the transaction against the hash of the transaction.
        pub fn verify_all(
            mut self,
            context: Context,
        ) -> Result<Self, aws_lc_rs::error::Unspecified> {
            let digest = self.hash(context);
            let mut result = Ok(());
            self.traverse_mut(&mut |v| {
                if let Some(Signature {
                    public_key,
                    signature,
                    ..
                }) = (v as &mut dyn Any).downcast_mut::<Signature>()
                {
                    if !signature.is_empty() {
                        if let Err(e) = UnparsedPublicKey::new(&EdDSAParameters, public_key)
                            .verify_digest(&digest, signature)
                        {
                            result = Err(e);
                        }
                    }
                } else {
                    // Missing signature is an error:
                    result = Err(aws_lc_rs::error::Unspecified);
                }
            });
            result.map(|()| self)
        }

        /// Fill in every blank signature with a valid signature over the hash of the total object,
        /// passed in from the outside.
        fn bind(
            mut self,
            keypairs: &impl Fn(&[u8]) -> Option<&Ed25519KeyPair>,
            digest: Digest,
        ) -> Result<Self, SignError> {
            let mut result = Ok(());
            self.traverse_mut(&mut |v| {
                if let Some(Signature {
                    public_key,
                    signature,
                }) = (v as &mut dyn Any).downcast_mut::<Signature>()
                {
                    // Only fill in missing signatures:
                    if signature.is_empty() {
                        // Only fill in signatures we can sign for:
                        if let Some(keypair) = keypairs(public_key.as_ref()) {
                            if keypair.public_key().as_ref() != public_key.as_ref() {
                                // Keypair doesn't match public key:
                                result = Err(SignError::WrongKeypair);
                                return;
                            }
                            *signature = keypair.sign(digest.as_ref()).as_ref().to_vec().into();
                        } else {
                            // No keypair available:
                            result = Err(SignError::MissingKeypair);
                        }
                    } else {
                        // Signature already present:
                        result = Err(SignError::AlreadySigned);
                    }
                }
            });
            result.map(|()| self)
        }

        /// Remove all signatures from this object and its sub-objects.
        fn unbind(&mut self) {
            self.traverse_mut(&mut |v| {
                if let Some(Signature { signature, .. }) =
                    (v as &mut dyn Any).downcast_mut::<Signature>()
                {
                    signature.clear();
                }
            });
        }
    }

    // Signatures are treated as a primitive in traversals.
    impl TraverseMut for Signature {}

    impl TraverseMut for Config {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                admin_config,
                oracle_config,
                onion_config,
            } = self;
            admin_config.traverse_mut(f);
            oracle_config.traverse_mut(f);
            onion_config.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for config::VotingConfig {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                total,
                quorum,
                timeout,
                delay,
            } = self;
            total.traverse_mut(f);
            quorum.traverse_mut(f);
            timeout.traverse_mut(f);
            delay.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for config::AdminConfig {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                admins,
                voting_config,
            } = self;
            admins.traverse_mut(f);
            voting_config.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for config::OracleConfig {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                oracles,
                voting_config,
                enabled,
                max_enrolled_subdomains,
            } = self;
            oracles.traverse_mut(f);
            voting_config.traverse_mut(f);
            enabled.traverse_mut(f);
            max_enrolled_subdomains.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for config::OnionConfig {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { enabled } = self;
            enabled.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for Admin {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { public_key } = self;
            public_key.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for Oracle {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { public_key } = self;
            public_key.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for Transaction {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { chain_id, actions } = self;
            chain_id.traverse_mut(f);
            actions.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for Action {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { action } = self;
            action.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for action::Action {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            match self {
                action::Action::Reconfigure(v) => v.traverse_mut(f),
                action::Action::Observe(v) => v.traverse_mut(f),
            }
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for action::Reconfigure {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self { signature, config } = self;
            signature.traverse_mut(f);
            config.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for action::Observe {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                signature,
                observation,
            } = self;
            signature.traverse_mut(f);
            observation.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for action::observe::Observation {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                domain,
                hash_observed,
                blockstamp,
            } = self;
            domain.traverse_mut(f);
            hash_observed.traverse_mut(f);
            blockstamp.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }

    impl TraverseMut for action::observe::observation::Blockstamp {
        fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
            let Self {
                block_hash,
                block_number,
            } = self;
            block_hash.traverse_mut(f);
            block_number.traverse_mut(f);
            f(self as &mut dyn Any);
        }
    }
}
