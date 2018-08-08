/*
 * Copyright 2018 Bitwise IO
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */
use batch::Batch;
use transaction::Transaction;

use permissions::{IdentitySource, Permission, Policy};

const ROLE_TRANSACTOR: &str = "transactor";
const ROLE_BATCH_TRANSACTOR: &str = "transactor.batch_signer";
const ROLE_TXN_TRANSACTOR: &str = "transactor.transaction_signer";
const POLICY_DEFAULT: &str = "default";

const ANY_KEY: &str = "*";

pub struct PermissionVerifier {
    on_chain_identities: Box<IdentitySource>,
    local_identities: Box<IdentitySource>,
}

impl PermissionVerifier {
    pub fn new(
        on_chain_identities: Box<IdentitySource>,
        local_identities: Box<IdentitySource>,
    ) -> Self {
        PermissionVerifier {
            on_chain_identities,
            local_identities,
        }
    }

    /// Check the batch signing key against the allowed transactor
    /// permissions. The roles being checked are the following, from first
    /// to last:
    ///     "transactor.batch_signer"
    ///     "transactor"
    ///     "default"
    ///
    /// The first role that is set will be the one used to enforce if the
    /// batch signer is allowed.
    ///
    /// Args:
    ///     batch (Batch): The batch that is being verified.
    ///     state_root(string): The state root of the previous block. If
    ///         this is None, the current state root hash will be
    ///         retrieved.
    ///     from_state (bool): Whether the identity value should be read
    ///         directly from state, instead of using the cached values.
    ///         This should be used when the state_root passed is not from
    ///         the current chain head.
    pub fn is_batch_signer_authorized(&self, batch: &Batch) -> bool {
        let policy_name: &str = self
            .on_chain_identities
            .get_role(ROLE_BATCH_TRANSACTOR)
            .or_else(|| self.on_chain_identities.get_role(ROLE_TRANSACTOR))
            .map(|role| role.policy_name())
            .unwrap_or(POLICY_DEFAULT);

        let allowed = self
            .on_chain_identities
            .get_policy(policy_name)
            .map(|policy| PermissionVerifier::is_allowed(&batch.signer_public_key, policy))
            .unwrap_or(true);

        allowed && self.is_transaction_signer_authorized(&batch.transactions)
    }

    pub fn check_off_chain_batch_roles(&self, batch: &Batch) -> bool {
        true
    }

    fn is_allowed(public_key: &str, policy: &Policy) -> bool {
        for permission in policy.permissions() {
            match permission {
                Permission::PermitKey(key) => {
                    if key == public_key || key == ANY_KEY {
                        return true;
                    }
                }
                Permission::DenyKey(key) => {
                    if key == public_key || key == ANY_KEY {
                        return false;
                    }
                }
            }
        }

        false
    }

    /// Check the transaction signing key against the allowed transactor
    /// permissions. The roles being checked are the following, from first
    /// to last:
    ///     "transactor.transaction_signer.<TP_Name>"
    ///     "transactor.transaction_signer"
    ///     "transactor"
    ///     "default"
    ///
    /// The first role that is set will be the one used to enforce if the
    /// transaction signer is allowed.
    ///
    /// Args:
    ///     transactions (List of Transactions): The transactions that are
    ///         being verified.
    ///     state_root(string): The state root of the previous block. If
    ///         this is None, the current state root hash will be
    ///         retrieved.
    ///     from_state (bool): Whether the identity value should be read
    ///         directly from state, instead of using the cached values.
    ///         This should be used when the state_root passed is not from
    ///         the current chain head.
    fn is_transaction_signer_authorized(&self, transactions: &[Transaction]) -> bool {
        let policy_name: Option<&str> = self
            .on_chain_identities
            .get_role(ROLE_TXN_TRANSACTOR)
            .or_else(|| self.on_chain_identities.get_role(ROLE_TRANSACTOR))
            .map(|role| role.policy_name());

        for transaction in transactions {
            let policy_name = self
                .on_chain_identities
                .get_role(&format!(
                    "{}.{}",
                    ROLE_TXN_TRANSACTOR, transaction.family_name
                ))
                .map(|role| role.policy_name())
                .or(policy_name)
                .unwrap_or(POLICY_DEFAULT);

            if let Some(policy) = self.on_chain_identities.get_policy(policy_name) {
                if !PermissionVerifier::is_allowed(&transaction.signer_public_key, policy) {
                    debug!(
                        "Transaction Signer: {} is not permitted.",
                        &transaction.signer_public_key
                    );
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use batch::Batch;
    use permissions::{IdentitySource, Permission, Policy, Role};
    use transaction::Transaction;

    #[test]
    /// Test that if no roles are set and no default policy is set,
    /// permit all is used.
    fn allow_all_with_no_permissions() {
        let batch = create_batches(1, 1, "test_pubkey")
            .into_iter()
            .nth(0)
            .unwrap();

        let permission_verifier = PermissionVerifier::new(
            Box::new(TestIdentitySource::default()),
            Box::new(TestIdentitySource::default()),
        );

        assert!(permission_verifier.is_batch_signer_authorized(&batch));
    }

    #[test]
    /// Test that if no roles are set, the default policy is used.
    ///     1. Set default policy to permit all. Batch should be allowed.
    ///     2. Set default policy to deny all. Batch should be rejected.
    fn default_policy_permission() {
        let batch = create_batches(1, 1, "test_pubkey")
            .into_iter()
            .nth(0)
            .unwrap();

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "default",
                vec![Permission::PermitKey("*".into())],
            ));
            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(permission_verifier.is_batch_signer_authorized(&batch));
        }

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "default",
                vec![Permission::DenyKey("*".into())],
            ));
            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(!permission_verifier.is_batch_signer_authorized(&batch));
        }
    }

    #[test]
    /// Test that role: "transactor" is checked properly.
    ///     1. Set policy to permit signing key. Batch should be allowed.
    ///     2. Set policy to permit some other key. Batch should be rejected.
    fn transactor_role() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey(pub_key.clone())],
            ));
            on_chain_identities.add_role(Role::new("transactor", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(permission_verifier.is_batch_signer_authorized(&batch));
        }
        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::DenyKey(pub_key.clone())],
            ));
            on_chain_identities.add_role(Role::new("transactor", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(!permission_verifier.is_batch_signer_authorized(&batch));
        }
    }

    #[test]
    /// Test that role: "transactor.batch_signer" is checked properly.
    ///     1. Set policy to permit signing key. Batch should be allowed.
    ///     2. Set policy to permit some other key. Batch should be rejected.
    fn transactor_batch_signer_role() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey(pub_key.clone())],
            ));
            on_chain_identities.add_role(Role::new("transactor.batch_signer", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(permission_verifier.is_batch_signer_authorized(&batch));
        }
        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::DenyKey(pub_key.clone())],
            ));
            on_chain_identities.add_role(Role::new("transactor.batch_signer", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(!permission_verifier.is_batch_signer_authorized(&batch));
        }
    }

    #[test]
    /// Test that role: "transactor.transaction_signer" is checked properly.
    ///     1. Set policy to permit signing key. Batch should be allowed.
    ///     2. Set policy to permit some other key. Batch should be rejected.
    fn transactor_transaction_signer_role() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey(pub_key.clone())],
            ));
            on_chain_identities.add_role(Role::new("transactor.transaction_signer", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(permission_verifier.is_batch_signer_authorized(&batch));
        }
        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey("other".to_string())],
            ));
            on_chain_identities.add_role(Role::new("transactor.transaction_signer", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(!permission_verifier.is_batch_signer_authorized(&batch));
        }
    }

    #[test]
    /// Test that role: "transactor.transaction_signer.intkey" is checked properly.
    ///     1. Set policy to permit signing key. Batch should be allowed.
    ///     2. Set policy to permit some other key. Batch should be rejected.
    fn transactor_transaction_signer_transaction_family() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey(pub_key.clone())],
            ));
            on_chain_identities
                .add_role(Role::new("transactor.transaction_signer.intkey", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(permission_verifier.is_batch_signer_authorized(&batch));
        }
        {
            let mut on_chain_identities = TestIdentitySource::default();
            on_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey("other".to_string())],
            ));
            on_chain_identities
                .add_role(Role::new("transactor.transaction_signer.intkey", "policy1"));

            let permission_verifier = on_chain_verifier(on_chain_identities);
            assert!(!permission_verifier.is_batch_signer_authorized(&batch));
        }
    }

    #[test]
    /// Test that if permissions are empty all signers are permitted.
    fn off_chain_permissions() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        let permission_verifier = off_chain_verifier(TestIdentitySource::default());

        assert!(permission_verifier.check_off_chain_batch_roles(&batch));
    }

    #[test]
    /// Test that role: "transactor" is checked properly in off-chain permissions.
    ///     1. Set policy to permit signing key. Batch should be allowed.
    ///     2. Set policy to permit some other key. Batch should be rejected.
    fn off_chain_transactor_role() {
        let pub_key = "test_pubkey".to_string();
        let batch = create_batches(1, 1, &pub_key).into_iter().nth(0).unwrap();

        {
            let mut off_chain_identities = TestIdentitySource::default();
            off_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::PermitKey(pub_key.clone())],
            ));
            off_chain_identities.add_role(Role::new("transactor", "policy1"));

            let permission_verifier = off_chain_verifier(off_chain_identities);
            assert!(permission_verifier.check_off_chain_batch_roles(&batch));
        }
        {
            let mut off_chain_identities = TestIdentitySource::default();
            off_chain_identities.add_policy(Policy::new(
                "policy1",
                vec![Permission::DenyKey(pub_key.clone())],
            ));
            off_chain_identities.add_role(Role::new("transactor", "policy1"));

            let permission_verifier = off_chain_verifier(off_chain_identities);
            assert!(!permission_verifier.check_off_chain_batch_roles(&batch));
        }
    }
    fn on_chain_verifier(identity_source: TestIdentitySource) -> PermissionVerifier {
        PermissionVerifier::new(
            Box::new(identity_source),
            Box::new(TestIdentitySource::default()),
        )
    }

    fn off_chain_verifier(identity_source: TestIdentitySource) -> PermissionVerifier {
        PermissionVerifier::new(
            Box::new(TestIdentitySource::default()),
            Box::new(TestIdentitySource::default()),
        )
    }

    fn create_transactions(count: usize, pub_key: &str) -> Vec<Transaction> {
        (0..count)
            .map(|i| Transaction {
                batcher_public_key: pub_key.to_string(),
                signer_public_key: pub_key.to_string(),
                header_signature: format!("signature-{}", i),
                payload: vec![],
                dependencies: vec![],
                family_name: "intkey".into(),
                family_version: "1.0".into(),
                inputs: vec![],
                outputs: vec![],
                payload_sha512: format!("nonesense-{}", i),
                header_bytes: vec![],
                nonce: format!("{}", i),
            })
            .collect()
    }

    fn create_batches(count: usize, txns_per_batch: usize, pub_key: &str) -> Vec<Batch> {
        (0..count)
            .map(|i| {
                let txns = create_transactions(txns_per_batch, pub_key);
                let txn_ids = txns
                    .iter()
                    .map(|txn| txn.header_signature.clone())
                    .collect();
                Batch {
                    signer_public_key: pub_key.to_string(),
                    transactions: txns,
                    transaction_ids: txn_ids,
                    header_signature: format!("batch-signature-{}", i),
                    header_bytes: vec![],
                    trace: false,
                }
            })
            .collect()
    }

    #[derive(Default)]
    struct TestIdentitySource {
        policies: HashMap<String, Policy>,
        roles: HashMap<String, Role>,
    }

    impl TestIdentitySource {
        fn add_policy(&mut self, policy: Policy) {
            self.policies.insert(policy.name.clone(), policy);
        }

        fn add_role(&mut self, role: Role) {
            self.roles.insert(role.name.clone(), role);
        }
    }

    impl IdentitySource for TestIdentitySource {
        fn get_role(&self, name: &str) -> Option<&Role> {
            self.roles.get(name)
        }

        fn get_policy(&self, name: &str) -> Option<&Policy> {
            self.policies.get(name)
        }
    }
}
