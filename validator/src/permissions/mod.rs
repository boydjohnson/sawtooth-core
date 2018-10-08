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

pub mod error;
pub mod verifier;

use permissions::error::IdentityError;
use proto::identity::Policy as ProtoPolicy;
use proto::identity::Policy_Entry;
use proto::identity::Policy_EntryType;
use proto::identity::Role as ProtoRole;

#[derive(Clone)]
pub enum Permission {
    PermitKey(String),
    DenyKey(String),
}

#[derive(Clone)]
pub struct Policy {
    name: String,
    permissions: Vec<Permission>,
}

impl Policy {
    pub fn new<S: Into<String>>(name: S, permissions: Vec<Permission>) -> Self {
        Policy {
            name: name.into(),
            permissions,
        }
    }

    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }
}

#[derive(Clone)]
pub struct Role {
    name: String,
    policy_name: String,
}

impl Role {
    pub fn new<N: Into<String>, P: Into<String>>(name: N, policy_name: P) -> Self {
        Role {
            name: name.into(),
            policy_name: policy_name.into(),
        }
    }

    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }
}

pub trait IdentitySource: Sync + Send {
    fn get_role(&self, name: &str) -> Result<Option<Role>, IdentityError>;
    fn get_policy(&self, name: &str) -> Result<Option<Policy>, IdentityError>;
}

impl From<ProtoRole> for Role {
    fn from(other: ProtoRole) -> Self {
        Role::new(other.name, other.policy_name)
    }
}

impl From<ProtoPolicy> for Policy {
    fn from(other: ProtoPolicy) -> Self {
        Policy::new(
            other.name,
            other.entries.iter().map(|entry| entry.into()).collect(),
        )
    }
}

impl<'a> From<&'a Policy_Entry> for Permission {
    fn from(other: &'a Policy_Entry) -> Self {
        match other.field_type {
            Policy_EntryType::PERMIT_KEY => Permission::PermitKey(other.key.clone()),
            Policy_EntryType::DENY_KEY => Permission::DenyKey(other.key.clone()),
            Policy_EntryType::ENTRY_TYPE_UNSET => panic!(
                "A policy entry will not be ENTRY_TYPE_UNSET for Policies in the IdentityView"
            ),
        }
    }
}
