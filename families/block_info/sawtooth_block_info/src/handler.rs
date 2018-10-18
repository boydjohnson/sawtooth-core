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

use block_info::{BlockInfo, BlockInfoConfig, BlockInfoTxn};
use hex;
use protobuf;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use addressing::{NAMESPACE, get_config_addr, create_block_address};
use state::*;
use payload::BlockInfoPayload;


cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
        use sabre_sdk::TransactionContext;
        use sabre_sdk::TransactionHandler;
        use sabre_sdk::TpProcessRequest;
        use sabre_sdk::{WasmPtr, execute_entrypoint};
    } else {
        use sawtooth_sdk::messages::processor::TpProcessRequest;
        use sawtooth_sdk::processor::handler::ApplyError;
        use sawtooth_sdk::processor::handler::TransactionContext;
        use sawtooth_sdk::processor::handler::TransactionHandler;
    }
}

const DEFAULT_SYNC_TOLERANCE: u64 = 60 * 5;
const DEFAULT_TARGET_COUNT: u64 = 256;

fn parse_protobuf<M: protobuf::Message>(bytes: &[u8]) -> Result<M, ApplyError> {
    protobuf::parse_from_bytes(bytes).map_err(|err| {
        ApplyError::InvalidTransaction(format!("Failed to serialize protobuf: {:?}", err))
    })
}

fn serialize_protobuf<M: protobuf::Message>(message: &M) -> Result<Vec<u8>, ApplyError> {
    protobuf::Message::write_to_bytes(message).map_err(|err| {
        ApplyError::InvalidTransaction(format!("Failed to serialize protobuf: {:?}", err))
    })
}

fn validate_hex(string: &str, length: usize) -> bool {
    hex::decode(string).is_ok() && string.len() == length
}

fn validate_timestamp(timestamp: u64, tolerance: u64) -> Result<(), ApplyError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before Unix epoch.")
        .as_secs();
    if timestamp < (now - tolerance) || (now + tolerance) < timestamp {
        return Err(ApplyError::InvalidTransaction(format!(
            "Timestamp must be less than local time. Expected {0} in ({1}-{2}, {1}+{2})",
            timestamp, now, tolerance
        )));
    }

    Ok(())
}

pub struct BlockInfoTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl BlockInfoTransactionHandler {
    pub fn new() -> BlockInfoTransactionHandler {
        BlockInfoTransactionHandler {
            family_name: "block_info".to_string(),
            family_versions: vec!["1.0".to_string()],
            namespaces: vec![NAMESPACE.to_string()],
        }
    }

    pub fn insert_block(
        &self,
        payload: &BlockInfoTxn,
        mut state: BlockInfoState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {

        let state = state.get_state();
        let mut new_config = BlockInfoConfig::new();

        let next_block = payload.get_block();
        let target_count = payload.get_target_count();
        let sync_tolerance = payload.get_sync_tolerance();

        // Get config and previous block (according to the block info in the
        // transaction) from state
        let entries = state.get_state();
        let mut config = BlockInfoConfig::new();

        // If there is no config in state, we don't know anything about what's
        // in state, so we have to treat this as the first entry
        let (sets, deletes) = match entries {
            Ok(Some(entries)) => {
                config = parse_protobuf(&entries)?;

                // If the config was changed in this transaction, update it
                if sync_tolerance != 0 {
                    config.sync_tolerance = sync_tolerance;
                }
                if target_count != 0 {
                    config.target_count = target_count;
                }

                if next_block.get_block_num() != config.latest_block + 1 {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Block number must be one more than previous
                        block's. Got {} expected {}",
                        next_block.get_block_num(),
                        config.latest_block
                    )));
                }

                validate_timestamp(next_block.get_timestamp(), config.get_sync_tolerance())?;

                let mut block_entries =
                    state.get_state_at_block(config.get_latest_block());

                let prev_block: BlockInfo = match block_entries {
                    None => {
                        return Err(ApplyError::InvalidTransaction(String::from(
                            "Config and state out of sync. Latest block not found in state.",
                        )));
                    }
                    Some(block_entries) => parse_protobuf(&block_entries)?,
                };

                if prev_block.get_block_num() != config.get_latest_block() {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Block info stored at latest block has incorrect block num.",
                    )));
                }

                if prev_block.get_header_signature() != next_block.get_previous_block_id() {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Previous block id must match header signature of
                         previous block. Got {}, expected {}",
                        next_block.get_previous_block_id(),
                        prev_block.get_header_signature()
                    )));
                }

                if next_block.get_timestamp() < prev_block.get_timestamp() {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "Timestamp must be greater than previous block's. Got {},
                         expected {}",
                        next_block.get_timestamp(),
                        prev_block.get_timestamp()
                    )));
                }

                let mut deletes: Vec<String> = Vec::new();
                let mut sets: Vec<(String, Vec<u8>)> = Vec::new();

                // Compute  deletes
                config.set_latest_block(next_block.get_block_num());
                while config.get_latest_block() - config.get_oldest_block()
                    > config.get_target_count()
                {
                    deletes.push(create_block_address(config.get_oldest_block()));
                    let oldest_block = config.get_oldest_block();
                    config.set_oldest_block(oldest_block + 1);
                }

                // Compute sets
                let mut sets = HashMap::new();
                sets.insert(get_config_addr(), serialize_protobuf(&config)?);
                sets.insert(
                    create_block_address(next_block.get_block_num()),
                    serialize_protobuf(next_block)?,
                );

                (sets, deletes)
            }
            _ => {
                // If target count or sync tolerance were not specified in the
                // txn, use default values.
                config.set_target_count(if target_count != 0 {
                    target_count
                } else {
                    DEFAULT_TARGET_COUNT
                });
                config.set_sync_tolerance(if sync_tolerance != 0 {
                    sync_tolerance
                } else {
                    DEFAULT_SYNC_TOLERANCE
                });
                config.set_latest_block(next_block.get_block_num());
                config.set_oldest_block(next_block.get_block_num());

                validate_timestamp(next_block.get_timestamp(), config.get_sync_tolerance())?;

                let config_bytes = serialize_protobuf(&config)?;
                let block_bytes = serialize_protobuf(next_block)?;

                let mut sets = HashMap::new();
                sets.insert(get_config_addr(), config_bytes);
                sets.insert(
                    create_block_address(next_block.get_block_num()),
                    block_bytes,
                );

                (sets, Vec::new())
            }
        };

        if !deletes.is_empty() {
            state.delete_state(deletes.to_vec())?;
        }

        if !sets.is_empty() {
            state.set_state(sets)?;
        }

        Ok(())
    }

}

impl TransactionHandler for BlockInfoTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        let header = request.get_header();
        let signer_public_key = header.get_signer_public_key();

        let payload = BlockInfoPayload::new(request.get_payload())?;
        let state = BlockInfoState::new(context);

        self.insert_block(&payload, state, signer_public_key)
    }
}

#[cfg(target_arch = "wasm32")]
// Sabre apply must return a bool
fn apply(request: &TpProcessRequest, context: &mut TransactionContext) -> Result<bool, ApplyError> {
    let handler = BlockInfoTransactionHandler::new();
    match handler.apply(request, context) {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe fn entrypoint(payload: WasmPtr, signer: WasmPtr, signature: WasmPtr) -> i32 {
    execute_entrypoint(payload, signer, signature, apply)
}
