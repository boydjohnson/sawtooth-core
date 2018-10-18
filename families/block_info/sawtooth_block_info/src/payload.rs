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
 use std::time::{SystemTime, UNIX_EPOCH};

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
    } else {
        use sawtooth_sdk::processor::ApplyError;
    }
}

use protobuf;
use protos::BlockInfoTxn;


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

pub struct BlockInfoPayload {
    BlockInfoTransaction: BlockInfoTxn,
}

impl BlockInfoPayload {
    pub fn new(payload_data: &[u8]) -> Result<BlockInfoPayload, ApplyError> {
        let payload: BlockInfoTxn = parse_protobuf(&payload_data)?;

        let next_block = payload.get_block();
        let target_count = payload.get_target_count();
        let sync_tolerance = payload.get_sync_tolerance();

        if next_block.get_block_num() < 0 {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid block num: {}",
                next_block.get_block_num()
            )));
        }

        if !(validate_hex(next_block.get_previous_block_id(), 128)
            || next_block.get_previous_block_id() == "0000000000000000")
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid previous block id '{}'",
                next_block.get_previous_block_id()
            )));
        }
        if !validate_hex(next_block.get_signer_public_key(), 66) {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid signer public_key '{}'",
                next_block.get_signer_public_key()
            )));
        }
        if !validate_hex(next_block.get_header_signature(), 128) {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid header signature '{}'",
                next_block.get_header_signature()
            )));
        }

        if next_block.get_timestamp() <= 0 {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid timestamp '{}'",
                next_block.get_timestamp()
            )));
        }

        Ok(payload)
    }
}

fn parse_protobuf<M: protobuf::Message>(bytes: &[u8]) -> Result<M, ApplyError> {
    protobuf::parse_from_bytes(bytes).map_err(|err| {
        ApplyError::InvalidTransaction(format!("Failed to serialize protobuf: {:?}", err))
    })
}
