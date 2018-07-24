/*
 * Copyright 2018 Intel Corporation
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

use cpython;
use cpython::{FromPyObject, ObjectProtocol, PyObject, Python};

use block::Block;
use scheduler::TxnExecutionResult;
use std::sync::mpsc::Sender;

#[derive(Debug)]
pub enum ValidationError {
    BlockValidationFailure(String),
}

pub trait BlockValidator: Send + Sync {
    fn has_block(&self, block_id: &str) -> bool;

    fn validate_block(&self, block: Block) -> Result<(), ValidationError>;

    fn submit_blocks_for_verification(
        &self,
        blocks: &[Block],
        response_sender: Sender<BlockValidationResult>,
    );
}

#[derive(Clone, Debug)]
pub struct BlockValidationResult {
    pub block_id: String,
    pub execution_results: Vec<TxnExecutionResult>,
    pub num_transactions: u64,
    pub status: BlockValidationStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockValidationStatus {
    Valid,
    Invalid,
}

impl<'source> FromPyObject<'source> for BlockValidationResult {
    fn extract(py: Python, obj: &'source PyObject) -> cpython::PyResult<Self> {
        let py_status: i32 = obj.getattr(py, "status")?.extract(py)?;
        let status = match py_status {
            1 => BlockValidationStatus::Valid,
            _ => BlockValidationStatus::Invalid,
        };
        let execution_results: Vec<TxnExecutionResult> =
            obj.getattr(py, "execution_results")?.extract(py)?;
        let block_id: String = obj.getattr(py, "block_id")?.extract(py)?;
        let num_transactions = obj.getattr(py, "num_transactions")?.extract(py)?;

        Ok(BlockValidationResult {
            block_id,
            execution_results,
            num_transactions,
            status,
        })
    }
}
