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

use std::sync::mpsc::Sender;

use cpython;
use cpython::{FromPyObject, ObjectProtocol, PyObject, Python};

use batch::Batch;
use block::Block;
use execution::execution_platform::ExecutionPlatform;
use gossip::permission_verifier::PermissionVerifier;
use journal::block_manager::BlockManager;
use journal::block_store::{BatchIndex, BlockStore, TransactionIndex};
use journal::block_wrapper::BlockStatus;
use journal::validation_rule_enforcer::enforce_validation_rules;
use scheduler::TxnExecutionResult;
use state::{settings_view::SettingsView, state_view_factory::StateViewFactory};

#[derive(Debug)]
pub enum ValidationError {
    BlockValidationFailure(String),
    BlockValidationError(String),
}

pub trait BlockValidator: Sync + Send + Clone {
    fn has_block(&self, block_id: &str) -> bool;

    fn validate_block(&self, block: Block) -> Result<(), ValidationError>;

    fn submit_blocks_for_verification(
        &self,
        blocks: &[Block],
        response_sender: Sender<BlockValidationResult>,
    );

    fn process_pending(&self, block: &Block, response_sender: Sender<BlockValidationResult>);
}

pub trait BlockStatusStore {
    fn status(&self, block_id: &str) -> BlockStatus;
}

#[derive(Clone, Debug)]
pub struct BlockValidationResult {
    pub block_id: String,
    pub execution_results: Vec<TxnExecutionResult>,
    pub num_transactions: u64,
    pub status: BlockStatus,
}

impl<'source> FromPyObject<'source> for BlockValidationResult {
    fn extract(py: Python, obj: &'source PyObject) -> cpython::PyResult<Self> {
        let status: BlockStatus = obj.getattr(py, "status")?.extract(py)?;
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

#[derive(Clone)]
pub struct BlockValidations<
    TEP: ExecutionPlatform,
    PV: PermissionVerifier,
    BS: BlockStore,
    B: BatchIndex,
    T: TransactionIndex,
> {
    transaction_executor: TEP,
    permission_verifier: PV,
    view_factory: StateViewFactory,
    block_store: BS,
    batch_index: B,
    transaction_index: T,
    block_manager: BlockManager,
}

impl<
        TEP: ExecutionPlatform,
        PV: PermissionVerifier,
        BS: BlockStore,
        B: BatchIndex,
        T: TransactionIndex,
    > BlockValidations<TEP, PV, BS, B, T>
where
    B: Clone,
    T: Clone,
{
    fn new(
        block_manager: BlockManager,
        transaction_executor: TEP,
        permission_verifier: PV,
        view_factory: StateViewFactory,
        block_store: BS,
        batch_index: B,
        transaction_index: T,
    ) -> Self {
        BlockValidations {
            transaction_executor,
            permission_verifier,
            view_factory,
            block_store,
            batch_index,
            transaction_index,
            block_manager,
        }
    }

    fn validate_block(&self, block: Block) -> Result<BlockValidationResult, ValidationError> {
        let mut chain_head_option = self
            .block_store
            .iter()
            .map_err(|err| {
                ValidationError::BlockValidationError(format!(
                    "There was an error reading from the BlockStore: {:?}",
                    err
                ))
            })?.next()
            .map(|b| b.header_signature.clone());

        loop {
            if let Some(chain_head_id) = chain_head_option {
                self.validate_duplicates_and_dependencies(&block)?;
                if !self.check_chain_head_updated(&chain_head_id)? {
                    break;
                }
            } else {
                warn!(
                    "Tried to validate block {} without a chainhead.",
                    &block.header_signature
                );
                return Err(ValidationError::BlockValidationError(format!(
                    "Tried to validate block {} without a chainhead",
                    &block.header_signature
                )));
            }

            chain_head_option = self
                .block_store
                .iter()
                .map_err(|err| {
                    ValidationError::BlockValidationError(format!(
                        "There was an error reading from the BlockStore: {:?}",
                        err
                    ))
                })?.next()
                .map(|b| b.header_signature.clone());
        }
        if let Some(Some(previous_block)) =
            self.block_manager.get(&[&block.previous_block_id]).next()
        {
            self.validate_permissions(&block, &previous_block.state_root_hash)?;
            self.validate_on_chain_rules(&block, &previous_block.state_root_hash)?;
            Ok(self.validate_batches_in_block(block, &previous_block.state_root_hash)?)
        } else {
            warn!(
                "During block validation, unable to get predecessor of {}, to get state hash for permission and on_chain_rules validation",
                &block.header_signature
            );

            Err(ValidationError::BlockValidationError(format!(
                "Unable to get block {}, predecessor of block being validated {}",
                &block.previous_block_id, &block.header_signature,
            )))
        }
    }

    fn validate_batches_in_block(
        &self,
        block: Block,
        previous_state_root: &str,
    ) -> Result<BlockValidationResult, ValidationError> {
        let ending_state_hash = &block.state_root_hash;

        let mut scheduler = self
            .transaction_executor
            .create_scheduler(previous_state_root)
            .map_err(|err| {
                ValidationError::BlockValidationError(format!(
                    "Error during validation of block {} batches: {:?}",
                    &block.header_signature, err,
                ))
            })?;

        let greatest_batch_index = block.batches.len() - 1;
        let mut index = 0;
        for batch in block.batches {
            if index < greatest_batch_index {
                scheduler.add_batch(batch, None, false).map_err(|err| {
                    ValidationError::BlockValidationError(format!(
                        "While adding a batch to the schedule: {:?}",
                        err
                    ))
                })?;
            } else {
                scheduler
                    .add_batch(batch, Some(ending_state_hash), false)
                    .map_err(|err| {
                        ValidationError::BlockValidationError(format!(
                            "While adding the last batch to the schedule: {:?}",
                            err
                        ))
                    })?;
            }
            index += 1;
        }
        let execution_results = scheduler
            .complete(true)
            .map_err(|err| {
                ValidationError::BlockValidationError(format!(
                    "During call to scheduler.complete: {:?}",
                    err
                ))
            })?.ok_or(ValidationError::BlockValidationFailure(format!(
                "Block {} failed validation: no execution results produced",
                &block.header_signature
            )))?;

        if let Some(ref actual_ending_state_hash) = execution_results.ending_state_hash {
            if ending_state_hash != actual_ending_state_hash {
                return Err(ValidationError::BlockValidationFailure(format!(
                "Block {} failed validation: expected state hash {}, validation found state hash {}",
                &block.header_signature,
                ending_state_hash,
                actual_ending_state_hash
            )));
            }
        } else {
            return Err(ValidationError::BlockValidationFailure(format!(
                "Block {} failed validation: no ending state hash was produced",
                &block.header_signature
            )));
        }

        let mut results = vec![];
        for (batch_id, transaction_execution_results) in execution_results.batch_results {
            if let Some(txn_results) = transaction_execution_results {
                for r in txn_results {
                    if !r.is_valid {
                        return Err(ValidationError::BlockValidationFailure(format!(
                            "Block {} failed validation: batch {} was invalid due to transaction {}",
                            &block.header_signature,
                            &batch_id,
                            &r.signature)));
                    }
                    results.push(r);
                }
            } else {
                return Err(ValidationError::BlockValidationFailure(format!(
                    "Block {} failed validation: batch {} did not have transaction results",
                    &block.header_signature, &batch_id
                )));
            }
        }
        Ok(BlockValidationResult {
            block_id: block.header_signature,
            num_transactions: results.len() as u64,
            execution_results: results,
            status: BlockStatus::Valid,
        })
    }

    fn validate_duplicates_and_dependencies(&self, block: &Block) -> Result<(), ValidationError> {
        let chain_commit_state = ChainCommitState::new(
            &block.previous_block_id,
            &self.block_manager,
            self.batch_index.clone(),
            self.transaction_index.clone(),
            self.block_store.clone(),
        );
    }

    fn validate_permissions(
        &self,
        block: &Block,
        prev_state_root: &str,
    ) -> Result<(), ValidationError> {
        if block.block_num != 0 {
            for batch in &block.batches {
                let batch_id = &batch.header_signature;
                if !self.permission_verifier.is_batch_signer_authorized(
                    batch,
                    prev_state_root,
                    true,
                ) {
                    return Err(ValidationError::BlockValidationError(
                            format!("Block {} failed permission verification: batch {} signer is not authorized",
                            &block.header_signature,
                            batch_id)));
                }
            }
        }
        Ok(())
    }

    fn validate_on_chain_rules(
        &self,
        block: &Block,
        prev_state_root: &str,
    ) -> Result<(), ValidationError> {
        if block.block_num != 0 {
            let settings_view: SettingsView = self
                .view_factory
                .create_view(prev_state_root)
                .map_err(|err| {
                    ValidationError::BlockValidationError(format!(
                        "During validate_on_chain_rules, error creating settings view: {:?}",
                        err
                    ))
                })?;
            let batches: Vec<&Batch> = block.batches.iter().collect();
            if !enforce_validation_rules(&settings_view, &block.signer_public_key, &batches) {
                return Err(ValidationError::BlockValidationFailure(format!(
                    "Block {} failed validation rules",
                    &block.header_signature
                )));
            }
        }
        Ok(())
    }

    fn check_chain_head_updated(&self, original_chain_head: &str) -> Result<bool, ValidationError> {
        let chain_head = self
            .block_store
            .iter()
            .map_err(|err| {
                ValidationError::BlockValidationError(format!(
                    "There was an error reading from the BlockStore: {:?}",
                    err
                ))
            })?.next()
            .expect("During block validation, the block store has no chain head");

        if chain_head.header_signature != original_chain_head {
            return Ok(true);
        }
        Ok(false)
    }
}
