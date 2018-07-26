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

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use block::Block;
use journal::block_store::{BlockStore, BlockStoreError};
use journal::NULL_BLOCK_IDENTIFIER;

#[derive(Debug, PartialEq)]
pub enum BlockManagerError {
    MissingPredecessor(String),
    MissingPredecessorInBranch(String),
    MissingInput,
    UnknownBlock,
    UnknownBlockStore,
    BlockStoreError,
}

impl From<BlockStoreError> for BlockManagerError {
    fn from(_other: BlockStoreError) -> Self {
        BlockManagerError::BlockStoreError
    }
}

struct RefCount {
    pub block_id: String,
    pub previous_block_id: String,
    pub external_ref_count: u64,
    pub internal_ref_count: u64,
}

impl RefCount {
    fn new_reffed_block(block_id: String, previous_id: String) -> Self {
        RefCount {
            block_id,
            previous_block_id: previous_id,
            external_ref_count: 0,
            internal_ref_count: 1,
        }
    }

    fn new_unreffed_block(block_id: String, previous_id: String) -> Self {
        RefCount {
            block_id,
            previous_block_id: previous_id,
            external_ref_count: 1,
            internal_ref_count: 0,
        }
    }

    fn increase_internal_ref_count(&mut self) {
        self.internal_ref_count += 1;
    }

    fn decrease_internal_ref_count(&mut self) {
        match self.internal_ref_count.checked_sub(1) {
            Some(ref_count) => self.internal_ref_count = ref_count,
            None => panic!("The internal ref-count fell below zero, its lowest possible value"),
        }
    }

    fn increase_external_ref_count(&mut self) {
        self.external_ref_count += 1;
    }

    fn decrease_external_ref_count(&mut self) {
        match self.external_ref_count.checked_sub(1) {
            Some(ref_count) => self.external_ref_count = ref_count,
            None => panic!("The external ref-count fell below zero, its lowest possible value"),
        }
    }
}

/// An Enum describing where a block is found within the BlockManager.
/// This is used by iterators calling private methods.
enum BlockLocation<'a> {
    MainCache(&'a Block),
    InStore(&'a str),
    Unknown,
}

#[derive(Default)]
struct BlockManagerState {
    block_by_block_id: HashMap<String, Block>,

    blockstore_by_name: HashMap<String, Box<BlockStore>>,

    references_by_block_id: HashMap<String, RefCount>,
}

impl BlockManagerState {
    pub fn new() -> Self {
        BlockManagerState::default()
    }

    fn contains(&self, block_id: &str) -> bool {
        let in_memory = self.block_by_block_id.contains_key(block_id);

        let in_any_blockstore = self.blockstore_by_name
            .values()
            .any(|blockstore| blockstore.get(vec![block_id.into()]).count() > 0);
        let is_root = block_id == NULL_BLOCK_IDENTIFIER;

        in_memory || in_any_blockstore || is_root
    }

    /// Checks that every block is preceded by the block referenced by block.previous_block_id except the
    /// zeroth block in tail, which references head.
    fn check_predecessor_relationship(
        &self,
        tail: &[Block],
        head: &Block,
    ) -> Result<(), BlockManagerError> {
        let mut previous = None;
        for block in tail {
            match previous {
                Some(previous_block_id) => {
                    if block.previous_block_id != previous_block_id {
                        return Err(BlockManagerError::MissingPredecessorInBranch(format!(
                            "During Put, missing predecessor of block {}: {}",
                            block.header_signature, block.previous_block_id
                        )));
                    }
                    previous = Some(block.header_signature.as_str());
                }
                None => {
                    if block.previous_block_id != head.header_signature {
                        return Err(BlockManagerError::MissingPredecessorInBranch(format!(
                            "During Put, missing predecessor of block {}: {}",
                            block.previous_block_id, head.header_signature
                        )));
                    }

                    previous = Some(block.header_signature.as_str());
                }
            }
        }
        Ok(())
    }

    fn put(&mut self, branch: Vec<Block>) -> Result<(), BlockManagerError> {
        match branch.split_first() {
            Some((head, tail)) => {
                if !self.contains(head.previous_block_id.as_str()) {
                    return Err(BlockManagerError::MissingPredecessor(format!(
                        "During Put, missing predecessor of block {}: {}",
                        head.header_signature, head.previous_block_id
                    )));
                }

                self.check_predecessor_relationship(tail, head)?;
                if !self.contains(&head.header_signature) {
                    self.references_by_block_id
                        .get_mut(&head.previous_block_id)
                        .map(|r| r.increase_internal_ref_count());
                }
            }
            None => return Err(BlockManagerError::MissingInput),
        }
        let blocks_not_added_yet: Vec<Block> = branch
            .into_iter()
            .filter(|block| !self.contains(block.header_signature.as_str()))
            .collect();
        if let Some((last_block, blocks_with_references)) = blocks_not_added_yet.split_last() {
            self.references_by_block_id.insert(
                last_block.header_signature.clone(),
                RefCount::new_unreffed_block(
                    last_block.header_signature.clone(),
                    last_block.previous_block_id.clone(),
                ),
            );
            self.block_by_block_id
                .insert(last_block.header_signature.clone(), last_block.clone());

            blocks_with_references.into_iter().for_each(|block| {
                self.block_by_block_id
                    .insert(block.header_signature.clone(), block.clone());

                self.references_by_block_id.insert(
                    block.header_signature.clone(),
                    RefCount::new_reffed_block(
                        block.header_signature.clone(),
                        block.previous_block_id.clone(),
                    ),
                );
            })
        };
        Ok(())
    }

    fn get_block_by_block_id(&self, block_id: &str) -> Option<&Block> {
        self.block_by_block_id.get(block_id)
    }

    fn get_block_from_main_cache_or_blockstore_name<'a>(
        &'a self,
        block_id: &str,
    ) -> BlockLocation<'a> {
        let block = self.get_block_by_block_id(block_id);
        if block.is_some() {
            BlockLocation::MainCache(block.unwrap())
        } else {
            let name: Option<&'a str> = self.blockstore_by_name
                .iter()
                .find(|(name, store)| store.get(vec![block_id.to_string()]).count() > 0)
                .map(|(name, _)| name.as_str());

            name.map(BlockLocation::InStore)
                .unwrap_or(BlockLocation::Unknown)
        }
    }

    fn get_block_from_blockstore<'a>(
        &'a self,
        block_id: String,
        store_name: &str,
    ) -> Result<Option<&'a Block>, BlockManagerError> {
        Ok(self.blockstore_by_name
            .get(store_name)
            .ok_or(BlockManagerError::UnknownBlockStore)?
            .get(vec![block_id])
            .nth(0))
    }

    fn get_block_from_any_blockstore(&self, block_id: String) -> Option<&Block> {
        self.blockstore_by_name
            .values()
            .find(|blockstore| blockstore.get(vec![block_id.clone()]).count() > 0)
            .map(|blockstore| blockstore.get(vec![block_id]).nth(0).unwrap())
    }

    fn ref_block(&mut self, block_id: &str) -> Result<(), BlockManagerError> {
        match self.references_by_block_id.get_mut(block_id) {
            Some(r) => r.increase_external_ref_count(),
            None => return Err(BlockManagerError::UnknownBlock),
        }
        Ok(())
    }

    fn unref_block(&mut self, tip: &str) -> Result<(), BlockManagerError> {
        let (external_ref_count, internal_ref_count, block_id) =
            self.lower_tip_blocks_refcount(tip)?;

        let mut blocks_to_remove = vec![];

        let mut optional_new_tip = None;

        if external_ref_count == 0 && internal_ref_count == 0 {
            if let Some(block_id) = block_id {
                let (mut predecesors_to_remove, new_tip) =
                    self.find_block_ids_for_blocks_with_refcount_1_or_less(&block_id);
                blocks_to_remove.append(&mut predecesors_to_remove);
                self.block_by_block_id.remove(tip);
                optional_new_tip = new_tip;
            }
        }

        blocks_to_remove.iter().for_each(|block_id| {
            self.block_by_block_id.remove(block_id.as_str());
        });

        if let Some(block_id) = optional_new_tip {
            if let Some(ref mut new_tip) = self.references_by_block_id.get_mut(block_id.as_str()) {
                new_tip.decrease_internal_ref_count();
            };
        };

        Ok(())
    }

    fn lower_tip_blocks_refcount(
        &mut self,
        tip: &str,
    ) -> Result<(u64, u64, Option<String>), BlockManagerError> {
        match self.references_by_block_id.get_mut(tip) {
            Some(ref mut ref_block) => {
                if ref_block.external_ref_count > 0 {
                    ref_block.decrease_external_ref_count();
                }
                Ok((
                    ref_block.external_ref_count,
                    ref_block.internal_ref_count,
                    Some(ref_block.block_id.clone()),
                ))
            }
            None => Err(BlockManagerError::UnknownBlock),
        }
    }

    /// Starting from some `tip` block_id, walk back until finding a block that has a
    /// internal ref_count >= 2 or an external_ref_count > 0.
    fn find_block_ids_for_blocks_with_refcount_1_or_less(
        &mut self,
        tip: &str,
    ) -> (Vec<String>, Option<String>) {
        let mut blocks_to_remove = vec![];
        let mut block_id = tip;
        let pointed_to;
        loop {
            if let Some(ref ref_block) = self.references_by_block_id.get(block_id) {
                if ref_block.internal_ref_count >= 2 || ref_block.external_ref_count >= 1 {
                    pointed_to = Some(block_id.into());
                    break;
                } else if ref_block.previous_block_id == NULL_BLOCK_IDENTIFIER {
                    blocks_to_remove.push(block_id.into());
                    pointed_to = None;
                    break;
                } else {
                    blocks_to_remove.push(block_id.into());
                }
                block_id = &ref_block.previous_block_id;
            }
        }
        (blocks_to_remove, pointed_to)
    }

    fn add_store(
        &mut self,
        store_name: &str,
        store: Box<BlockStore>,
    ) -> Result<(), BlockManagerError> {
        self.blockstore_by_name.insert(store_name.into(), store);
        Ok(())
    }
}

/// The BlockManager maintains integrity of all the blocks it contains,
/// such that for any Block within the BlockManager,
/// that Block's predecessor is also within the BlockManager.
#[derive(Default)]
pub struct BlockManager {
    state: Arc<RwLock<BlockManagerState>>,
}

impl BlockManager {
    pub fn new() -> Self {
        BlockManager::default()
    }

    /// Put is idempotent, making the guarantee that after put is called with a
    /// block in the vector argument, that block is in the BlockManager
    /// whether or not it was already in the BlockManager.
    /// Put makes three other guarantees
    ///     - If the zeroth block in branch does not have its predecessor
    ///       in the BlockManager an error is returned
    ///     - If any block after the zeroth block in branch
    ///       does not have its predecessor as the block to its left in
    ///       branch, an error is returned.
    ///     - If branch is empty, an error is returned
    pub fn put(&self, branch: Vec<Block>) -> Result<(), BlockManagerError> {
        let mut state = self.state
            .write()
            .expect("No lock holder has poisoned the lock");

        Ok(state.put(branch)?)
    }

    pub fn get<'a>(&self, block_ids: &'a [&'a str]) -> Box<Iterator<Item = Block>> {
        Box::new(GetBlockIterator::new(Arc::clone(&self.state), block_ids))
    }

    pub fn branch(&self, tip: &str) -> Box<Iterator<Item = Block>> {
        Box::new(BranchIterator::new(Arc::clone(&self.state), tip.into()))
    }

    pub fn branch_diff(&self, tip: &str, exclude: &str) -> Box<Iterator<Item = Block>> {
        Box::new(BranchDiffIterator::new(
            Arc::clone(&self.state),
            tip,
            exclude,
        ))
    }

    /// Starting at a tip block, if the tip block's ref-count drops to 0,
    /// remove all blocks until a ref-count of 1 is found.
    pub fn unref_block(&mut self, tip: &str) -> Result<(), BlockManagerError> {
        let mut state = self.state
            .write()
            .expect("No lock holder has poisoned the lock");
        Ok(state.unref_block(tip)?)
    }

    pub fn persist(&self, head: &str, store_name: &str) -> Result<(), BlockManagerError> {
        let mut state = self.state
            .write()
            .expect("No lock holder has poisoned the lock");

        Ok(self.persist_internal(&mut state, head, store_name)?)
    }

    pub fn add_store(
        &mut self,
        store_name: &str,
        store: Box<BlockStore>,
    ) -> Result<(), BlockManagerError> {
        let mut state = self.state
            .write()
            .expect("No lock holder has poisoned the lock");

        Ok(state.add_store(store_name, store)?)
    }

    fn remove_blocks_from_blockstore(
        &self,
        state: &mut BlockManagerState,
        head: &str,
        other: &str,
        store_name: &str,
    ) -> Result<(), BlockManagerError> {
        let to_be_removed: Vec<Block> = self.branch_diff(other, head).collect();

        let blockstore = state
            .blockstore_by_name
            .get_mut(store_name)
            .ok_or(BlockManagerError::UnknownBlockStore)?;

        let blocks_for_the_main_pool = blockstore.delete(
            to_be_removed
                .iter()
                .map(|b| b.header_signature.clone())
                .collect(),
        )?;
        for block in blocks_for_the_main_pool {
            state
                .block_by_block_id
                .insert(block.header_signature.clone(), block);
        }

        Ok(())
    }

    fn insert_blocks_in_blockstore(
        &self,
        state: &mut BlockManagerState,
        head: &str,
        other: &str,
        store_name: &str,
    ) -> Result<(), BlockManagerError> {
        let to_be_inserted: Vec<Block> = self.branch_diff(head, other).collect();

        let blockstore = state
            .blockstore_by_name
            .get_mut(store_name)
            .ok_or(BlockManagerError::UnknownBlockStore)?;
        blockstore.put(to_be_inserted)?;
        Ok(())
    }

    fn persist_internal(
        &self,
        mut state: &mut BlockManagerState,
        head: &str,
        store_name: &str,
    ) -> Result<(), BlockManagerError> {
        if !state.blockstore_by_name.contains_key(store_name) {
            return Err(BlockManagerError::UnknownBlockStore);
        }

        let head_block_in_blockstore = state
            .blockstore_by_name
            .get(store_name)
            .expect("Blockstore removed during persist operation")
            .iter()
            .nth(0)
            .map(|b| b.header_signature.clone());

        if let Some(head_block_in_blockstore) = head_block_in_blockstore {
            let other = head_block_in_blockstore.as_str();

            self.remove_blocks_from_blockstore(&mut state, head, other, store_name)?;

            self.insert_blocks_in_blockstore(&mut state, head, other, store_name)?;
        } else {
            // There are no other blocks in the blockstore and so
            // we would like to insert all of the blocks
            self.insert_blocks_in_blockstore(&mut state, head, "NULL", store_name)?;
        }

        Ok(())
    }
}

struct GetBlockIterator {
    state: Arc<RwLock<BlockManagerState>>,
    block_ids: Vec<String>,
    index: usize,
}

impl GetBlockIterator {
    pub fn new(state: Arc<RwLock<BlockManagerState>>, block_ids: &[&str]) -> Self {
        GetBlockIterator {
            state,
            block_ids: block_ids.iter().map(|s| (*s).into()).collect(),
            index: 0,
        }
    }
}

impl Iterator for GetBlockIterator {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        let block = match self.block_ids.get(self.index) {
            Some(ref block_id) => {
                let state = self.state
                    .read()
                    .expect("No lock holder has poisoned the lock");
                match state.get_block_from_main_cache_or_blockstore_name(block_id) {
                    BlockLocation::MainCache(block) => Some(block.clone()),
                    BlockLocation::InStore(blockstore_name) => state
                        .get_block_from_blockstore((*block_id).clone(), blockstore_name)
                        .expect("An anchor pointed to a blockstore that does not exist")
                        .cloned(),
                    BlockLocation::Unknown => state
                        .get_block_from_any_blockstore((*block_id).clone())
                        .cloned(),
                }
            }
            None => None,
        };
        self.index += 1;
        block
    }
}

struct BranchIterator {
    state: Arc<RwLock<BlockManagerState>>,
    next_block_id: String,
    blockstore: Option<String>,
}

impl BranchIterator {
    pub fn new(state: Arc<RwLock<BlockManagerState>>, first_block_id: String) -> Self {
        BranchIterator {
            state,
            next_block_id: first_block_id,
            blockstore: None,
        }
    }
}

impl Iterator for BranchIterator {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_block_id == NULL_BLOCK_IDENTIFIER {
            None
        } else if self.blockstore.is_none() {
            let state = self.state
                .read()
                .expect("No lock holder should have poisoned the lock");

            match state.get_block_from_main_cache_or_blockstore_name(&self.next_block_id) {
                BlockLocation::MainCache(block) => {
                    self.next_block_id = block.previous_block_id.clone();
                    Some(block.clone())
                }
                BlockLocation::InStore(blockstore_name) => {
                    self.blockstore = Some(blockstore_name.into());
                    state
                        .get_block_from_blockstore(self.next_block_id.clone(), blockstore_name)
                        .expect("Blockstore referenced by anchor does not exist")
                        .cloned()
                }
                BlockLocation::Unknown => None,
            }
        } else {
            let blockstore_id = self.blockstore.as_ref().unwrap();

            let state = self.state
                .read()
                .expect("No lock holder should have poisoned the lock");
            let block = state
                .get_block_from_blockstore(self.next_block_id.clone(), blockstore_id)
                .expect("The Blockmanager has lost a blockstore that is referenced by an anchor")
                .expect(
                    "The block was not in the blockstore referenced by a successor block's anchor",
                );
            Some(block.clone())
        }
    }
}

struct BranchDiffIterator {
    state: Arc<RwLock<BlockManagerState>>,

    left_block: Option<Block>,
    right_block: Option<Block>,

    blockstore: Option<String>,

    has_reached_common_ancestor: bool,
}

impl BranchDiffIterator {
    fn new(state: Arc<RwLock<BlockManagerState>>, tip: &str, exclude: &str) -> Self {
        let mut iterator = BranchDiffIterator {
            state,
            left_block: None,
            right_block: None,

            blockstore: None,
            has_reached_common_ancestor: false,
        };

        iterator.left_block = iterator.get_block_by_block_id(tip.into());
        iterator.right_block = iterator.get_block_by_block_id(exclude.into());

        if let Some(left) = iterator.left_block.clone() {
            if let Some(right) = iterator.right_block.clone() {
                let difference = iterator.block_num_difference(&left, &right);
                if difference < 0 {
                    iterator.right_block = iterator.get_nth_previous_block(
                        right.header_signature.clone(),
                        difference.abs() as u64,
                    );
                }
            }
        }

        iterator
    }

    fn block_num_difference(&self, left: &Block, right: &Block) -> i64 {
        left.block_num as i64 - right.block_num as i64
    }

    fn get_previous_block(&mut self, block_id: String) -> Option<Block> {
        let block = self.get_block_by_block_id(block_id);
        block
            .map(|b| self.get_block_by_block_id(b.previous_block_id.clone()))
            .unwrap_or(None)
    }

    fn get_nth_previous_block(&mut self, block_id: String, n: u64) -> Option<Block> {
        if n == 0 {
            return None;
        }

        let mut current_block_id = block_id;

        let mut block = self.get_previous_block(current_block_id.clone());
        if let Some(ref b) = block {
            current_block_id = b.header_signature.clone();
        }

        for _ in 1..n {
            block = self.get_previous_block(current_block_id.clone());
            if let Some(ref b) = block {
                current_block_id = b.header_signature.clone();
            }
        }
        block
    }

    fn get_block_by_block_id(&mut self, block_id: String) -> Option<Block> {
        if block_id == NULL_BLOCK_IDENTIFIER {
            None
        } else if self.blockstore.is_none() {
            let state = self.state
                .read()
                .expect("No lock holder has poisoned the lock");
            match state.get_block_from_main_cache_or_blockstore_name(block_id.as_str()) {
                BlockLocation::MainCache(block) => Some(block.clone()),
                BlockLocation::InStore(blockstore_name) => {
                    self.blockstore = Some(blockstore_name.into());
                    state
                        .get_block_from_blockstore(block_id, blockstore_name)
                        .expect("Blockstore referenced by anchor does not exist")
                        .cloned()
                }
                BlockLocation::Unknown => None,
            }
        } else {
            let blockstore_id = self.blockstore.as_ref().unwrap();
            let state = self.state
                .read()
                .expect("No lock holder has poisoned the lock");
            let block = state
                .get_block_from_blockstore(block_id.clone(), blockstore_id)
                .expect("The Blockmanager has lost a blockstore that is referenced by an anchor")
                .expect(
                    "The block was not in the blockstore referenced by a successor block's anchor",
                );
            Some(block.clone())
        }
    }
}

impl Iterator for BranchDiffIterator {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_reached_common_ancestor {
            None
        } else if let Some(ref left) = self.left_block.clone() {
            if let Some(ref right) = self.right_block.clone() {
                if left.header_signature == NULL_BLOCK_IDENTIFIER {
                    return None;
                }
                if left.header_signature == right.header_signature
                    && left.block_num == right.block_num
                {
                    self.has_reached_common_ancestor = true;
                    return None;
                }
                let difference = self.block_num_difference(&left, &right);
                if difference > 0 {
                    self.left_block = self.get_previous_block(left.header_signature.clone());
                } else {
                    self.left_block = self.get_previous_block(left.header_signature.clone());
                    self.right_block = self.get_previous_block(right.header_signature.clone());
                }
                Some(left.clone())
            } else {
                self.left_block = self.get_previous_block(left.header_signature.clone());
                Some(left.clone())
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{BlockManager, BlockManagerError};
    use block::Block;
    use journal::block_store::InMemoryBlockStore;
    use journal::NULL_BLOCK_IDENTIFIER;

    fn create_block(header_signature: &str, previous_block_id: &str, block_num: u64) -> Block {
        Block {
            header_signature: header_signature.into(),
            batches: vec![],
            state_root_hash: "".into(),
            consensus: vec![],
            batch_ids: vec![],
            signer_public_key: "".into(),
            previous_block_id: previous_block_id.into(),
            block_num,
            header_bytes: vec![],
        }
    }

    #[test]
    fn test_put_ref_then_unref() {
        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let b_block_id = b.header_signature.clone();
        let c = create_block("C", "B", 2);
        let c_block_id = c.header_signature.clone();

        let mut block_manager = BlockManager::new();
        assert_eq!(block_manager.put(vec![a, b]), Ok(()));

        assert_eq!(block_manager.put(vec![c]), Ok(()));

        block_manager.ref_block(b_block_id.as_str()).unwrap();
        block_manager.unref_block(c_block_id.as_str()).unwrap();

        let d = create_block("D", "C", 3);

        assert_eq!(
            block_manager.put(vec![d]),
            Err(BlockManagerError::MissingPredecessor(format!(
                "During Put, missing predecessor of block D: C"
            )))
        );

        let e = create_block("E", "B", 2);

        block_manager.put(vec![e]).unwrap();
    }

    #[test]
    fn test_multiple_branches_put_ref_then_unref() {
        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let c = create_block("C", "B", 2);
        let c_block_id = &c.header_signature.clone();
        let d = create_block("D", "C", 3);
        let d_block_id = &d.header_signature.clone();
        let e = create_block("E", "C", 3);

        let f = create_block("F", "E", 4);
        let f_block_id = &f.header_signature.clone();

        let mut block_manager = BlockManager::new();
        block_manager.put(vec![a.clone(), b, c]).unwrap();
        block_manager.put(vec![d]).unwrap();
        block_manager.put(vec![e, f]).unwrap();

        block_manager.unref_block(d_block_id).unwrap();

        block_manager.unref_block(f_block_id).unwrap();

        let q = create_block("Q", "C", 3);
        let q_block_id = &q.header_signature.clone();
        block_manager.put(vec![q]).unwrap();
        block_manager.unref_block(c_block_id).unwrap();
        block_manager.unref_block(q_block_id).unwrap();

        let g = create_block("G", "A", 1);
        assert_eq!(
            block_manager.put(vec![g]),
            Err(BlockManagerError::MissingPredecessor(format!(
                "During Put, missing predecessor of block G: A"
            )))
        );
    }

    #[test]
    fn test_put_empty_vec() {
        let mut block_manager = BlockManager::new();
        assert_eq!(
            block_manager.put(vec![]),
            Err(BlockManagerError::MissingInput)
        );
    }

    #[test]
    fn test_put_missing_predecessor() {
        let mut block_manager = BlockManager::new();
        let a = create_block("A", "o", 54);
        let b = create_block("B", "A", 55);
        assert_eq!(
            block_manager.put(vec![a, b]),
            Err(BlockManagerError::MissingPredecessor(format!(
                "During Put, missing predecessor of block A: o"
            )))
        );
    }

    #[test]
    fn test_get_blocks() {
        let mut block_manager = BlockManager::new();
        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let c = create_block("C", "B", 2);

        block_manager
            .put(vec![a.clone(), b.clone(), c.clone()])
            .unwrap();

        let mut get_block_iter = block_manager.get(&["A", "C", "D"]);

        assert_eq!(get_block_iter.next(), Some(&a));
        assert_eq!(get_block_iter.next(), Some(&c));
        assert_eq!(get_block_iter.next(), None);
        assert_eq!(get_block_iter.next(), None);
    }

    #[test]
    fn test_branch_in_memory() {
        let mut block_manager = BlockManager::new();
        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let c = create_block("C", "B", 2);

        block_manager
            .put(vec![a.clone(), b.clone(), c.clone()])
            .unwrap();

        let mut branch_iter = block_manager.branch("C");

        assert_eq!(branch_iter.next(), Some(&c));
        assert_eq!(branch_iter.next(), Some(&b));
        assert_eq!(branch_iter.next(), Some(&a));
        assert_eq!(branch_iter.next(), None);

        let mut empty_iter = block_manager.branch("P");

        assert_eq!(empty_iter.next(), None);
    }

    #[test]
    fn test_branch_diff() {
        let mut block_manager = BlockManager::new();

        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let c = create_block("C", "A", 1);
        let d = create_block("D", "C", 2);
        let e = create_block("E", "D", 3);

        block_manager.put(vec![a.clone(), b.clone()]).unwrap();
        block_manager.put(vec![c.clone()]).unwrap();
        block_manager.put(vec![d.clone(), e.clone()]).unwrap();

        let mut branch_diff_iter = block_manager.branch_diff("C", "B");

        assert_eq!(branch_diff_iter.next(), Some(&c));
        assert_eq!(branch_diff_iter.next(), None);

        let mut branch_diff_iter2 = block_manager.branch_diff("B", "E");

        assert_eq!(branch_diff_iter2.next(), Some(&b));
        assert_eq!(branch_diff_iter2.next(), None);

        let mut branch_diff_iter3 = block_manager.branch_diff("C", "E");

        assert_eq!(branch_diff_iter3.next(), None);

        let mut branch_diff_iter4 = block_manager.branch_diff("E", "C");

        assert_eq!(branch_diff_iter4.next(), Some(&e));
        assert_eq!(branch_diff_iter4.next(), Some(&d));
        assert_eq!(branch_diff_iter4.next(), None);
    }

    #[test]
    fn test_persist_ref_unref() {
        let mut block_manager = BlockManager::new();

        let a = create_block("A", NULL_BLOCK_IDENTIFIER, 0);
        let b = create_block("B", "A", 1);
        let c = create_block("C", "A", 1);
        let d = create_block("D", "C", 2);
        let e = create_block("E", "D", 3);
        let f = create_block("F", "C", 2);

        let q = create_block("Q", "F", 3);
        let p = create_block("P", "E", 4);

        block_manager.put(vec![a.clone(), b.clone()]).unwrap();
        block_manager
            .put(vec![c.clone(), d.clone(), e.clone()])
            .unwrap();
        block_manager.put(vec![f.clone()]).unwrap();

        let blockstore = Box::new(InMemoryBlockStore::new());
        block_manager.add_store("commit", blockstore).unwrap();

        block_manager.persist("C", "commit").unwrap();
        block_manager.persist("B", "commit").unwrap();

        block_manager.ref_block("D").unwrap();

        block_manager.persist("C", "commit").unwrap();
        block_manager.unref_block("B").unwrap();

        block_manager.persist("F", "commit").unwrap();
        block_manager.persist("E", "commit").unwrap();

        block_manager.unref_block("F").unwrap();
        block_manager.unref_block("D").unwrap();

        block_manager.persist("A", "commit").unwrap();

        block_manager.unref_block("E").unwrap();

        assert_eq!(
            block_manager.put(vec![q]),
            Err(BlockManagerError::MissingPredecessor(format!(
                "During Put, missing predecessor of block Q: F"
            )))
        );

        assert_eq!(
            block_manager.put(vec![p]),
            Err(BlockManagerError::MissingPredecessor(format!(
                "During Put, missing predecessor of block P: E"
            )))
        );
    }
}
