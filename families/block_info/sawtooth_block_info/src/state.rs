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

use addressing::{create_block_address, get_config_addr};

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
        use sabre_sdk::TransactionContext;
    } else {
        use sawtooth_sdk::processor::ApplyError;
        use sawtooth_sdk::processor::TransactionContext;
    }
}



pub struct BlockInfoState<'a> {
    context: &'a mut TransactionContext,
}
impl<'a> BlockInfoState<'a> {
    pub fn new(context: &'a mut TransactionContext) -> BlockInfoState {
        BlockInfoState { context }
    }

    pub fn get_state(
        &mut self,
    ) -> Result<BlockInfoState, ApplyError> {
        let state_data = self.context.get_state(vec![get_config_addr()]);
        Ok(state_data)
    }

    pub fn get_state_at_block(
        &mut self,
        block_num: u64,
    ) -> Result<BlockInfoState, ApplyError> {
        let state_data = self.context.get_state(vec![create_block_address(block_num)]);
        Ok(state_data)
    }

    pub fn set_state(
        &mut self,
        sets: Vec<(String, Vec<u8>)>,
    ) -> Result<(), ApplyError> {
        self.context.set_state(sets)
    }

    pub fn delete_state(
        &mut self,
        deletes: Vec<String>,
    ) -> Result<(), ApplyError> {
        self.context.delete_state(deletes.to_vec())
    }

}
