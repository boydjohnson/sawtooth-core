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

use cpython::{self, ObjectProtocol};

use batch::Batch;
use transaction::Transaction;

pub trait PermissionVerifier {
    fn is_batch_signer_authorized(&self, batch: &Batch, state_root: &str, from_state: bool)
        -> bool;
}

impl PermissionVerifier for cpython::PyObject {
    fn is_batch_signer_authorized(
        &self,
        batch: &Batch,
        state_root: &str,
        from_state: bool,
    ) -> bool {
        let gil = cpython::Python::acquire_gil();
        let py = gil.python();

        self.call_method(
            py,
            "is_batch_signer_authorized",
            (batch, state_root, from_state),
            None,
        ).expect("PermissionVerifier has not method `is_batch_signer_authorized`")
            .extract(py)
            .expect("Unable to extract bool from `is_batch_signer_authorized`")
    }
}
