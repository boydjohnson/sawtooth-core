#![feature(test)]

extern crate cpython;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate sawtooth_perf;
extern crate sawtooth_sdk;
extern crate sawtooth_smallbank_workload;
extern crate sawtooth_validator;
extern crate test;

use cpython::{ObjectProtocol, PyObject, Python};
use protobuf::Message;
use sawtooth_perf::batch_gen::SignedBatchIterator;
use sawtooth_sdk::messages::{batch::BatchHeader, transaction::TransactionHeader};
use sawtooth_sdk::signing;
use sawtooth_smallbank_workload::playlist::SmallbankGeneratingIter;
use sawtooth_smallbank_workload::smallbank_transformer;
use sawtooth_validator::batch::Batch;
use sawtooth_validator::block::Block;
use sawtooth_validator::journal::block_manager::BlockManager;
use sawtooth_validator::journal::block_store::IndexedBlockStore;
use sawtooth_validator::journal::block_validator::DuplicatesAndDependenciesValidation;
use sawtooth_validator::journal::chain_ffi::PyBlockStore;
use sawtooth_validator::journal::NULL_BLOCK_IDENTIFIER;
use sawtooth_validator::transaction::Transaction;
use test::Bencher;

const ACCOUNTS: usize = 100;
const TXNS_PER_BATCH: usize = 1;
const BATCHES_PER_BLOCK: u64 = 500;

lazy_static! {
    static ref PY_BLOCK_STORE: PyObject = Python::acquire_gil()
        .python()
        .import("sawtooth_validator.journal.block_store")
        .expect("Unable to import block store")
        .get(Python::acquire_gil().python(), "BlockStore")
        .expect("Unable to get BlockStore");
}

lazy_static! {
    static ref PY_INDEXED_DATABASE: PyObject = Python::acquire_gil()
        .python()
        .import("sawtooth_validator.database.indexed_database")
        .expect("Unable to import indexed_database")
        .get(Python::acquire_gil().python(), "IndexedDatabase")
        .expect("Unable to get IndexedDatabase");
}

struct BlockIterator<'a> {
    batch_iter: SignedBatchIterator<'a>,
    previous_block_id: String,
    block_num: u64,
    signer: &'a signing::Signer<'a>,
}

impl<'a> BlockIterator<'a> {
    fn new(batch_iter: SignedBatchIterator<'a>, signer: &'a signing::Signer) -> Self {
        BlockIterator {
            batch_iter,
            previous_block_id: NULL_BLOCK_IDENTIFIER.to_string(),
            block_num: 0,
            signer,
        }
    }
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batches = vec![];
        for _ in 1..BATCHES_PER_BLOCK {
            if let Some(batch) = self
                .batch_iter
                .next()
                .map(|b| b.ok().map(|b| from_sdk_proto(b)))
                .unwrap_or(None)
            {
                batches.push(batch);
            }
        }

        let signature = self.signer.sign(self.previous_block_id.as_bytes()).unwrap();
        let block = create_block(
            batches,
            self.block_num,
            signature.clone(),
            self.previous_block_id.clone(),
        );
        self.previous_block_id = signature;

        Some(block)
    }
}

fn from_sdk_proto(other: ::sawtooth_sdk::messages::batch::Batch) -> Batch {
    let mut header = BatchHeader::new();
    header.merge_from_bytes(&other.header).unwrap();

    Batch {
        header_signature: other.header_signature,
        transaction_ids: header.transaction_ids.to_vec(),
        transactions: other
            .transactions
            .into_iter()
            .map(|t| transaction_from_sdk_proto(t))
            .collect(),
        header_bytes: other.header,
        signer_public_key: header.signer_public_key,
        trace: other.trace,
    }
}

fn transaction_from_sdk_proto(
    other: ::sawtooth_sdk::messages::transaction::Transaction,
) -> Transaction {
    let mut header = TransactionHeader::new();
    header.merge_from_bytes(&other.header).unwrap();

    Transaction {
        batcher_public_key: header.batcher_public_key,
        header_signature: other.header_signature,
        header_bytes: other.header,
        signer_public_key: header.signer_public_key,
        payload: other.payload,
        dependencies: header.dependencies.to_vec(),
        family_name: header.family_name,
        family_version: header.family_version,
        inputs: header.inputs.to_vec(),
        outputs: header.outputs.to_vec(),
        nonce: header.nonce,
        payload_sha512: header.payload_sha512,
    }
}

fn create_block(
    batches: Vec<Batch>,
    block_num: u64,
    block_id: String,
    previous_block_id: String,
) -> Block {
    Block {
        header_signature: block_id,
        previous_block_id,
        batch_ids: batches.iter().map(|b| b.header_signature.clone()).collect(),
        batches,
        header_bytes: vec![],
        state_root_hash: "".to_string(),
        consensus: vec![],
        signer_public_key: "".to_string(),
        block_num,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sawtooth_validator::journal::block_validator::BlockValidation;

    #[bench]
    fn bench_duplicates_and_dependencies_validation(b: &mut Bencher) {
        let context = signing::create_context("secp256k1").unwrap();
        let private_key = context.new_random_private_key().unwrap();

        let signer = signing::Signer::new(context.as_ref(), private_key.as_ref());
        let mut transformer = smallbank_transformer::SBPayloadTransformer::new(&signer);

        let SEED = vec![
            1, 99, 2, 4, 44, 49, 2, 10, 8, 48, 25, 198, 65, 178, 244, 3, 208,
        ];

        let mut transaction_iterator =
            SmallbankGeneratingIter::new(ACCOUNTS, SEED.as_slice()).map(move |ref payload| {
                transformer
                    .payload_to_transaction(payload)
                    .expect("It is good")
            });

        let batch_iter =
            SignedBatchIterator::new(&mut transaction_iterator, TXNS_PER_BATCH, &signer);

        let mut block_iterator = BlockIterator::new(batch_iter, &signer);
        let block_manager = BlockManager::new();

        for _ in 1..20 {
            if let Some(block) = block_iterator.next() {
                block_manager.put(vec![block]).unwrap();
            }
        }

        let duplicates_validation = DuplicatesAndDependenciesValidation::new(block_manager.clone());
        b.iter(|| {
            let block = block_iterator
                .next()
                .expect("There is always another block");
            block_manager.put(vec![block.clone()]).unwrap();
            if let Err(_) = duplicates_validation.validate_block(&block, None) {
                println!("ERror");
            }
        })
    }

    #[bench]
    fn bench_duplicates_and_dependencies_blockstore_validation(b: &mut Bencher) {
        let context = signing::create_context("secp256k1").unwrap();
        let private_key = context.new_random_private_key().unwrap();

        let signer = signing::Signer::new(context.as_ref(), private_key.as_ref());
        let mut transformer = smallbank_transformer::SBPayloadTransformer::new(&signer);

        let SEED = vec![
            99, 5, 55, 255, 8, 7, 2, 188, 92, 146, 25, 199, 67, 178, 244, 233, 208,
        ];

        let mut transaction_iterator =
            SmallbankGeneratingIter::new(ACCOUNTS, SEED.as_slice()).map(move |ref payload| {
                transformer
                    .payload_to_transaction(payload)
                    .expect("It is good")
            });

        let batch_iter =
            SignedBatchIterator::new(&mut transaction_iterator, TXNS_PER_BATCH, &signer);

        let mut block_iterator = BlockIterator::new(batch_iter, &signer);
        let block_manager = BlockManager::new();

        let gil = Python::acquire_gil();
        let py = gil.python();

        let indexed_database = PY_INDEXED_DATABASE
            .call(py, ("/tmp/tmp_blockstore.lmdb",), None)
            .unwrap();
        let block_store =
            PyBlockStore::new(PY_BLOCK_STORE.call(py, (indexed_database,), None).unwrap());

        block_manager
            .add_store("COMMIT", Box::new(block_store))
            .unwrap();

        for i in 1..20 {
            if let Some(block) = block_iterator.next() {
                let block_id = block.header_signature.clone();
                block_manager.put(vec![block]).unwrap();
                if i == 18 {
                    block_manager.persist(&block_id, "COMMIT").unwrap();
                }
            }
        }

        let duplicates_validation = DuplicatesAndDependenciesValidation::new(block_manager.clone());
        b.iter(|| {
            let block = block_iterator
                .next()
                .expect("There is always another block");
            block_manager.put(vec![block.clone()]).unwrap();
            if let Err(_) = duplicates_validation.validate_block(&block, None) {
                println!("ERror");
            }
        })
    }

}
