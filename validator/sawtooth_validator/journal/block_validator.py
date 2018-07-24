# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import collections
import logging

from sawtooth_validator.concurrent.threadpool import \
    InstrumentedThreadPoolExecutor

from sawtooth_validator.journal.block_wrapper import NULL_BLOCK_IDENTIFIER
from sawtooth_validator.journal.chain_commit_state import ChainCommitState
from sawtooth_validator.journal.chain_commit_state import DuplicateTransaction
from sawtooth_validator.journal.chain_commit_state import DuplicateBatch
from sawtooth_validator.journal.chain_commit_state import MissingDependency
from sawtooth_validator.journal.validation_rule_enforcer import \
    enforce_validation_rules
from sawtooth_validator.state.settings_view import SettingsViewFactory
from sawtooth_validator import metrics

from sawtooth_validator.protobuf.block_pb2 import BlockHeader
from sawtooth_validator.state.merkle import INIT_ROOT_KEY


LOGGER = logging.getLogger(__name__)
COLLECTOR = metrics.get_collector(__name__)


class BlockValidationFailure(Exception):
    """
    Indication that a failure has occurred during block validation.
    """


class BlockValidationError(Exception):
    """
    Indication that an error occured during block validation and the validity
    of the block could not be determined.
    """


# Need to disable this new pylint check until the function can be refactored
# to return instead of raise StopIteration, which it does by calling next()
# pylint: disable=stop-iteration-return
def look_ahead(iterable):
    """Pass through all values from the given iterable, augmented by the
    information if there are more values to come after the current one
    (True), or if it is the last value (False).
    """
    # Get an iterator and pull the first value.
    it = iter(iterable)
    last = next(it)
    # Run the iterator to exhaustion (starting from the second value).
    for val in it:
        # Report the *previous* value (more to come).
        yield last, True
        last = val
    # Report the last value.
    yield last, False


BlockValidationResult = collections.namedtuple("BlockValidationResult",
                                               ["execution_results",
                                                "block_id",
                                                "num_transactions",
                                                "status"])


class BlockValidator:
    """
    Responsible for validating a block.
    """

    def __init__(self,
                 block_manager,
                 block_store,
                 state_view_factory,
                 transaction_executor,
                 identity_signer,
                 data_dir,
                 config_dir,
                 permission_verifier,
                 thread_pool=None):
        """Initialize the BlockValidator
        Args:
            block_manager: The componenet that stores blocks and maintains
                integrity of the predecessor relationship.
            state_view_factory: A factory that can be used to create read-
                only views of state for a particular merkle root, in
                particular the state as it existed when a particular block
                was the chain head.
            transaction_executor: The transaction executor used to
                process transactions.
            identity_signer: A cryptographic signer for signing blocks.
            data_dir: Path to location where persistent data for the
                consensus module can be stored.
            config_dir: Path to location where config data for the
                consensus module can be found.
            permission_verifier: The delegate for handling permission
                validation on blocks.
            thread_pool: (Optional) Executor pool used to submit block
                validation jobs. If not specified, a default will be created.
        Returns:
            None
        """

        self._block_manager = block_manager
        self._block_store = block_store
        self._chain_head_fn = None
        self._state_view_factory = state_view_factory
        self._transaction_executor = transaction_executor
        self._identity_signer = identity_signer
        self._data_dir = data_dir
        self._config_dir = config_dir
        self._permission_verifier = permission_verifier

        self._settings_view_factory = SettingsViewFactory(state_view_factory)

        self._thread_pool = InstrumentedThreadPoolExecutor(1) \
            if thread_pool is None else thread_pool

    def stop(self):
        self._thread_pool.shutdown(wait=True)

    def set_chain_head_fn(self, func):
        self._chain_head_fn = func

    def _get_previous_block_state_root(self, block):
        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        if block_header.previous_block_id == NULL_BLOCK_IDENTIFIER:
            return INIT_ROOT_KEY
        try:
            block = next(
                self._block_manager.get(
                    [block_header.previous_block_id]))
        except StopIteration:
            return None
        block_header = BlockHeader()
        block_header.ParseFromString(block.header)
        return block_header.state_root_hash

    def _validate_batches_in_block(self, block, prev_state_root):
        """
        Validate all batches in the block. This includes:
            - Validating all transaction dependencies are met
            - Validating there are no duplicate batches or transactions
            - Validating execution of all batches in the block produces the
              correct state root hash

        Args:
            block: the block of batches to validate
            prev_state_root: the state root to execute transactions on top of

        Raises:
            BlockValidationFailure:
                If validation fails, raises this error with the reason.
            MissingDependency:
                Validation failed because of a missing dependency.
            DuplicateTransaction:
                Validation failed because of a duplicate transaction.
            DuplicateBatch:
                Validation failed because of a duplicate batch.
        """
        if not block.batches:
            return

        scheduler = None
        try:
            while True:
                try:
                    chain_head = self._chain_head_fn()

                    block_header = BlockHeader()
                    block_header.ParseFromString(block.header)

                    chain_commit_state = ChainCommitState(
                        block_header.previous_block_id,
                        self._block_manager,
                        self._block_store)

                    chain_commit_state.check_for_duplicate_batches(
                        block.batches)

                    transactions = []
                    for batch in block.batches:
                        transactions.extend(batch.transactions)

                    chain_commit_state.check_for_duplicate_transactions(
                        transactions)

                    chain_commit_state.check_for_transaction_dependencies(
                        transactions)

                    if not self._check_chain_head_updated(chain_head, block):
                        break

                except (DuplicateBatch,
                        DuplicateTransaction,
                        MissingDependency) as err:
                    if not self._check_chain_head_updated(chain_head, block):
                        raise BlockValidationFailure(
                            "Block {} failed validation: {}".format(
                                block.header_signature, err))

            scheduler = self._transaction_executor.create_scheduler(
                prev_state_root)

            for batch, has_more in look_ahead(block.batches):
                if has_more:
                    scheduler.add_batch(batch)
                else:
                    scheduler.add_batch(batch, block_header.state_root_hash)

        except Exception:
            if scheduler is not None:
                scheduler.cancel()
            raise

        scheduler.finalize()
        scheduler.complete(block=True)
        state_hash = None

        execution_results = []
        num_transactions = 0

        for batch in block.batches:
            batch_result = scheduler.get_batch_execution_result(
                batch.header_signature)
            if batch_result is not None and batch_result.is_valid:
                txn_results = \
                    scheduler.get_transaction_execution_results(
                        batch.header_signature)
                execution_results.extend(txn_results)
                state_hash = batch_result.state_hash
                num_transactions += len(batch.transactions)
            else:
                raise BlockValidationFailure(
                    "Block {} failed validation: Invalid batch "
                    "{}".format(block.header_signature, batch))

        if block_header.state_root_hash != state_hash:
            raise BlockValidationFailure(
                "Block {} failed state root hash validation. Expected {}"
                " but got {}".format(
                    block.header_signature,
                    block_header.state_root_hash,
                    state_hash))

        return execution_results, num_transactions

    def _check_chain_head_updated(self, chain_head, block):
        # The validity of blocks depends partially on whether or not
        # there are any duplicate transactions or batches in the block.
        # This can only be checked accurately if the block store does
        # not update during validation. The current practice is the
        # assume this will not happen and, if it does, to reprocess the
        # validation. This has been experimentally proven to be more
        # performant than locking the chain head and block store around
        # duplicate checking.
        if chain_head is None:
            return False

        current_chain_head = self._chain_head_fn()
        if chain_head.header_signature != current_chain_head.header_signature:
            LOGGER.warning(
                "Chain head updated from %s to %s while checking "
                "duplicates and dependencies in block %s. "
                "Reprocessing validation.",
                chain_head, current_chain_head, block)
            return True

        return False

    def _validate_permissions(self, block, prev_state_root):
        """
        Validate that all of the batch signers and transaction signer for the
        batches in the block are permitted by the transactor permissioning
        roles stored in state as of the previous block. If a transactor is
        found to not be permitted, the block is invalid.
        """

        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        if block_header.block_num != 0:
            for batch in block.batches:
                if not self._permission_verifier.is_batch_signer_authorized(
                        batch, prev_state_root, from_state=True):
                    return False
        return True

    def _validate_on_chain_rules(self, block, prev_state_root):
        """
        Validate that the block conforms to all validation rules stored in
        state. If the block breaks any of the stored rules, the block is
        invalid.
        """

        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        if block_header.block_num != 0:
            return enforce_validation_rules(
                self._settings_view_factory.create_settings_view(
                    prev_state_root),
                block_header.signer_public_key,
                block.batches)
        return True

    def validate_block(self, block):

        block_header = BlockHeader()
        block_header.ParseFromString(block.header)

        # pylint: disable=broad-except
        try:

            try:
                prev_state_root = self._get_previous_block_state_root(block)
            except KeyError:
                raise BlockValidationError(
                    'Block {} rejected due to missing predecessor'.format(
                        block.header_signature))

            if not self._validate_permissions(block, prev_state_root):
                raise BlockValidationFailure(
                    'Block {} failed permission validation'.format(
                        block.header_signature))

            if not self._validate_on_chain_rules(block, prev_state_root):
                raise BlockValidationFailure(
                    'Block {} failed on-chain validation rules'.format(
                        block.header_signature))

            return self._validate_batches_in_block(block, prev_state_root)

        except BlockValidationFailure as err:
            raise err

        except BlockValidationError as err:
            raise err

        except Exception as e:
            LOGGER.exception(
                "Unhandled exception BlockValidator.validate_block()")
            raise e

    def submit_blocks_for_verification(self, blocks, callback):
        for block in blocks:
            # Schedule the block for processing
            self._thread_pool.submit(
                self.process_block_verification, block, callback)

    def has_block(self, block_id):
        return False

    def return_block_failure(self, block):
        return BlockValidationResult(
            execution_results=[],
            num_transactions=0,
            status=0,
            block_id=block.header_signature)

    def process_block_verification(self, block, callback):
        """
        Main entry for Block Validation, Take a given candidate block
        and decide if it is valid then if it is valid determine if it should
        be the new head block. Returns the results to the ChainController
        so that the change over can be made if necessary.
        """
        try:
            execution_results, num_transactions = self.validate_block(block)
            result = BlockValidationResult(
                execution_results=execution_results,
                num_transactions=num_transactions,
                status=1,
                block_id=block.header_signature)
            LOGGER.info(
                'Block %s passed validation', block.header_signature)
        except BlockValidationFailure as err:
            result = self.return_block_failure(block)
            LOGGER.warning(
                'Block %s failed validation: %s', block.header_signature, err)
        except BlockValidationError as err:
            result = self.return_block_failure(block)
            LOGGER.error(
                'Encountered an error while validating %s: %s',
                block.header_signature, err)
        except Exception:  # pylint: disable=broad-except
            result = self.return_block_failure(block)
            LOGGER.exception(
                "Block validation failed with unexpected error: %s",
                block.header_signature)

        callback(result)
