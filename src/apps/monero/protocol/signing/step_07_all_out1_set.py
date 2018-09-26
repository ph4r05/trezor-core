"""
All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
transaction prefix hash.
Adds additional public keys to the tx.extra
"""

import gc

from .state import State

from apps.monero.controller import misc
from apps.monero.layout import confirms
from apps.monero.xmr import common, crypto


async def all_out1_set(state: State):
    print("07")

    state._mem_trace(0)
    # state.state.set_output_done() todo needed?

    await confirms.transaction_step(state.ctx, state.STEP_ALL_OUT)
    state._mem_trace(1)

    if state.out_idx + 1 != state.num_dests():
        raise ValueError("Invalid out num")

    # Test if \sum Alpha == \sum A
    if state.use_simple_rct:
        state.assrt(crypto.sc_eq(state.sumout, state.sumpouts_alphas))

    # Fee test
    if state.fee != (state.summary_inputs_money - state.summary_outs_money):
        raise ValueError(
            "Fee invalid %s vs %s, out: %s"
            % (
                state.fee,
                state.summary_inputs_money - state.summary_outs_money,
                state.summary_outs_money,
            )
        )
    state._mem_trace(2)

    # Set public key to the extra
    # Not needed to remove - extra is clean
    _set_tx_extra(state)
    state.additional_tx_public_keys = None

    gc.collect()
    state._mem_trace(3)

    if state.summary_outs_money > state.summary_inputs_money:
        raise ValueError(
            "Transaction inputs money (%s) less than outputs money (%s)"
            % (state.summary_inputs_money, state.summary_outs_money)
        )

    # Hashing transaction prefix
    _set_tx_prefix(state)
    extra_b = state.tx.extra
    state.tx = None
    gc.collect()
    state._mem_trace(4)

    # Txprefix match check for multisig
    if not common.is_empty(state.exp_tx_prefix_hash) and not common.ct_equal(
        state.exp_tx_prefix_hash, state.tx_prefix_hash
    ):
        # state.state.set_fail()  todo needed?
        # todo   raise wire.NotEnoughFunds(e.message) ??
        raise misc.TrezorTxPrefixHashNotMatchingError("Tx prefix invalid")

    gc.collect()
    state._mem_trace(5)

    from trezor.messages.MoneroRingCtSig import MoneroRingCtSig
    from trezor.messages.MoneroTransactionAllOutSetAck import (
        MoneroTransactionAllOutSetAck
    )

    # Initializes RCTsig structure (fee, tx prefix hash, type)
    rv_pb = MoneroRingCtSig(
        txn_fee=state.get_fee(),
        message=state.tx_prefix_hash,
        rv_type=state.get_rct_type(),
    )

    return MoneroTransactionAllOutSetAck(
        extra=extra_b, tx_prefix_hash=state.tx_prefix_hash, rv=rv_pb
    )


def _set_tx_extra(state: State):
    from apps.monero.xmr.sub import tsx_helper

    state.tx.extra = tsx_helper.add_tx_pub_key_to_extra(state.tx.extra, state.tx_pub)

    # Not needed to remove - extra is clean
    # state.tx.extra = await monero.remove_field_from_tx_extra(state.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
    if state.need_additional_txkeys:
        state.tx.extra = tsx_helper.add_additional_tx_pub_keys_to_extra(
            state.tx.extra, pub_enc=state.additional_tx_public_keys
        )


def _set_tx_prefix(state: State):
    from apps.monero.xmr.serialize.message_types import BlobType

    state.tx_prefix_hasher.message_field(state.tx, ("extra", BlobType))  # extra

    state.tx_prefix_hash = state.tx_prefix_hasher.get_digest()
    state.tx_prefix_hasher = None

    # Hash message to the final_message
    state.full_message_hasher.set_message(state.tx_prefix_hash)
