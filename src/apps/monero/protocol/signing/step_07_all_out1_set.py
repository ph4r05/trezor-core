"""
All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
transaction prefix hash.
Adds additional public keys to the tx.extra
"""

import gc

from .state import State

from apps.monero.layout import confirms
from apps.monero.xmr import crypto


async def all_out1_set(state: State):
    print("07")

    state.mem_trace(0)
    # state.state.set_output_done() todo needed?

    await confirms.transaction_step(state.ctx, state.STEP_ALL_OUT)
    state.mem_trace(1)

    if state.current_output_index + 1 != state.output_count:
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
    state.mem_trace(2)

    # Set public key to the extra
    # Not needed to remove - extra is clean
    _set_tx_extra(state)
    state.additional_tx_public_keys = None

    gc.collect()
    state.mem_trace(3)

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
    state.mem_trace(4)

    # In the multisig mode here needs to be a check whether currently computed
    # transaction prefix matches expected transaction prefix sent in the
    # init step.

    from trezor.messages.MoneroRingCtSig import MoneroRingCtSig
    from trezor.messages.MoneroTransactionAllOutSetAck import (
        MoneroTransactionAllOutSetAck,
    )

    # Initializes RCTsig structure (fee, tx prefix hash, type)
    rv_pb = MoneroRingCtSig(
        txn_fee=state.fee, message=state.tx_prefix_hash, rv_type=state.get_rct_type()
    )

    return MoneroTransactionAllOutSetAck(
        extra=extra_b, tx_prefix_hash=state.tx_prefix_hash, rv=rv_pb
    )


def _set_tx_extra(state: State):
    state.tx.extra = _add_tx_pub_key_to_extra(state.tx.extra, state.tx_pub)

    if state.need_additional_txkeys:
        state.tx.extra = _add_additional_tx_pub_keys_to_extra(
            state.tx.extra, state.additional_tx_public_keys
        )


def _set_tx_prefix(state: State):
    # Serializing "extra" type as BlobType.
    # uvarint(len(extra)) || extra
    state.tx_prefix_hasher.uvarint(len(state.tx.extra))
    state.tx_prefix_hasher.buffer(state.tx.extra)

    state.tx_prefix_hash = state.tx_prefix_hasher.get_digest()
    state.tx_prefix_hasher = None

    # Hash message to the final_message
    state.full_message_hasher.set_message(state.tx_prefix_hash)


def _add_tx_pub_key_to_extra(tx_extra, pub_key):
    """
    Adds public key to the extra
    """
    to_add = bytearray(33)
    to_add[0] = 1  # TX_EXTRA_TAG_PUBKEY
    crypto.encodepoint_into(memoryview(to_add)[1:], pub_key)
    return tx_extra + to_add


def _add_additional_tx_pub_keys_to_extra(tx_extra, pub_enc):
    """
    Adds all additional tx public keys to the extra buffer
    """
    from apps.monero.xmr.serialize import int_serialize

    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    num_keys = len(pub_enc)
    len_size = int_serialize.uvarint_size(num_keys)
    buffer = bytearray(1 + len_size + 32 * num_keys)

    buffer[0] = 0x4  # TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
    int_serialize.dump_uvarint_b_into(num_keys, buffer, 1)  # uvarint(num_keys)
    offset = 1 + len_size

    for idx in range(num_keys):
        buffer[offset : offset + 32] = pub_enc[idx]
        offset += 32

    tx_extra += buffer
    return tx_extra
