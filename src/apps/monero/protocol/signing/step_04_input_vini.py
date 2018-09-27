"""
Set tx.vin[i] for incremental tx prefix hash computation.
After sorting by key images on host.
Hashes pseudo_out to the final_message.
"""

from .state import State

from apps.monero.layout import confirms
from apps.monero.protocol import hmac_encryption_keys
from apps.monero.xmr import common, crypto


async def input_vini(
    state: State, src_entr, vini_bin, hmac, pseudo_out, pseudo_out_hmac
):
    from trezor.messages.MoneroTransactionInputViniAck import (
        MoneroTransactionInputViniAck
    )

    await confirms.transaction_step(
        state.ctx, state.STEP_VINI, state.inp_idx + 1, state.input_count
    )

    if state.inp_idx >= state.input_count:
        raise ValueError("Too many inputs")

    state.inp_idx += 1

    # HMAC(T_in,i || vin_i)
    hmac_vini = await hmac_encryption_keys.gen_hmac_vini(
        state.key_hmac, src_entr, vini_bin, state.source_permutation[state.inp_idx]
    )
    if not common.ct_equal(hmac_vini, hmac):
        raise ValueError("HMAC is not correct")

    hash_vini_pseudo_out(state, vini_bin, state.inp_idx, pseudo_out, pseudo_out_hmac)

    # TODO check input count?
    return MoneroTransactionInputViniAck()


def hash_vini_pseudo_out(
    state: State, vini_bin, inp_idx, pseudo_out=None, pseudo_out_hmac=None
):
    """
    Incremental hasing of tx.vin[i] and pseudo output
    """
    state.tx_prefix_hasher.buffer(vini_bin)

    # Pseudo_out incremental hashing - applicable only in simple rct
    if not state.use_simple_rct or state.use_bulletproof:
        return

    idx = state.source_permutation[inp_idx]
    pseudo_out_hmac_comp = crypto.compute_hmac(
        hmac_encryption_keys.hmac_key_txin_comm(state.key_hmac, idx), pseudo_out
    )
    if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_comp):
        raise ValueError("HMAC invalid for pseudo outs")

    state.full_message_hasher.set_pseudo_out(pseudo_out)
