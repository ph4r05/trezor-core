"""
Set destination entry one by one.
Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.
"""
import gc

from trezor import utils

from .state import State

from apps.monero.controller import misc
from apps.monero.layout import confirms
from apps.monero.protocol import hmac_encryption_keys
from apps.monero.xmr import common, crypto


async def set_out1(state: State, dst_entr, dst_entr_hmac, rsig_data=None):
    state._mem_trace(0, True)
    mods = utils.unimport_begin()

    await confirms.transaction_step(
        state.ctx, state.STEP_OUT, state.out_idx + 1, state.num_dests()
    )
    state._mem_trace(1)

    if (
        state.inp_idx + 1 != state.num_inputs()
    ):  # todo check state.state.is_input_vins() - needed?
        raise ValueError("Invalid number of inputs")

    state.out_idx += 1
    state._mem_trace(2, True)

    if dst_entr.amount <= 0 and state.tx.version <= 1:
        raise ValueError("Destination with wrong amount: %s" % dst_entr.amount)

    # HMAC check of the destination
    dst_entr_hmac_computed = await hmac_encryption_keys.gen_hmac_tsxdest(
        state.key_hmac, dst_entr, state.out_idx
    )
    if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
        raise ValueError("HMAC invalid")
    del (dst_entr_hmac, dst_entr_hmac_computed)
    state._mem_trace(3, True)

    # First output - tx prefix hasher - size of the container
    if state.out_idx == 0:
        state.tx_prefix_hasher.container_size(state.num_dests())
    state._mem_trace(4, True)

    state.summary_outs_money += dst_entr.amount
    utils.unimport_end(mods)
    state._mem_trace(5, True)

    # Range proof first, memory intensive
    rsig, mask = _range_proof(state, state.out_idx, dst_entr.amount, rsig_data)
    utils.unimport_end(mods)
    state._mem_trace(6, True)

    # Amount key, tx out key
    additional_txkey_priv = _set_out1_additional_keys(state, dst_entr)
    derivation = _set_out1_derivation(state, dst_entr, additional_txkey_priv)
    amount_key = crypto.derivation_to_scalar(derivation, state.out_idx)
    tx_out_key = crypto.derive_public_key(
        derivation, state.out_idx, crypto.decodepoint(dst_entr.addr.spend_public_key)
    )
    del (derivation, additional_txkey_priv)
    state._mem_trace(7, True)

    # Tx header prefix hashing, hmac dst_entr
    tx_out_bin, hmac_vouti = await _set_out1_tx_out(state, dst_entr, tx_out_key)
    state._mem_trace(11, True)

    # Out_pk, ecdh_info
    out_pk, ecdh_info_bin = _set_out1_ecdh(
        state=state,
        dest_pub_key=tx_out_key,
        amount=dst_entr.amount,
        mask=mask,
        amount_key=amount_key,
    )
    del (dst_entr, mask, amount_key, tx_out_key)
    state._mem_trace(12, True)

    # Incremental hashing of the ECDH info.
    # RctSigBase allows to hash only one of the (ecdh, out_pk) as they are serialized
    # as whole vectors. Hashing ECDH info saves state space.
    state.full_message_hasher.set_ecdh(ecdh_info_bin)
    state._mem_trace(13, True)

    # Output_pk is stored to the state as it is used during the signature and hashed to the
    # RctSigBase later.
    state.output_pk.append(out_pk)
    state._mem_trace(14, True)

    from trezor.messages.MoneroTransactionSetOutputAck import (
        MoneroTransactionSetOutputAck
    )

    out_pk_bin = bytearray(64)
    utils.memcpy(out_pk_bin, 0, out_pk.dest, 0, 32)
    utils.memcpy(out_pk_bin, 32, out_pk.mask, 0, 32)

    return MoneroTransactionSetOutputAck(
        tx_out=tx_out_bin,
        vouti_hmac=hmac_vouti,
        rsig_data=_return_rsig_data(state, rsig),
        out_pk=out_pk_bin,
        ecdh_info=ecdh_info_bin,
    )


async def _set_out1_tx_out(state: State, dst_entr, tx_out_key):
    # Manual serialization of TxOut(0, TxoutToKey(key))
    tx_out_bin = bytearray(34)
    tx_out_bin[0] = 0  # amount varint
    tx_out_bin[1] = 2  # variant code TxoutToKey
    crypto.encodepoint_into(tx_out_bin, tx_out_key, 2)
    state._mem_trace(8)

    # Tx header prefix hashing
    state.tx_prefix_hasher.buffer(tx_out_bin)
    state._mem_trace(9, True)

    # Hmac dest_entr.
    hmac_vouti = await hmac_encryption_keys.gen_hmac_vouti(
        state.key_hmac, dst_entr, tx_out_bin, state.out_idx
    )
    state._mem_trace(10, True)
    return tx_out_bin, hmac_vouti


def _range_proof(state, idx, amount, rsig_data=None):
    """
    Computes rangeproof and related information - out_sk, out_pk, ecdh_info.
    In order to optimize incremental transaction build, the mask computation is changed compared
    to the official Monero code. In the official code, the input pedersen commitments are computed
    after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

    In order to save roundtrips we compute commitments randomly and then for the last rangeproof
    a[63] = (\\sum_{i=0}^{num_inp}alpha_i - \\sum_{i=0}^{num_outs-1} amasks_i) - \\sum_{i=0}^{62}a_i

    The range proof is incrementally hashed to the final_message.
    """
    from apps.monero.xmr import ring_ct

    mask = _get_out_mask(state, idx)
    state.output_amounts.append(amount)
    provided_rsig = (
        rsig_data.rsig
        if rsig_data and rsig_data.rsig and len(rsig_data.rsig) > 0
        else None
    )
    if not state.rsig_offload and provided_rsig:
        raise misc.TrezorError("Provided unexpected rsig")
    if not state.rsig_offload:
        state.output_masks.append(mask)

    # Batching
    bidx = _get_rsig_batch(state, idx)
    batch_size = state.rsig_grp[bidx]
    last_in_batch = _is_last_in_batch(state, idx, bidx)
    if state.rsig_offload and provided_rsig and not last_in_batch:
        raise misc.TrezorError("Provided rsig too early")
    if state.rsig_offload and last_in_batch and not provided_rsig:
        raise misc.TrezorError("Rsig expected, not provided")

    # Batch not finished, skip range sig generation now
    if not last_in_batch:
        return None, mask

    # Rangeproof
    # Pedersen commitment on the value, mask from the commitment, range signature.
    C, rsig = None, None

    state._mem_trace("pre-rproof" if __debug__ else None, collect=True)
    if not state.rsig_offload and state.use_bulletproof:
        rsig = ring_ct.prove_range_bp_batch(state.output_amounts, state.output_masks)
        state._mem_trace("post-bp" if __debug__ else None, collect=True)

        # Incremental hashing
        state.full_message_hasher.rsig_val(rsig, True, raw=False)
        state._mem_trace("post-bp-hash" if __debug__ else None, collect=True)

        rsig = misc.dump_rsig_bp(rsig)
        state._mem_trace(
            "post-bp-ser, size: %s" % len(rsig) if __debug__ else None, collect=True
        )

    elif not state.rsig_offload and not state.use_bulletproof:
        C, mask, rsig = ring_ct.prove_range_chunked(amount, mask)
        del (ring_ct)

        # Incremental hashing
        state.full_message_hasher.rsig_val(rsig, False, raw=True)
        _check_out_commitment(state, amount, mask, C)

    elif state.rsig_offload and state.use_bulletproof:
        from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof

        masks = [
            _get_out_mask(state, 1 + idx - batch_size + ix) for ix in range(batch_size)
        ]

        bp_obj = misc.parse_msg(rsig_data.rsig, Bulletproof())
        rsig_data.rsig = None

        state.full_message_hasher.rsig_val(bp_obj, True, raw=False)
        res = ring_ct.verify_bp(bp_obj, state.output_amounts, masks)
        state.assrt(res, "BP verification fail")
        state._mem_trace("BP verified" if __debug__ else None, collect=True)
        del (bp_obj, ring_ct)

    elif state.rsig_offload and not state.use_bulletproof:
        state.full_message_hasher.rsig_val(rsig_data.rsig, False, raw=True)
        rsig_data.rsig = None

    else:
        raise misc.TrezorError("Unexpected rsig state")

    state._mem_trace("rproof" if __debug__ else None, collect=True)
    state.output_amounts = []
    if not state.rsig_offload:
        state.output_masks = []
    return rsig, mask


def _return_rsig_data(state, rsig):
    if rsig is None:
        return None
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    if isinstance(rsig, list):
        return MoneroTransactionRsigData(rsig_parts=rsig)
    else:
        return MoneroTransactionRsigData(rsig=rsig)


def _set_out1_ecdh(state: State, dest_pub_key, amount, mask, amount_key):
    from apps.monero.xmr import ring_ct

    # Mask sum
    out_pk = misc.StdObj(
        dest=crypto.encodepoint(dest_pub_key),
        mask=crypto.encodepoint(crypto.gen_commitment(mask, amount)),
    )
    state.sumout = crypto.sc_add(state.sumout, mask)
    state.output_sk.append(misc.StdObj(mask=mask))

    # ECDH masking
    from apps.monero.xmr.sub.recode import recode_ecdh

    ecdh_info = misc.StdObj(mask=mask, amount=crypto.sc_init(amount))
    ring_ct.ecdh_encode_into(
        ecdh_info, ecdh_info, derivation=crypto.encodeint(amount_key)
    )
    recode_ecdh(ecdh_info, encode=True)

    ecdh_info_bin = bytearray(64)
    utils.memcpy(ecdh_info_bin, 0, ecdh_info.mask, 0, 32)
    utils.memcpy(ecdh_info_bin, 32, ecdh_info.amount, 0, 32)
    gc.collect()

    return out_pk, ecdh_info_bin


def _set_out1_additional_keys(state: State, dst_entr):
    additional_txkey = None
    additional_txkey_priv = None
    if state.need_additional_txkeys:
        use_provided = state.num_dests() == len(state.additional_tx_private_keys)
        additional_txkey_priv = (
            state.additional_tx_private_keys[state.out_idx]
            if use_provided
            else crypto.random_scalar()
        )

        if dst_entr.is_subaddress:
            additional_txkey = crypto.scalarmult(
                crypto.decodepoint(dst_entr.addr.spend_public_key),
                additional_txkey_priv,
            )
        else:
            additional_txkey = crypto.scalarmult_base(additional_txkey_priv)

        state.additional_tx_public_keys.append(crypto.encodepoint(additional_txkey))
        if not use_provided:
            state.additional_tx_private_keys.append(additional_txkey_priv)
    return additional_txkey_priv


def _set_out1_derivation(state: State, dst_entr, additional_txkey_priv):
    from apps.monero.xmr.sub.addr import addr_eq

    change_addr = state.change_address()
    if change_addr and addr_eq(dst_entr.addr, change_addr):
        # sending change to yourself; derivation = a*R
        derivation = crypto.generate_key_derivation(
            state.tx_pub, state.creds.view_key_private
        )

    else:
        # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        deriv_priv = (
            additional_txkey_priv
            if dst_entr.is_subaddress and state.need_additional_txkeys
            else state.tx_priv
        )
        derivation = crypto.generate_key_derivation(
            crypto.decodepoint(dst_entr.addr.view_public_key), deriv_priv
        )
    return derivation


def _check_out_commitment(state: State, amount, mask, C):
    state.assrt(
        crypto.point_eq(
            C,
            crypto.point_add(crypto.scalarmult_base(mask), crypto.scalarmult_h(amount)),
        ),
        "OutC fail",
    )


def _is_last_in_batch(state: State, idx, bidx=None):
    """
    Returns true if the current output is last in the rsig batch
    """
    bidx = _get_rsig_batch(idx) if bidx is None else bidx
    batch_size = state.rsig_grp[bidx]
    return (idx - sum(state.rsig_grp[:bidx])) + 1 == batch_size


def _get_rsig_batch(state: State, idx):
    """
    Returns index of the current rsig batch
    """
    r = 0
    c = 0
    while c < idx + 1:
        c += state.rsig_grp[r]
        r += 1
    return r - 1


def _get_out_mask(state: State, idx):
    if state.rsig_offload:
        return state.output_masks[idx]
    else:
        is_last = idx + 1 == state.num_dests()
        if is_last:
            return crypto.sc_sub(state.sumpouts_alphas, state.sumout)
        else:
            return crypto.random_scalar()
