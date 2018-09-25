"""
MLSAG message computed.
"""

from .state import State

from apps.monero.layout import confirms


async def mlsag_done(state: State):
    from trezor.messages.MoneroTransactionMlsagDoneAck import (
        MoneroTransactionMlsagDoneAck
    )
    # state.state.set_final_message_done()  todo needed?
    await confirms.transaction_step(state.ctx, state.STEP_MLSAG)

    _ecdh_info(state)
    _out_pk(state)
    state.full_message_hasher.rctsig_base_done()
    state.out_idx = -1
    state.inp_idx = -1

    state.full_message = state.full_message_hasher.get_digest()
    state.full_message_hasher = None

    result = MoneroTransactionMlsagDoneAck(full_message_hash=state.full_message)
    return await dispatch_and_forward(state, result)


def _ecdh_info(state: State):  # todo why is it here? remove
    """
    Sets ecdh info for the incremental hashing mlsag.
    """
    pass


def _out_pk(state: State):
    """
    Sets out_pk for the incremental hashing mlsag.
    """
    if state.num_dests() != len(state.output_pk):
        raise ValueError("Invalid number of ecdh")

    for out in state.output_pk:
        state.full_message_hasher.set_out_pk(out)


async def dispatch_and_forward(state, result_msg):
    from trezor.messages import MessageType
    from apps.monero.protocol.signing import step_09_sign_input

    await state.ctx.write(result_msg)
    del result_msg

    received_msg = await state.ctx.read(
        (MessageType.MoneroTransactionSignInputRequest,)
    )
    return await step_09_sign_input.sign_input(
        state,
        received_msg.src_entr,
        received_msg.vini,
        received_msg.vini_hmac,
        received_msg.pseudo_out,
        received_msg.pseudo_out_hmac,
        received_msg.alpha_enc,
        received_msg.spend_enc,
    )
