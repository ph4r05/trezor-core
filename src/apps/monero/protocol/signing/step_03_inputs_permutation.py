"""
Set permutation on the inputs - sorted by key image on host.
"""

from .state import State

from apps.monero.layout.confirms import transaction_step
from apps.monero.xmr import common


async def tsx_inputs_permutation(state: State, permutation):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    from trezor.messages.MoneroTransactionInputsPermutationAck import (
        MoneroTransactionInputsPermutationAck
    )

    await transaction_step(state.ctx, state.STEP_PERM)

    _tsx_inputs_permutation(state, permutation)

    return await dispatch_and_forward(state, MoneroTransactionInputsPermutationAck())


def _tsx_inputs_permutation(state: State, permutation):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    state.source_permutation = permutation
    common.check_permutation(permutation)
    state.inp_idx = -1


async def dispatch_and_forward(state, result_msg):
    from trezor.messages import MessageType
    from apps.monero.protocol.signing import step_04_input_vini

    await state.ctx.write(result_msg)
    del result_msg

    received_msg = await state.ctx.read(
        (MessageType.MoneroTransactionInputViniRequest,)
    )

    return await step_04_input_vini.input_vini(
        state,
        received_msg.src_entr,
        received_msg.vini,
        received_msg.vini_hmac,
        received_msg.pseudo_out,
        received_msg.pseudo_out_hmac,
    )
