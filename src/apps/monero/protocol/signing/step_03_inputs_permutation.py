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

    return MoneroTransactionInputsPermutationAck()


def _tsx_inputs_permutation(state: State, permutation):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    state.source_permutation = permutation
    common.check_permutation(permutation)
    state.current_input_index = -1
