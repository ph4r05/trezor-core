import gc

from trezor import log, utils
from trezor.messages import MessageType
from apps.monero.protocol.signing.state import State


async def sign_tx(ctx, received_msg):
    state = State(ctx)

    while True:
        if __debug__:
            log.debug(__name__, "#### F: %s, A: %s", gc.mem_free(), gc.mem_alloc())
        gc.collect()
        gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())

        mods = utils.unimport_begin()
        result_msg, accept_msgs = await sign_tx_dispatch(state, received_msg)
        utils.unimport_end(mods)

        if accept_msgs is None:
            break
        received_msg = await ctx.call(result_msg, *accept_msgs)

    return result_msg


async def sign_tx_dispatch(state, msg):
    if msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInitRequest:
        from apps.monero.protocol.signing import step_01_init_transaction

        return (
            await step_01_init_transaction.init_transaction(
                state, msg.address_n, msg.network_type, msg.tsx_data
            ),
            (MessageType.MoneroTransactionSetInputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSetInputRequest:
        from apps.monero.protocol.signing import step_02_set_input

        return (
            await step_02_set_input.set_input(state, msg.src_entr),
            (
                MessageType.MoneroTransactionSetInputRequest,
                MessageType.MoneroTransactionInputsPermutationRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInputsPermutationRequest:
        from apps.monero.protocol.signing import step_03_inputs_permutation

        return (
            await step_03_inputs_permutation.tsx_inputs_permutation(state, msg.perm),
            (MessageType.MoneroTransactionInputViniRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInputViniRequest:
        from apps.monero.protocol.signing import step_04_input_vini

        return (
            await step_04_input_vini.input_vini(
                state,
                msg.src_entr,
                msg.vini,
                msg.vini_hmac,
                msg.pseudo_out,
                msg.pseudo_out_hmac,
            ),
            (
                MessageType.MoneroTransactionInputViniRequest,
                MessageType.MoneroTransactionAllInputsSetRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionAllInputsSetRequest:
        from apps.monero.protocol.signing import step_05_all_in_set

        return (
            await step_05_all_in_set.all_in_set(state, msg.rsig_data),
            (MessageType.MoneroTransactionSetOutputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSetOutputRequest:
        from apps.monero.protocol.signing import step_06_set_out1

        dst, dst_hmac, rsig_data = msg.dst_entr, msg.dst_entr_hmac, msg.rsig_data
        del (msg)

        return (
            await step_06_set_out1.set_out1(state, dst, dst_hmac, rsig_data),
            (
                MessageType.MoneroTransactionSetOutputRequest,
                MessageType.MoneroTransactionAllOutSetRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionAllOutSetRequest:
        from apps.monero.protocol.signing import step_07_all_out1_set

        # todo check TrezorTxPrefixHashNotMatchingError
        return (
            await step_07_all_out1_set.all_out1_set(state),
            (MessageType.MoneroTransactionMlsagDoneRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionMlsagDoneRequest:
        from apps.monero.protocol.signing import step_08_mlsag_done

        return (
            await step_08_mlsag_done.mlsag_done(state),
            (MessageType.MoneroTransactionSignInputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSignInputRequest:
        from apps.monero.protocol.signing import step_09_sign_input

        return (
            await step_09_sign_input.sign_input(
                state,
                msg.src_entr,
                msg.vini,
                msg.vini_hmac,
                msg.pseudo_out,
                msg.pseudo_out_hmac,
                msg.alpha_enc,
                msg.spend_enc,
            ),
            (
                MessageType.MoneroTransactionSignInputRequest,
                MessageType.MoneroTransactionFinalRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionFinalRequest:
        from apps.monero.protocol.signing import step_10_sign_final

        return await step_10_sign_final.final_msg(state), None

    else:
        from trezor import wire

        raise wire.DataError("Unknown message")
