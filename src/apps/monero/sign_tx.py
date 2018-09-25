from apps.monero.protocol.signing import step_01_init_transaction


async def sign_tx(ctx, msg):
    return await step_01_init_transaction.init_transaction(
        ctx, msg.address_n, msg.network_type, msg.tsx_data
    )
