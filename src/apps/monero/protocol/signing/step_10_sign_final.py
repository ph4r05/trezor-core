"""
Final message.
Offloading tx related data, encrypted.
"""

import gc

from .state import State

from apps.monero.controller import misc
from apps.monero.xmr import crypto
from apps.monero.xmr.enc import chacha_poly
from apps.monero.protocol import hmac_encryption_keys
from trezor.messages.MoneroTransactionFinalAck import MoneroTransactionFinalAck

from apps.monero.layout import confirms


async def final_msg(state: State):
    # state.state.set_final() todo needed?
    print("10")

    cout_key = (
        hmac_encryption_keys.enc_key_cout(state.key_enc) if state.multi_sig else None
    )

    # Encrypted tx keys under transaction specific key, derived from txhash and spend key.
    # Deterministic transaction key, so we can recover it just from transaction and the spend key.
    tx_key, salt, rand_mult = misc.compute_tx_key(
        state.creds.spend_key_private, state.tx_prefix_hash
    )

    key_buff = crypto.encodeint(state.tx_priv) + b"".join(
        [crypto.encodeint(x) for x in state.additional_tx_private_keys]
    )
    tx_enc_keys = chacha_poly.encrypt_pack(tx_key, key_buff)

    await confirms.transaction_finished(state.ctx)
    gc.collect()

    return MoneroTransactionFinalAck(
        cout_key=cout_key, salt=salt, rand_mult=rand_mult, tx_enc_keys=tx_enc_keys
    )
