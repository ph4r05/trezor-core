class TrezorError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class TrezorSecurityError(TrezorError):
    pass


class TrezorTxPrefixHashNotMatchingError(TrezorError):
    pass


class TrezorChangeAddressError(TrezorError):
    pass


class TrezorNotEnoughOutputs(TrezorError):
    pass


def compute_tx_key(spend_key_private, tx_prefix_hash, salt=None, rand_mult=None):
    from apps.monero.xmr import crypto

    if not salt:
        salt = crypto.random_bytes(32)

    if not rand_mult:
        rand_mult_num = crypto.random_scalar()
        rand_mult = crypto.encodeint(rand_mult_num)
    else:
        rand_mult_num = crypto.decodeint(rand_mult)

    rand_inp = crypto.sc_add(spend_key_private, rand_mult_num)
    passwd = crypto.keccak_2hash(crypto.encodeint(rand_inp) + tx_prefix_hash)
    tx_key = crypto.compute_hmac(salt, passwd)
    return tx_key, salt, rand_mult


async def monero_get_creds(ctx, address_n=None, network_type=None):
    from apps.common import seed
    from apps.monero.xmr import crypto
    from apps.monero.xmr import monero
    from apps.monero.xmr.sub.creds import AccountCreds

    # If path contains 0 it is not SLIP-0010
    address_n = address_n or ()
    use_slip0010 = 0 not in address_n
    curve = "ed25519" if use_slip0010 else "secp256k1"

    node = await seed.derive_node(ctx, address_n, curve)
    pre_key = node.private_key()

    key_seed = pre_key if use_slip0010 else crypto.cn_fast_hash(node.private_key())
    keys = monero.generate_monero_keys(
        key_seed
    )  # spend_sec, spend_pub, view_sec, view_pub

    creds = AccountCreds.new_wallet(keys[2], keys[0], network_type)
    return creds


def parse_msg(bts, msg):
    from apps.monero.xmr.serialize import xmrserialize
    from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter

    reader = MemoryReaderWriter(memoryview(bts))
    ar = xmrserialize.Archive(reader, False)
    return ar.message(msg)


def dump_msg(msg, preallocate=None, msg_type=None, prefix=None):
    from apps.monero.xmr.serialize import xmrserialize
    from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter

    writer = MemoryReaderWriter(preallocate=preallocate)
    if prefix:
        writer.write(prefix)
    ar = xmrserialize.Archive(writer, True)
    ar.message(msg, msg_type=msg_type)
    return writer.get_buffer()


def dump_msg_gc(msg, preallocate=None, msg_type=None, del_msg=False):
    b = dump_msg(msg, preallocate=preallocate, msg_type=msg_type)
    if del_msg:
        del msg

    import gc

    gc.collect()
    return b


def dump_rsig_bp(rsig):
    from trezor.utils import memcpy

    if len(rsig.L) > 127:
        raise ValueError("Too large")

    # Manual serialization as the generic purpose misc.dump_msg_gc
    # is more memory intensive which is not desired in the range proof section.

    # BP: V, A, S, T1, T2, taux, mu, L, R, a, b, t
    # Commitment vector V is not serialized
    # Vector size under 127 thus varint occupies 1 B
    buff_size = 32 * (9 + 2 * (len(rsig.L))) + 2
    buff = bytearray(buff_size)

    memcpy(buff, 0, rsig.A, 0, 32)
    memcpy(buff, 32, rsig.S, 0, 32)
    memcpy(buff, 32 * 2, rsig.T1, 0, 32)
    memcpy(buff, 32 * 3, rsig.T2, 0, 32)
    memcpy(buff, 32 * 4, rsig.taux, 0, 32)
    memcpy(buff, 32 * 5, rsig.mu, 0, 32)

    buff[32 * 6] = len(rsig.L)
    offset = 32 * 6 + 1

    for x in rsig.L:
        memcpy(buff, offset, x, 0, 32)
        offset += 32

    buff[offset] = len(rsig.R)
    offset += 1

    for x in rsig.R:
        memcpy(buff, offset, x, 0, 32)
        offset += 32

    memcpy(buff, offset, rsig.a, 0, 32)
    offset += 32
    memcpy(buff, offset, rsig.b, 0, 32)
    offset += 32
    memcpy(buff, offset, rsig.t, 0, 32)
    return buff
