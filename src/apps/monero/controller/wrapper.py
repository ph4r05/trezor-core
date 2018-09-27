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
