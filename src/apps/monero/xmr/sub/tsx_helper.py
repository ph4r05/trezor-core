from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import int_serialize


def absolute_output_offsets_to_relative(off):
    """
    Relative offsets, prev + cur = next.
    Helps with varint encoding size.
    """
    if len(off) == 0:
        return off
    off.sort()
    for i in range(len(off) - 1, 0, -1):
        off[i] -= off[i - 1]
    return off


def add_tx_pub_key_to_extra(tx_extra, pub_key):
    """
    Adds public key to the extra
    """
    to_add = bytearray(33)
    to_add[0] = 1  # TX_EXTRA_TAG_PUBKEY
    crypto.encodepoint_into(memoryview(to_add)[1:], pub_key)
    return tx_extra + to_add


def add_additional_tx_pub_keys_to_extra(tx_extra, pub_enc):
    """
    Adds all additional tx public keys to the extra buffer
    """
    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    num_keys = len(pub_enc)
    len_size = int_serialize.uvarint_size(num_keys)
    buffer = bytearray(1 + len_size + 32 * num_keys)

    buffer[0] = 0x4  # TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
    int_serialize.dump_uvarint_b_into(num_keys, buffer, 1)  # uvarint(num_keys)
    offset = 1 + len_size

    for idx in range(num_keys):
        buffer[offset : offset + 32] = pub_enc[idx]
        offset += 32

    tx_extra += buffer
    return tx_extra
