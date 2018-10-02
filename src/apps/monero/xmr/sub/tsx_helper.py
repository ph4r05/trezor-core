from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import xmrserialize
from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr.serialize_messages.tx_extra import (
    TxExtraAdditionalPubKeys,
    TxExtraField,
)


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
    to_add[0] = 1
    crypto.encodepoint_into(memoryview(to_add)[1:], pub_key)  # TX_EXTRA_TAG_PUBKEY
    return tx_extra + to_add


def add_additional_tx_pub_keys_to_extra(
    tx_extra, additional_pub_keys=None, pub_enc=None
):
    """
    Adds all pubkeys to the extra
    """
    pubs_msg = TxExtraAdditionalPubKeys(
        data=pub_enc
        if pub_enc
        else [crypto.encodepoint(x) for x in additional_pub_keys]
    )

    rw = MemoryReaderWriter()
    ar = xmrserialize.Archive(rw, True)

    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    ar.variant(pubs_msg, TxExtraField)
    tx_extra += rw.get_buffer()
    return tx_extra
