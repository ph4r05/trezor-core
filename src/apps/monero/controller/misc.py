#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
from apps.monero.xmr.serialize_messages.addr import AccountPublicAddress
from apps.monero.xmr.serialize_messages.tx_dest_entry import TxDestinationEntry
from apps.monero.xmr.serialize_messages.tx_src_entry import TxSourceEntry
from apps.monero.xmr.serialize_messages.tx_prefix import TxinToKey

from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr import crypto
from apps.monero.xmr.tsx_data import TsxData
from apps.monero.xmr.serialize import xmrserialize
from trezor.messages.MoneroTsxData import MoneroTsxData
from trezor.messages.MoneroTxDestinationEntry import MoneroTxDestinationEntry


class TrezorError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class TrezorSecurityError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorInvalidStateError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorTxPrefixHashNotMatchingError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def compute_tx_key(spend_key_private, tx_prefix_hash, salt=None, rand_mult=None):
    """

    :param spend_key_private:
    :param tx_prefix_hash:
    :param salt:
    :param rand_mult:
    :return:
    """
    if not salt:
        salt = crypto.random_bytes(32)

    if not rand_mult:
        rand_mult_num = crypto.random_scalar()
        rand_mult = crypto.encodeint(rand_mult_num)
    else:
        rand_mult_num = crypto.decodeint(rand_mult)

    rand_inp = crypto.sc_add(spend_key_private, rand_mult_num)
    passwd = crypto.keccak_2hash(crypto.encodeint(rand_inp) + tx_prefix_hash)
    tx_key = crypto.pbkdf2(passwd, salt, count=100)
    return tx_key, salt, rand_mult


def translate_monero_dest_entry(dst_entry: MoneroTxDestinationEntry):
    d = TxDestinationEntry()
    d.amount = dst_entry.amount
    d.is_subaddress = dst_entry.is_subaddress
    d.addr = AccountPublicAddress(m_spend_public_key=dst_entry.addr.m_spend_public_key,
                                  m_view_public_key=dst_entry.addr.m_view_public_key)
    return d


async def translate_tsx_data(tsx_data: MoneroTsxData):
    tsxd = TsxData()
    for fld in TsxData.MFIELDS:
        fname = fld[0]
        if hasattr(tsx_data, fname):
            setattr(tsxd, fname, getattr(tsx_data, fname))

    if tsx_data.change_dts:
        tsxd.change_dts = translate_monero_dest_entry(tsx_data.change_dts)

    tsxd.outputs = [translate_monero_dest_entry(x) for x in tsx_data.outputs]
    return tsxd


async def parse_msg(bts, msg):
    reader = MemoryReaderWriter(bytearray(bts))
    ar = xmrserialize.Archive(reader, False)
    return await ar.message(msg)


async def parse_src_entry(bts):
    return await parse_msg(bts, TxSourceEntry())


async def parse_dst_entry(bts):
    return await parse_msg(bts, TxDestinationEntry())


async def parse_vini(bts):
    return await parse_msg(bts, TxinToKey())


async def dump_msg(msg):
    writer = MemoryReaderWriter()
    ar = xmrserialize.Archive(writer, True)
    await ar.message(msg)
    return bytes(writer.buffer)
