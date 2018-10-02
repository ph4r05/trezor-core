from common import *
import utest

from trezor import log, loop, utils
from apps.monero.xmr.serialize import xmrserialize as xms
from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr.serialize_messages.base import ECPoint
from apps.monero.xmr.serialize_messages.tx_prefix import (
    TxinToKey,
    TxinGen,
    TxInV,
    TxOut,
    TxoutToKey,
)


class XmrTstData(object):
    """Simple tests data generator"""

    def __init__(self, *args, **kwargs):
        super(XmrTstData, self).__init__()
        self.ec_offset = 0

    def reset(self):
        self.ec_offset = 0

    def generate_ec_key(self, use_offset=True):
        """
        Returns test EC key, 32 element byte array
        :param use_offset:
        :return:
        """
        offset = 0
        if use_offset:
            offset = self.ec_offset
            self.ec_offset += 1

        return bytearray(range(offset, offset + 32))

    def gen_transaction_prefix(self):
        """
        Returns test transaction prefix
        :return:
        """
        vin = [
            TxinToKey(
                amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
            ),
            TxinToKey(
                amount=456, key_offsets=[9, 8, 7, 6], k_image=bytearray(range(32, 64))
            ),
            TxinGen(height=99),
        ]

        vout = [
            TxOut(amount=11, target=TxoutToKey(key=bytearray(range(32)))),
            TxOut(amount=34, target=TxoutToKey(key=bytearray(range(64, 96)))),
        ]

        msg = TransactionPrefix(
            version=2, unlock_time=10, vin=vin, vout=vout, extra=list(range(31))
        )
        return msg


class TestMoneroSerializer(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMoneroSerializer, self).__init__(*args, **kwargs)
        self.tdata = XmrTstData()

    def setUp(self):
        self.tdata.reset()

    def test_varint(self):
        """
        Var int
        :return:
        """
        # fmt: off
        test_nums = [0, 1, 12, 44, 32, 63, 64, 127, 128, 255, 256, 1023, 1024, 8191, 8192,
                     2**16, 2**16 - 1, 2**32, 2**32 - 1, 2**64, 2**64 - 1, 2**72 - 1, 2**112]
        # fmt: on

        for test_num in test_nums:
            writer = MemoryReaderWriter()

            xms.dump_uvarint(writer, test_num)
            test_deser = xms.load_uvarint(MemoryReaderWriter(writer.get_buffer()))

            self.assertEqual(test_num, test_deser)

    def test_ecpoint(self):
        """
        Ec point
        :return:
        """
        ec_data = bytearray(range(32))
        writer = MemoryReaderWriter()

        xms.dump_blob(writer, ec_data, ECPoint)
        self.assertTrue(len(writer.get_buffer()), ECPoint.SIZE)

        test_deser = xms.load_blob(
            MemoryReaderWriter(writer.get_buffer()), ECPoint
        )
        self.assertEqual(ec_data, test_deser)

    def test_ecpoint_obj(self):
        """
        EC point into
        :return:
        """
        ec_data = bytearray(list(range(32)))
        ec_point = ECPoint()
        ec_point.data = ec_data
        writer = MemoryReaderWriter()

        xms.dump_blob(writer, ec_point, ECPoint)
        self.assertTrue(len(writer.get_buffer()), ECPoint.SIZE)

        ec_point2 = ECPoint()
        test_deser = xms.load_blob(
            MemoryReaderWriter(writer.get_buffer()), ECPoint, elem=ec_point2
        )

        self.assertEqual(ec_data, ec_point2.data)
        self.assertEqual(ec_point, ec_point2)

    def test_simple_msg(self):
        """
        TxinGen
        :return:
        """
        msg = TxinGen(height=42)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = ar2.message(None, msg_type=TxinGen)
        self.assertEqual(msg.height, test_deser.height)

    def test_simple_msg_into(self):
        """
        TxinGen
        :return:
        """
        msg = TxinGen(height=42)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        ar1.message(msg)

        msg2 = TxinGen()
        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = ar2.message(msg2, TxinGen)
        self.assertEqual(msg.height, test_deser.height)
        self.assertEqual(msg.height, msg2.height)
        self.assertEqual(msg2, test_deser)

    def test_txin_to_key(self):
        """
        TxinToKey
        :return:
        """
        msg = TxinToKey(
            amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
        )

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = ar2.message(None, TxinToKey)
        self.assertEqual(msg.amount, test_deser.amount)
        self.assertEqual(msg, test_deser)

    def test_txin_variant(self):
        """
        TxInV
        :return:
        """
        msg1 = TxinToKey(
            amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
        )
        msg = TxInV()
        msg.set_variant("txin_to_key", msg1)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        ar1.variant(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = ar2.variant(None, TxInV, wrapped=True)
        self.assertEqual(test_deser.__class__, TxInV)
        self.assertEqual(msg, test_deser)
        self.assertEqual(msg.variant_elem, test_deser.variant_elem)
        self.assertEqual(msg.variant_elem_type, test_deser.variant_elem_type)


if __name__ == "__main__":
    unittest.main()
