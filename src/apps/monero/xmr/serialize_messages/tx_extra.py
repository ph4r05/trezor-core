
from apps.monero.xmr.serialize.message_types import (
    BlobType,
    ContainerType,
    MessageType,
    VariantType,
)
from apps.monero.xmr.serialize_messages.base import ECPublicKey


class TxExtraNonce(MessageType):
    __slots__ = ("nonce",)
    VARIANT_CODE = 0x2

    @classmethod
    def f_specs(cls):
        return (("nonce", BlobType),)


class TxExtraAdditionalPubKeys(MessageType):
    __slots__ = ("data",)
    VARIANT_CODE = 0x4

    @classmethod
    def f_specs(cls):
        return (("data", ContainerType, ECPublicKey),)


class TxExtraField(VariantType):
    @classmethod
    def f_specs(cls):
        return (
            ("tx_extra_nonce", TxExtraNonce),
            ("tx_extra_additional_pub_keys", TxExtraAdditionalPubKeys),
        )
