# Automatically generated by pb2py
import protobuf as p


class MoneroTsxMlsagDoneResp(p.MessageType):
    MESSAGE_WIRE_TYPE = 314
    FIELDS = {
        1: ('full_message_hash', p.BytesType, 0),
    }

    def __init__(
        self,
        full_message_hash: bytes = None
    ) -> None:
        self.full_message_hash = full_message_hash