# Automatically generated by pb2py
import protobuf as p


class MoneroTsxSetOutput(p.MessageType):
    FIELDS = {
        1: ('dst_entr', p.BytesType, 0),
        2: ('dst_entr_hmac', p.BytesType, 0),
    }

    def __init__(
        self,
        dst_entr: bytes = None,
        dst_entr_hmac: bytes = None
    ) -> None:
        self.dst_entr = dst_entr
        self.dst_entr_hmac = dst_entr_hmac
