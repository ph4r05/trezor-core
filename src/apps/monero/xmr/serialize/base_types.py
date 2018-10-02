class XmrType:
    pass


class UVarintType(XmrType):
    pass


class IntType(XmrType):
    WIDTH = 0
    SIGNED = 0
    VARIABLE = 0


class UInt8(IntType):
    WIDTH = 1
