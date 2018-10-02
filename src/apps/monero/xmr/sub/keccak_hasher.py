from apps.monero.xmr import crypto


class KeccakXmrArchive:
    def __init__(self, ctx=None):
        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = None
        self.keeping = False

    def ctx(self):
        return self.kwriter.ctx()

    def get_digest(self):
        return self.kwriter.get_digest()

    def refresh(self, ctx=None):
        if ctx is None:
            ctx = self.kwriter.ctx()
        self.kwriter = get_keccak_writer(ctx=ctx)

    def _ar(self, xser=None):
        if self.keeping and self.ar:
            return self.ar
        if xser:
            ar = xser.Archive(self.kwriter, True)
        else:
            from apps.monero.xmr.serialize import xmrserialize

            ar = xmrserialize.Archive(self.kwriter, True)
        self.ar = ar if self.keeping else None
        return ar

    def keep(self, keep=True):
        self.keeping = keep

    def release(self):
        self.ar = None

    def buffer(self, buf):
        return self.kwriter.write(buf)

    def uvarint(self, i):
        ar = self._ar(None)
        ar.uvarint(i)

    def uint(self, i, width):
        ar = self._ar(None)
        ar.uint(i, width=width)

    def field(self, elem=None, elem_type=None, params=None, xser=None):
        ar = self._ar(xser)
        return ar.field(elem, elem_type, params)

    def message_field(self, msg, field, fvalue=None, xser=None):
        ar = self._ar(xser)
        return ar.message_field(msg, field, fvalue)

    def container_size(
        self, container_len=None, container_type=None, params=None, xser=None
    ):
        ar = self._ar(xser)
        return ar.container_size(container_len, container_type, params)


class AHashWriter:
    def __init__(self, hasher):
        self.hasher = hasher

    def write(self, buf):
        self.hasher.update(buf)
        return len(buf)

    async def awrite(self, buf):
        return self.write(buf)

    def get_digest(self, *args) -> bytes:
        return self.hasher.digest(*args)

    def ctx(self):
        return self.hasher


def get_keccak_writer(ctx=None):
    return AHashWriter(crypto.get_keccak() if ctx is None else ctx)
