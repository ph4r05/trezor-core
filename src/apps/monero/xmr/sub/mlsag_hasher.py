from apps.monero.xmr import common, crypto
from apps.monero.xmr.serialize_messages.base import ECKey
from apps.monero.xmr.serialize_messages.ct_keys import KeyV
from apps.monero.xmr.serialize_messages.tx_full import RctSigBase
from apps.monero.xmr.serialize_messages.tx_rsig import RctType
from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhInfo


class PreMlsagHasher(object):
    """
    Iterative construction of the pre_mlsag_hash
    """
    def __init__(self):
        from apps.monero.xmr.sub.keccak_archive import KeccakArchive

        self.is_simple = None
        self.state = 0
        self.kc_master = common.HashWrapper(crypto.get_keccak())
        self.rtcsig_hasher = KeccakArchive()
        self.rsig_hasher = crypto.get_keccak()

    def init(self, is_simple):
        if self.state != 0:
            raise ValueError('State error')

        self.state = 1
        self.is_simple = is_simple

    async def set_message(self, message):
        self.kc_master.update(message)

    async def set_type_fee(self, rv_type, fee):
        if self.state != 1:
            raise ValueError('State error')
        self.state = 2

        await self.rtcsig_hasher.ar.message_field(None, field=RctSigBase.MFIELDS[0], fvalue=rv_type)
        await self.rtcsig_hasher.ar.message_field(None, field=RctSigBase.MFIELDS[1], fvalue=fee)

    async def set_pseudo_out(self, out):
        if self.state != 2 and self.state != 3:
            raise ValueError('State error')
        self.state = 3

        await self.rtcsig_hasher.ar.field(out, KeyV.ELEM_TYPE)

    async def set_ecdh(self, ecdh):
        if self.state != 2 and self.state != 3 and self.state != 4:
            raise ValueError('State error')
        self.state = 4

        await self.rtcsig_hasher.ar.field(ecdh, EcdhInfo.ELEM_TYPE)

    async def set_out_pk(self, out_pk, mask=None):
        if self.state != 4 and self.state != 5:
            raise ValueError('State error')
        self.state = 5

        await self.rtcsig_hasher.ar.field(mask if mask else out_pk.mask, ECKey)

    async def rctsig_base_done(self):
        if self.state != 5:
            raise ValueError('State error')
        self.state = 6

        c_hash = self.rtcsig_hasher.kwriter.get_digest()
        self.kc_master.update(c_hash)
        del self.rtcsig_hasher

    async def rsig_val(self, p, bulletproof, raw=False):
        if self.state == 8:
            raise ValueError('State error')

        if raw:
            self.rsig_hasher.update(p)
            return

        if bulletproof:
            self.rsig_hasher.update(p.A)
            self.rsig_hasher.update(p.S)
            self.rsig_hasher.update(p.T1)
            self.rsig_hasher.update(p.T2)
            self.rsig_hasher.update(p.taux)
            self.rsig_hasher.update(p.mu)
            for i in range(len(p.L)):
                self.rsig_hasher.update(p.L[i])
            for i in range(len(p.R)):
                self.rsig_hasher.update(p.R[i])
            self.rsig_hasher.update(p.a)
            self.rsig_hasher.update(p.b)
            self.rsig_hasher.update(p.t)

        else:
            for i in range(64):
                self.rsig_hasher.update(p.asig.s0[i])
            for i in range(64):
                self.rsig_hasher.update(p.asig.s1[i])
            self.rsig_hasher.update(p.asig.ee)
            for i in range(64):
                self.rsig_hasher.update(p.Ci[i])

    async def get_digest(self):
        if self.state != 6:
            raise ValueError('State error')
        self.state = 8

        c_hash = self.rsig_hasher.digest()
        del self.rsig_hasher

        self.kc_master.update(c_hash)
        return self.kc_master.digest()


async def get_pre_mlsag_hash(rv):
    """
    Generates final message for the Ring CT signature

    :param rv:
    :type rv: RctSig
    :return:
    """
    from apps.monero.xmr.sub.keccak_archive import get_keccak_writer
    from apps.monero.xmr.serialize import xmrserialize

    kc_master = common.HashWrapper(crypto.get_keccak())
    kc_master.update(rv.message)

    is_simple = rv.type in [RctType.Simple, RctType.SimpleBulletproof]
    inputs = len(rv.pseudoOuts) if is_simple else 0
    outputs = len(rv.ecdhInfo)

    kwriter = get_keccak_writer()
    ar = xmrserialize.Archive(kwriter, True)
    await rv.serialize_rctsig_base(ar, inputs, outputs)
    c_hash = kwriter.get_digest()
    kc_master.update(c_hash)

    kc = crypto.get_keccak()
    if rv.type in [RctType.FullBulletproof, RctType.SimpleBulletproof]:
        for p in rv.p.bulletproofs:
            kc.update(p.A)
            kc.update(p.S)
            kc.update(p.T1)
            kc.update(p.T2)
            kc.update(p.taux)
            kc.update(p.mu)
            for i in range(len(p.L)):
                kc.update(p.L[i])
            for i in range(len(p.R)):
                kc.update(p.R[i])
            kc.update(p.a)
            kc.update(p.b)
            kc.update(p.t)

    else:
        for r in rv.p.rangeSigs:
            for i in range(64):
                kc.update(r.asig.s0[i])
            for i in range(64):
                kc.update(r.asig.s1[i])
            kc.update(r.asig.ee)
            for i in range(64):
                kc.update(r.Ci[i])

    c_hash = kc.digest()
    kc_master.update(c_hash)
    return kc_master.digest()
