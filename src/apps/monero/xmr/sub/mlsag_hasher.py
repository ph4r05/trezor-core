from apps.monero.xmr import crypto


class PreMlsagHasher:
    """
    Iterative construction of the pre_mlsag_hash
    """

    def __init__(self, state=None):
        from apps.monero.xmr.sub.keccak_hasher import KeccakXmrArchive

        self.is_simple = state[0] if state else None
        self.state = state[1] if state else 0
        self.kc_master = state[2] if state else crypto.get_keccak()
        self.rsig_hasher = state[3] if state else crypto.get_keccak()
        self.rtcsig_hasher = None
        if state:
            self.rtcsig_hasher = KeccakXmrArchive(state[4]) if state[4] else None
        else:
            self.rtcsig_hasher = KeccakXmrArchive()

    def state_save(self):
        return (
            self.is_simple,
            self.state,
            self.kc_master.ctx,
            self.rsig_hasher,
            self.rtcsig_hasher.ctx() if self.rtcsig_hasher else None,
        )

    def state_load(self, x):
        from apps.monero.xmr.sub.keccak_hasher import KeccakXmrArchive

        self.is_simple = x[0]
        self.state = x[1]
        self.kc_master = x[2]
        self.rsig_hasher = x[3]
        if x[4]:
            self.rtcsig_hasher = KeccakXmrArchive(x[4])
        else:
            self.rtcsig_hasher = None

    def init(self, is_simple):
        if self.state != 0:
            raise ValueError("State error")

        self.state = 1
        self.is_simple = is_simple

    def set_message(self, message):
        self.kc_master.update(message)

    def set_type_fee(self, rv_type, fee):
        if self.state != 1:
            raise ValueError("State error")
        self.state = 2
        self.rtcsig_hasher.uint(rv_type, 1)  # UInt8
        self.rtcsig_hasher.uvarint(fee)  # UVarintType

    def set_pseudo_out(self, out):
        if self.state != 2 and self.state != 3:
            raise ValueError("State error")
        self.state = 3

        from apps.monero.xmr.serialize_messages.ct_keys import KeyV

        self.rtcsig_hasher.field(out, KeyV.ELEM_TYPE)

    def set_ecdh(self, ecdh):
        if self.state != 2 and self.state != 3 and self.state != 4:
            raise ValueError("State error")
        self.state = 4
        self.rtcsig_hasher.buffer(ecdh)

    def set_out_pk_mask(self, out_pk_mask):
        if self.state != 4 and self.state != 5:
            raise ValueError("State error")
        self.state = 5
        self.rtcsig_hasher.buffer(out_pk_mask)  # ECKey

    def rctsig_base_done(self):
        if self.state != 5:
            raise ValueError("State error")
        self.state = 6

        c_hash = self.rtcsig_hasher.get_digest()
        self.kc_master.update(c_hash)
        self.rtcsig_hasher = None

    def rsig_val(self, p, bulletproof, raw=False):
        if self.state == 8:
            raise ValueError("State error")

        if raw:
            if isinstance(p, list):
                for x in p:
                    self.rsig_hasher.update(x)
            else:
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

    def get_digest(self):
        if self.state != 6:
            raise ValueError("State error")
        self.state = 8

        c_hash = self.rsig_hasher.digest()
        self.rsig_hasher = None

        self.kc_master.update(c_hash)
        return self.kc_master.digest()
