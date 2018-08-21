#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
import micropython
import sys

from trezor import log

PREV_MEM = gc.mem_free()
CUR_MES = 0


def log_trace(x=None):
    log.debug(
        __name__,
        "Log trace %s, ... F: %s A: %s, S: %s",
        x,
        gc.mem_free(),
        gc.mem_alloc(),
        micropython.stack_use(),
    )


def check_mem(x=""):
    global PREV_MEM, CUR_MES

    gc.collect()
    free = gc.mem_free()
    diff = PREV_MEM - free
    log.debug(
        __name__,
        "======= {} {} Diff: {} Free: {} Allocated: {}".format(
            CUR_MES, x, diff, free, gc.mem_alloc()
        ),
    )
    micropython.mem_info()
    gc.collect()
    CUR_MES += 1
    PREV_MEM = free


def retit(**kwargs):
    from trezor.messages.Failure import Failure

    return Failure(**kwargs)


async def dispatch_diag(ctx, msg, **kwargs):
    if msg.ins == 0:
        check_mem(0)
        return retit()

    elif msg.ins == 1:
        check_mem(1)
        micropython.mem_info(1)
        return retit()

    elif msg.ins == 2:
        log.debug(__name__, "_____________________________________________")
        log.debug(__name__, "_____________________________________________")
        log.debug(__name__, "_____________________________________________")
        return retit()

    elif msg.ins == 3:
        pass

    elif msg.ins == 4:
        total = 0
        monero = 0

        for k, v in sys.modules.items():
            log.info(__name__, "Mod[%s]: %s", k, v)
            total += 1
            if k.startswith("apps.monero"):
                monero += 1
        log.info(__name__, "Total modules: %s, Monero modules: %s", total, monero)
        return retit()

    elif msg.ins == 5:
        check_mem()
        from apps.monero.xmr import bulletproof as bp

        check_mem("BP Imported")
        from apps.monero.xmr import crypto

        check_mem("Crypto Imported")

        bpi = bp.BulletProofBuilder()
        bpi.gc_fnc = gc.collect
        bpi.gc_trace = log_trace

        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()
        check_mem("BP pre input")

        bpi.set_input(val, mask)
        check_mem("BP post input")

        bp_res = bpi.prove()
        check_mem("BP post prove")

        bpi.verify(bp_res)
        check_mem("BP post verify")

        return retit()

    return retit()