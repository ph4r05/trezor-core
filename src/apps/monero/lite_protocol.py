#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
import micropython

from trezor import log


async def layout_lite_init_protocol(state, ctx, msg):
    from apps.monero.protocol_lite import lite
    from trezor.messages.MoneroLiteInitAck import MoneroLiteInitAck

    state.ctx_lite = lite.LiteProtocol()
    await state.ctx_lite.init(ctx, msg)
    return MoneroLiteInitAck()


async def layout_lite_protocol(state, ctx, msg):
    from apps.monero.protocol_lite import lite
    from trezor.messages.MoneroLiteAck import MoneroLiteAck

    log.debug(
        __name__,
        "### Lite. Free: {} Allocated: {}".format(
            gc.mem_free(), gc.mem_alloc()
        ),
    )

    gc.collect()
    # micropython.mem_info()
    # micropython.mem_info(1)

    try:
        sw, buff = await state.ctx_lite.dispatch(ctx, msg.ins, msg.p1, msg.p2, msg.data)

        res = MoneroLiteAck(sw=sw, data=buff)
        return res

    except Exception as e:
        state.ctx_ki = None
        log.debug(__name__, "Lite error, %s: %s", type(e), e)
        raise
