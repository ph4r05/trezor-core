#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from trezor.crypto import aes


def encrypt(key, plaintext, iv=None):
    """
    Uses AES-CBC for encryption
    :param key:
    :param plaintext:
    :param iv:
    :return: ciphertext
    """
    ctx = aes(aes.CBC, key, iv)
    return ctx.encrypt(plaintext)


def decrypt(key, ciphertext, iv=None):
    """
    AES-CBC decryption
    :param key:
    :param ciphertext:
    :param iv:
    :return:
    """
    ctx = aes(aes.CBC, key, iv)
    return ctx.decrypt(ciphertext)
