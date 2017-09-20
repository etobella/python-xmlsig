# -*- coding: utf-8 -*-
# © 2017 Creu Blanca
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).


class Algorithm(object):
    private_key_class = None
    public_key_class = None

    @staticmethod
    def sign(data, private_key, digest):
        raise Exception("Sign function must be redefined")

    @staticmethod
    def verify(signature_value, data, public_key, digest):
        raise Exception("Verify function must be redefined")

    @staticmethod
    def key_value(node, public_key):
        raise Exception("Key Value function must be redefined")
