#/usr/bin/python
# -*- coding: utf-8 -*-

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class packetKindNotManaged(Error):
    """Exception raised when in input there is a packet which is not eapol.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr, msg):
        self.expr = expr
        self.msg = msg
