"""
This module contains utility functions for the nxsuite package.
"""

import ctypes

def _to_c_char_p(*args):
        """
        Converts a list of strings to a list of ctypes.c_char_p.

        Args:
            args (list): List of strings

        Returns:
            list: List of ctypes.c_char_p
        """
        return [ctypes.c_char_p(arg.encode("utf-8")) for arg in args]