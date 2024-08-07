"""
This module provides functions to extract and pack NSP files.
"""

import ctypes
from .setup import _load_dll, _get_prodkeys, _get_title_id
from .utils import _to_c_char_p

_hactool_dll = _load_dll()
_hacpack_dll = _load_dll(hactool=False)

_extract_nsp = _hactool_dll.nsp
_extract_nsp.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_extract_nsp.restype = ctypes.c_bool

_pack_nsp = _hacpack_dll.nsp
_pack_nsp.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_pack_nsp.restype = ctypes.c_bool


def extract(nsp, out_dir, prodkeys=None):
    """
    Extracts an NSP file.

    Args:
        nsp (str): Path to the NSP file
        out_dir (str): Path to the output directory
        prodkeys (str): Path to the prod.keys file

    Returns:
        bool: Indicates if the NSP file was successfully extracted
    """
    if nsp.endswith(".nsp"):
        prodkeys = prodkeys or _get_prodkeys()

        if not prodkeys:
            print("Error: prod.keys file not set.")
            return True

        return _extract_nsp(*_to_c_char_p(nsp, out_dir, prodkeys))
    else:
        print("This is not a NSP file.")
        return True


def pack(nca_dir, out_dir, title_id=None, prodkeys=None):
    """
    Packs a NSP file.

    Args:
        nca_dir (str): Directory containing the NCA files
        out_dir (str): Output directory
        title_id (str): Title ID
        prodkeys (str): Path to the prod.keys file

    Returns:
        bool: Indicates if the NSP file was successfully created
    """
    prodkeys = prodkeys or _get_prodkeys()
    title_id = title_id or _get_title_id()

    if not prodkeys:
        print("Error: prod.keys file not set")
        return True

    if not title_id:
        print("Error: Title ID not set")
        return True

    return _pack_nsp(*_to_c_char_p(nca_dir, out_dir, title_id, prodkeys))
