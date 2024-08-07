"""
This module sets the default values for the nxsuite.
"""

import ctypes
import os

_prodkeys = None
_sdk_version = None
_key_generation = None
_title_id = None
_title_version = None


def _load_dll(hactool=True):
    """
    Loads the hactool.dll or hacpack.dll library.
    """
    dll_name = "hactool.dll" if hactool else "hacpack.dll"
    dll_path = os.path.join(os.path.dirname(__file__), "_libs", dll_name)
    return ctypes.CDLL(dll_path, winmode=0)


def _get_prodkeys():
    """
    Returns the prod.keys file.

    Returns:
        str: Path to the prod.keys file
    """
    return _prodkeys


def _get_sdk_version():
    """
    Returns the SDK version.

    Returns:
        str: SDK version
    """
    return _sdk_version


def _get_key_generation():
    """
    Returns the key generation.

    Returns:
        str: Key generation
    """
    return _key_generation


def _get_title_id():
    """
    Returns the title ID.

    Returns:
        str: Title ID
    """
    return _title_id


def _get_title_version():
    """
    Returns the title version.

    Returns:
        str: Title version
    """
    return _title_version


def prodkeys(p_dir):
    """
    Sets the default prod.keys file.

    Args:
        p_dir (str): Path to the prod.keys file
    """
    if p_dir:
        global _prodkeys
        _prodkeys = p_dir


def sdk_version(sdk_ver):
    """
    Sets the default SDK version.

    Args:
        sdk_version (str): SDK version
    """
    global _sdk_version
    _sdk_version = sdk_ver


def key_generation(key_gen):
    """
    Sets the default key generation.

    Args:
        key_generation (str): Key generation
    """
    global _key_generation
    _key_generation = key_gen


def title_id(t_id):
    """
    Sets the default title ID.

    Args:
        title_id (str): Title ID
    """
    global _title_id
    _title_id = t_id


def title_version(t_ver):
    """
    Sets the default title version.

    Args:
        title_version (str): Title version
    """
    global _title_version
    _title_version = t_ver
