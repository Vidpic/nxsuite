"""
This module provides functions to work with NCA files.
"""

import ctypes
from dataclasses import dataclass
from .setup import (
    _load_dll,
    _get_prodkeys,
    _get_sdk_version,
    _get_key_generation,
    _get_title_id,
    _get_title_version,
)
from .utils import _to_c_char_p


_hactool_dll = _load_dll()
_hacpack_dll = _load_dll(hactool=False)


class NCAInfoC(ctypes.Structure):
    """
    NCAInfo is a ctypes structure that holds information about an NCA file.

    Attributes:
        status (bool): Indicates if the NCA file was successfully processed
        content_size (int): Size of the NCA content
        title_id (int): Title ID
        sdk_version (str): SDK version
        distribution_type (str): Distribution type (Download, Gamecard)
        content_type (str): Content type (Program, Meta, Control, Logo, Manual)
        master_key_rev (str): Master key revision
    """

    _fields_ = [
        ("status", ctypes.c_bool),
        ("content_size", ctypes.c_uint64),
        ("title_id", ctypes.c_uint64),
        ("sdk_version", ctypes.c_char * 20),
        ("distribution_type", ctypes.c_char_p),
        ("content_type", ctypes.c_char_p),
        ("master_key_rev", ctypes.c_char * 20),
    ]


@dataclass
class NCAInfo:
    """
    NCAInfo is a dataclass that holds information about an NCA file.

    Attributes:
        content_size (int): Size of the NCA content
        title_id (int): Title ID
        sdk_version (str): SDK version
        distribution_type (str): Distribution type (Download, Gamecard)
        content_type (str): Content type (Program, Meta, Control, Logo, Manual)
        master_key_rev (str): Master key revision
    """

    nca_info: NCAInfoC

    @property
    def content_size(self) -> str:
        """
        Returns the size of the NCA content.

        Returns:
            str: Size of the NCA content
        """
        return f"0x{self.nca_info.content_size:016x}"

    @property
    def title_id(self) -> str:
        """
        Returns the title ID.

        Returns:
            str: Title ID
        """
        return f"0x{self.nca_info.title_id:016x}"

    @property
    def sdk_version(self) -> str:
        """
        Returns the SDK version.

        Returns:
            str: SDK version
        """
        return self.nca_info.sdk_version.decode("utf-8")

    @property
    def distribution_type(self) -> str:
        """
        Returns the distribution type.

        Returns:
            str: Distribution type
        """
        return self.nca_info.distribution_type.decode("utf-8")

    @property
    def content_type(self) -> str:
        """
        Returns the content type.

        Returns:
            str: Content type
        """
        return self.nca_info.content_type.decode("utf-8")

    @property
    def master_key_rev(self) -> str:
        """
        Returns the master key revision.

        Returns:
            str: Master key revision
        """
        return self.nca_info.master_key_rev.decode("utf-8")

    def __str__(self):
        return (
            f"\t\t\t   Content Size: {self.content_size}\n"
            f"\t\t\t   Title ID: {self.title_id}\n"
            f"\t\t\t   SDK Version: {self.sdk_version}\n"
            f"\t\t\t   Distribution Type: {self.distribution_type}\n"
            f"\t\t\t   Content Type: {self.content_type}\n"
            f"\t\t\t   Master Key Revision: {self.master_key_rev}"
        )


_program_nca = _hacpack_dll.program_nca
_program_nca.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_program_nca.restype = ctypes.c_bool

_meta_nca = _hacpack_dll.meta_nca
_meta_nca.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_meta_nca.restype = ctypes.c_bool

_decrypt_nca = _hactool_dll.decrypt_nca
_decrypt_nca.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_decrypt_nca.restype = ctypes.c_bool

_nca_info = _hactool_dll.nca_info
_nca_info.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_nca_info.restype = NCAInfoC

_extract_romfs = _hactool_dll.extract_romfs
_extract_romfs.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_extract_romfs.restype = ctypes.c_bool


def info(nca, prodkeys=None):
    """
    Extracts information about an NCA file.

    Args:
        nca (str): Path to the NCA file
        prodkeys (str): Path to the prod.keys file

    Returns:
        str: Information about the NCA file
        str: Distribution type
    """
    if nca.endswith(".nca"):
        prodkeys = prodkeys or _get_prodkeys()

        if not prodkeys:
            print("Error: prod.keys file not set")
            return True

        nca_info = _nca_info(*_to_c_char_p(nca, prodkeys))
        return NCAInfo(nca_info)
    else:
        print("This is not a NCA file")
        return None


def decrypt(nca, out_dir, titlekey, prodkeys=None):
    """
    Decrypts an NCA file.

    Args:
        nca (str): Path to the NCA file
        titlekey (str): Title key
        out_dir (str): Path to the output directory
        prodkeys (str): Path to the prod.keys file

    Returns:
        bool: Indicates if the NCA file was successfully decrypted
    """
    if nca.endswith(".nca"):
        prodkeys = prodkeys or _get_prodkeys()

        if not prodkeys:
            print("Error: prod.keys file not set")
            return True

        return _decrypt_nca(*_to_c_char_p(nca, out_dir, titlekey, prodkeys))
    else:
        print("This is not a NCA file")
        return True


def extract_romfs(base_nca, update_nca, out_dir, update_titlekey, prodkeys=None):
    """
    Patches a RomFS directory.

    Args:
        base_nca (str): Path to the base NCA file
        update_nca (str): Path to the update NCA file
        out_dir (str): Path to the output directory
        update_titlekey (str): Update title key
        prodkeys (str): Path to the prod.keys file

    Returns:
        bool: Indicates if the RomFS directory was successfully extracted
    """
    if base_nca.endswith(".nca") and update_nca.endswith(".nca"):
        prodkeys = prodkeys or _get_prodkeys()

        if not prodkeys:
            print("Error: prod.keys file not set")
            return True

        return _extract_romfs(
            *_to_c_char_p(base_nca, update_nca, out_dir, update_titlekey, prodkeys)
        )
    else:
        print("These are not NCA files")
        return True


def pack_program(
    exefs,
    romfs,
    logo,
    out_dir,
    sdk_version=None,
    key_generation=None,
    title_id=None,
    prodkeys=None,
):
    """
    Creates a Program NCA file.

    Args:
        exefs (str): Path to the ExeFS directory
        romfs (str): Path to the RomFS directory
        logo (str): Path to the logo directory
        out_dir (str): Path to the output directory
        prodkeys (str): Path to the prod.keys file
        sdk_version (str): SDK version
        key_generation (str): Key generation
        title_id (str): Title ID

    Returns:
        bool: Indicates if the Program NCA file was successfully created
    """
    prodkeys = prodkeys or _get_prodkeys()
    sdk_version = sdk_version or _get_sdk_version()
    key_generation = key_generation or _get_key_generation()
    title_id = title_id or _get_title_id()

    if not all([prodkeys, sdk_version, key_generation, title_id]):
        if not prodkeys:
            print("Error: prod.keys file not set")
        if not sdk_version:
            print("Error: SDK version not set")
        if not key_generation:
            print("Error: Key generation not set")
        if not title_id:
            print("Error: Title ID not set")
        return True

    return _program_nca(
        *_to_c_char_p(
            exefs,
            romfs,
            logo,
            out_dir,
            sdk_version,
            key_generation,
            title_id,
            prodkeys,
        )
    )


def pack_meta(
    legal_nca,
    control_nca,
    html_doc,
    program_nca,
    out_dir,
    sdk_version=None,
    key_generation=None,
    title_id=None,
    title_version=None,
    prodkeys=None,
):
    """
    Creates a Meta NCA file.

    Args:
        legal_nca (str): Path to the legal NCA file
        control_nca (str): Path to the control NCA file
        html_doc (str): Path to the HTML document
        program_nca (str): Path to the program NCA file
        out_dir (str): Path to the output directory
        sdk_version (str): SDK version
        key_generation (str): Key generation
        title_id (str): Title ID
        title_version (str): Title version
        prodkeys (str): Path to the prod.keys file

    Returns:
        bool: Indicates if the Meta NCA file was successfully created
    """
    prodkeys = prodkeys or _get_prodkeys()
    sdk_version = sdk_version or _get_sdk_version()
    key_generation = key_generation or _get_key_generation()
    title_id = title_id or _get_title_id()
    title_version = title_version or _get_title_version()

    if not all([prodkeys, sdk_version, key_generation, title_id, title_version]):
        if not prodkeys:
            print("Error: prod.keys file not set")
        if not sdk_version:
            print("Error: SDK version not set")
        if not key_generation:
            print("Error: Key generation not set")
        if not title_id:
            print("Error: Title ID not set")
        if not title_version:
            print("Error: Title version not set")
        return True

    return _meta_nca(
        *_to_c_char_p(
            legal_nca,
            control_nca,
            html_doc,
            program_nca,
            out_dir,
            sdk_version,
            key_generation,
            title_id,
            title_version,
            prodkeys,
        )
    )
