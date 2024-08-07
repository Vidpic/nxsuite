"""
This module contains functions for working with ticket files.
"""

def get_titlekey(tik):
    """
    Get the title key from a ticket file.

    Args:
        tik (str): Path to the ticket file

    Returns:
        str: Title key
    """
    if tik.endswith(".tik"):
        with open(tik, "rb") as file:
            file.seek(0x180)
            titlekey = file.read(16).hex().upper()
            return titlekey
    else:
        print("This is not a ticket file.")
        return None
