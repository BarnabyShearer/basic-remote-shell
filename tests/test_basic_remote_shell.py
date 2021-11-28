"""Tests."""

import basic_remote_shell


def test_compute_key() -> None:
    """Test we can compute key."""
    assert (
        basic_remote_shell.compute_key(b"", 64, 0, b"", b"")[:8]
        == b"\x06\r\xc6>U\x95\xdf\xfb"
    )


def test_message() -> None:
    """Text message handling."""
    msg = basic_remote_shell.Message(("\01" * 16).encode())
    assert msg.get_so_far() == b""
    assert msg.get_bytes(0) == b""
    assert msg.get_boolean()
    assert msg.get_int() == 16843009
    assert msg.get_mpint() == 282578800148737
    msg = basic_remote_shell.Message(("\01" * 8).encode())
    assert msg.get_binary() == b"\01\01\01\01"
    msg = basic_remote_shell.Message(("\01" * 8).encode())
    assert msg.get_boolean()
    assert msg.get_remainder() == b"\01\01\01\01\01\01\01"
    assert msg.get_bytes(10) == b"\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00"
    msg = basic_remote_shell.Message(("\04").encode())
    assert msg.get_mpint() == 0
    msg.add_int(0)
    msg.add_mpint(0)
    msg.add_binary(b"")
