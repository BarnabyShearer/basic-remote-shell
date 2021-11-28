"""Tests."""

import basic_remote_shell


def test_compute_key() -> None:
    """Test we can compute key."""
    assert basic_remote_shell.compute_key(b"", 0, 0, b"", b"") == b""


def test_message() -> None:
    """Text message handling."""
    msg = basic_remote_shell.Message()
    assert msg.get_remainder() == b""
    assert msg.get_so_far() == b""
    assert msg.get_bytes(0) == b""
    assert not msg.get_boolean()
    assert msg.get_int() == 0
    assert msg.get_mpint() == 0
    assert msg.get_binary() == b""

    msg.add_int(0)
    msg.add_mpint(0)
    msg.add_binary(b"")
