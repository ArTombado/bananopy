import bananopy.banano as ban


def test_ban_from_raw():
    amount = 10 ** 29
    assert ban.ban_from_raw(amount) == 1


def test_ban_to_raw():
    amount = 1
    assert ban.ban_to_raw(amount) == 10 ** 29


def test_ban_to_banoshi():
    amount = 1
    assert ban.ban_to_banoshi(amount) == 100


def test_ban_from_banoshi():
    amount = 100
    assert ban.ban_from_banoshi(amount) == 1