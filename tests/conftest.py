"""No real networking in this synthetic suite; production transports unchanged."""
import socket

import pytest


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def denied(*args, **kwargs):
        raise OSError('SYNTHETIC_SUITE_NETWORK_DENIED')
    monkeypatch.setattr(socket, 'create_connection', denied)
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket.socket, 'connect_ex', denied)
    monkeypatch.setattr(socket.socket, 'sendto', denied)
