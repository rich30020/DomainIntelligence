
from collections import defaultdict
from threading import RLock
from typing import Callable, Any


class EventManager:
    """
    Gestisce gli eventi interni di Domain Intelligence.
    """

    def __init__(self):
        self._listeners = defaultdict(list)
        self._lock = RLock()

    def subscribe(
        self,
        event_name: str,
        callback: Callable
    ):
        """Registra una funzione per un determinato evento."""

        with self._lock:
            if callback not in self._listeners[event_name]:
                self._listeners[event_name].append(callback)

    def unsubscribe(
        self,
        event_name: str,
        callback: Callable
    ):
        """Rimuove una funzione dagli ascoltatori."""

        with self._lock:
            if callback in self._listeners[event_name]:
                self._listeners[event_name].remove(callback)

    def emit(
        self,
        event_name: str,
        data: Any = None
    ):
        """Invia un evento a tutti gli ascoltatori."""

        with self._lock:
            listeners = list(
                self._listeners[event_name]
            )

        for callback in listeners:
            try:
                callback(data)
            except Exception:
                # Un listener non deve bloccare gli altri.
                continue

    def clear(self):
        """Rimuove tutti gli ascoltatori."""

        with self._lock:
            self._listeners.clear()
