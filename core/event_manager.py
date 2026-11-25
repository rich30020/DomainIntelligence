
"""Thread-safe in-process event subscription and dispatch."""

from collections import defaultdict
from threading import RLock
from typing import Callable, Any


class EventManager:
    """Publish named events to registered callbacks.

    The listener list is copied under the lock, then callbacks run outside it.
    This prevents application code from holding internal synchronization and
    allows one failing listener to be isolated from the remaining listeners.
    """

    def __init__(self):
        self._listeners = defaultdict(list)
        self._lock = RLock()

    def subscribe(
        self,
        event_name: str,
        callback: Callable
    ):
        """Register ``callback`` once for the given event name."""

        with self._lock:
            if callback not in self._listeners[event_name]:
                self._listeners[event_name].append(callback)

    def unsubscribe(
        self,
        event_name: str,
        callback: Callable
    ):
        """Remove ``callback`` from the named event, if registered."""

        with self._lock:
            if callback in self._listeners[event_name]:
                self._listeners[event_name].remove(callback)

    def emit(
        self,
        event_name: str,
        data: Any = None
    ):
        """Dispatch event data to a snapshot of the current listeners."""

        with self._lock:
            listeners = list(
                self._listeners[event_name]
            )

        # Invoke callbacks outside the lock; listeners may subscribe or
        # unsubscribe while an event is being handled.
        for callback in listeners:
            try:
                callback(data)
            except Exception:
                # Listener failures are isolated so delivery can continue.
                continue

    def clear(self):
        """Remove every registered listener from the event registry."""

        with self._lock:
            self._listeners.clear()
