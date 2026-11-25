
"""Thread-pool helper for background tasks with cooperative cancellation."""

from concurrent.futures import ThreadPoolExecutor, Future
from threading import Event, RLock
from uuid import uuid4


class TaskManager:
    """Submit, track, cancel, and shut down background work safely.

    Each task receives its own ``threading.Event``. Long-running functions
    should check the event regularly; cancelling a Future cannot stop Python
    code that is already executing.
    """

    def __init__(self, max_workers: int = 3):

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="DomainIntel"
        )

        self._tasks = {}
        self._lock = RLock()

    def submit(self, function, *args, **kwargs):
        """Submit a callable and return its ID, Future, and cancellation event.

        The event is passed as a keyword argument named ``cancellation_event``
        so the submitted function can cooperate with cancellation requests.
        """

        task_id = str(uuid4())
        cancellation_event = Event()

        future = self._executor.submit(
            function,
            *args,
            cancellation_event=cancellation_event,
            **kwargs
        )

        with self._lock:
            self._tasks[task_id] = {
                "future": future,
                "cancellation_event": cancellation_event
            }

        return task_id, future, cancellation_event

    def cancel(self, task_id: str) -> bool:
        """Signal a running task to stop, or cancel it before it starts."""

        with self._lock:
            task = self._tasks.get(task_id)

        if not task:
            return False

        # Signal the callable first; Future.cancel() only prevents work that
        # has not started and cannot interrupt an executing thread.
        task["cancellation_event"].set()

        # Also cancel the Future when the task has not started yet.
        task["future"].cancel()

        return True

    def get_task(self, task_id: str):

        with self._lock:
            return self._tasks.get(task_id)

    def cleanup(self):
        """Remove completed tasks from the in-memory task registry."""

        with self._lock:
            completed = [
                task_id
                for task_id, task in self._tasks.items()
                if task["future"].done()
            ]

            for task_id in completed:
                del self._tasks[task_id]

    def shutdown(self):
        """Signal all tasks to stop and wait for the executor to finish."""

        with self._lock:
            for task in self._tasks.values():
                task["cancellation_event"].set()

        self._executor.shutdown(
            wait=True,
            cancel_futures=True
        )
