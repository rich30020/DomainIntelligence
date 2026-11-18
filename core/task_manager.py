
from concurrent.futures import ThreadPoolExecutor, Future
from threading import Event, RLock
from uuid import uuid4


class TaskManager:
    """
    Gestisce le attività eseguite in background.
    """

    def __init__(self, max_workers: int = 3):

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="DomainIntel"
        )

        self._tasks = {}
        self._lock = RLock()

    def submit(self, function, *args, **kwargs):
        """
        Avvia un'attività in background.
        Restituisce task_id, Future e cancellation_event.
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

        with self._lock:
            task = self._tasks.get(task_id)

        if not task:
            return False

        task["cancellation_event"].set()

        # Tenta di annullare anche il task se non è ancora partito.
        task["future"].cancel()

        return True

    def get_task(self, task_id: str):

        with self._lock:
            return self._tasks.get(task_id)

    def cleanup(self):

        with self._lock:
            completed = [
                task_id
                for task_id, task in self._tasks.items()
                if task["future"].done()
            ]

            for task_id in completed:
                del self._tasks[task_id]

    def shutdown(self):

        with self._lock:
            for task in self._tasks.values():
                task["cancellation_event"].set()

        self._executor.shutdown(
            wait=True,
            cancel_futures=True
        )
