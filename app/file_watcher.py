import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


def watch(file_name: str, callback: callable = None, path: str = "/etc"):
    class FileChangeHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.src_path.endswith(file_name):
                print("File updated:", event.src_path)
                if callback is not None:
                    callback()

    handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(handler, path=path, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()


def watch_async(file_name: str, callback: callable = None, path: str = "/etc"):
    threading.Thread(target=watch, args=(file_name, callback, path), daemon=True).start()
