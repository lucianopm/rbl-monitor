import os
import threading

from app import app, scheduler

# Use one Gunicorn worker. Each additional worker would create another scheduler.
if os.getenv("ENABLE_SCHEDULER", "1") == "1":
    threading.Thread(target=scheduler, daemon=True, name="rbl-scheduler").start()
