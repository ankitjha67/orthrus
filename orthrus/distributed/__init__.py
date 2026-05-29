"""Distributed scanning via Celery (PRD §15.3).

Optional ([distributed] extra: celery + redis). Workers are stateless and pull
per-target scan tasks from a Redis broker, writing results to the shared
database. Import the submodules only when running in distributed mode.
"""
