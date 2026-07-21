"""Operator notes - a lightweight, searchable knowledge base (PRD §7.13).

Free-form markdown notes attached to a program (or standalone), tagged and
full-text searchable. This is where a hunter keeps methodology, per-program tips,
and recon summaries; it's also the corpus a future RAG copilot retrieves over.

Stored as JSON at ``$ORTHRUS_HOME/notes.json``.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def default_notes_path() -> Path:
    home = os.environ.get("ORTHRUS_HOME")
    base = Path(home) if home else Path.home() / ".orthrus"
    return base / "notes.json"


@dataclass
class Note:
    id: str = field(default_factory=lambda: secrets.token_hex(4))
    title: str = ""
    body: str = ""
    program: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


class NotesStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_notes_path()

    def _read(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def add(self, note: Note) -> Note:
        data = self._read()
        data[note.id] = asdict(note)
        self._write(data)
        return note

    def get(self, note_id: str) -> Note | None:
        row = self._read().get(note_id)
        return Note(**row) if row else None

    def delete(self, note_id: str) -> bool:
        data = self._read()
        if note_id in data:
            del data[note_id]
            self._write(data)
            return True
        return False

    def list(self, *, program: str | None = None, tag: str | None = None) -> list[Note]:
        notes = [Note(**r) for r in self._read().values()]
        if program:
            notes = [n for n in notes if n.program.lower() == program.lower()]
        if tag:
            notes = [n for n in notes if tag.lower() in [t.lower() for t in n.tags]]
        return sorted(notes, key=lambda n: n.updated_at, reverse=True)

    def search(self, query: str, *, program: str | None = None) -> list[Note]:
        q = (query or "").lower().strip()
        if not q:
            return self.list(program=program)
        out = []
        for n in self.list(program=program):
            haystack = f"{n.title}\n{n.body}\n{' '.join(n.tags)}".lower()
            if q in haystack:
                out.append(n)
        return out


__all__ = ["Note", "NotesStore", "default_notes_path"]
