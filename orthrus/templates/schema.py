"""Declarative template schema - a pragmatic subset of the Nuclei format.

A template describes one or more HTTP requests plus *matchers* that decide
whether a response indicates the issue. This lets operators (and the community)
add detections as data files instead of Python code (PRD §6.1 - extensibility).

Supported matcher types: ``word``, ``regex``, ``status``, ``size``. Supported
extractor types: ``regex``, ``kval``. Nuclei's full DSL/expression matchers are
intentionally out of scope; everything here is evaluated by pure code in
``orthrus.templates.matchers``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from orthrus.core.schemas import Severity


class Matcher(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: str  # word | regex | status | size
    part: str = "body"  # body | header | all | status
    words: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    status: list[int] = Field(default_factory=list)
    size: list[int] = Field(default_factory=list)
    condition: str = "or"  # how multiple words/regex within this matcher combine
    negative: bool = False
    case_insensitive: bool = Field(default=False, alias="case-insensitive")


class Extractor(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: str = "regex"  # regex | kval
    name: str = ""
    part: str = "body"
    regex: list[str] = Field(default_factory=list)
    group: int = 0
    kval: list[str] = Field(default_factory=list)


class RequestTemplate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    method: str = "GET"
    path: list[str] = Field(default_factory=lambda: ["{{BaseURL}}"])
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    matchers: list[Matcher] = Field(default_factory=list)
    matchers_condition: str = Field(default="or", alias="matchers-condition")
    extractors: list[Extractor] = Field(default_factory=list)
    stop_at_first_match: bool = Field(default=True, alias="stop-at-first-match")
    redirects: bool = True


class TemplateInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str = ""
    author: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    reference: list[str] = Field(default_factory=list)
    cwe: str | None = None

    @property
    def primary_tag(self) -> str:
        return self.tags[0] if self.tags else "template"


class Template(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str
    info: TemplateInfo = Field(default_factory=TemplateInfo)
    # Accept both the legacy ``requests:`` key and modern ``http:`` key.
    requests: list[RequestTemplate] = Field(default_factory=list, alias="requests")

    @classmethod
    def from_dict(cls, data: dict) -> Template:
        """Build a Template, accepting either ``requests:`` or ``http:``."""
        payload = dict(data)
        if "requests" not in payload and "http" in payload:
            payload["requests"] = payload.get("http") or []
        return cls.model_validate(payload)


__all__ = ["Matcher", "Extractor", "RequestTemplate", "TemplateInfo", "Template"]
