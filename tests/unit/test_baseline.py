"""Tests for soft-404 / catch-all baseline calibration (false-positive suppression)."""

from __future__ import annotations

from types import SimpleNamespace

from hydra.core.baseline import (
    BaselineProfile,
    ResponseFingerprint,
    build_baseline,
    root_url,
)


# --------------------------------------------------------- ResponseFingerprint
def test_fingerprint_from_response_counts():
    fp = ResponseFingerprint.from_response(200, "one two\nthree")
    assert fp.status == 200
    assert fp.length == len("one two\nthree")
    assert fp.word_count == 3
    assert fp.line_count == 2


def test_similar_requires_same_status():
    a = ResponseFingerprint.from_response(200, "x" * 100)
    b = ResponseFingerprint.from_response(404, "x" * 100)
    assert a.similar_to(b) is False


def test_similar_on_close_length():
    base = ResponseFingerprint.from_response(200, "x" * 1000)
    near = ResponseFingerprint.from_response(200, "x" * 1010)  # within 5%
    assert near.similar_to(base) is True


def test_similar_via_word_line_counts_when_length_differs():
    # A catch-all that echoes the requested path: counts barely move even though
    # the absolute byte length shifts beyond the length tolerance.
    body = "\n".join(["line of words here"] * 50)  # 50 lines, 200 words
    base = ResponseFingerprint.from_response(200, body)
    echoed = ResponseFingerprint.from_response(200, body + " /hydra-not-found-abc")
    # length differs by only ~20 bytes here, but force the count-based path too:
    big = ResponseFingerprint(status=200, length=base.length + 9999, word_count=base.word_count + 1, line_count=base.line_count)
    assert echoed.similar_to(base) is True
    assert big.similar_to(base) is True


def test_not_similar_when_everything_differs():
    base = ResponseFingerprint.from_response(200, "x" * 100)
    other = ResponseFingerprint.from_response(200, "y\n" * 800)
    assert other.similar_to(base) is False


# ------------------------------------------------------------- BaselineProfile
def test_catch_all_true_for_found_status():
    p = BaselineProfile(fingerprints=[ResponseFingerprint.from_response(200, "home")])
    assert p.catch_all is True


def test_catch_all_false_for_clean_404():
    p = BaselineProfile(fingerprints=[ResponseFingerprint.from_response(404, "not found")])
    assert p.catch_all is False


def test_matches_empty_profile_is_false():
    assert BaselineProfile().matches(200, "anything") is False


def test_matches_recognises_the_catch_all():
    body = "<html><body>Welcome home</body></html>"
    p = BaselineProfile(fingerprints=[ResponseFingerprint.from_response(200, body)])
    assert p.matches(200, body) is True
    assert p.matches(200, body + "x") is True  # tiny echo variation
    assert p.matches(404, body) is False  # different status -> a real signal


def test_matches_rejects_genuinely_different_response():
    p = BaselineProfile(fingerprints=[ResponseFingerprint.from_response(200, "short home")])
    big = "<html>" + "data row\n" * 500 + "</html>"
    assert p.matches(200, big) is False


# -------------------------------------------------------------------- root_url
def test_root_url_variants():
    assert root_url("http://h:8080/a/b") == "http://h:8080"
    assert root_url("example.com") == "http://example.com"  # scheme-less -> http
    assert root_url("https://x.test") == "https://x.test"


# --------------------------------------------------------------- build_baseline
class _Resp:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.text = text


class _Http:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs: object) -> _Resp:
        self.calls.append(url)
        return self._resp


def _ctx(http: _Http, *, allow: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(target="http://127.0.0.1:8731/"),
        scope=SimpleNamespace(is_allowed=lambda url: allow),
        http=http,
    )


async def test_build_baseline_profiles_a_catch_all():
    http = _Http(_Resp(200, "<html>home</html>"))
    profile = await build_baseline(_ctx(http))
    assert len(profile.fingerprints) == 3  # three nonsense probes
    assert profile.catch_all is True
    # the catch-all response is recognised as not-a-real-hit
    assert profile.matches(200, "<html>home</html>") is True
    assert all("hydra-not-found-" in u for u in http.calls)


async def test_build_baseline_skips_out_of_scope():
    http = _Http(_Resp(200, "home"))
    profile = await build_baseline(_ctx(http, allow=False))
    assert profile.fingerprints == []
    assert http.calls == []


async def test_build_baseline_clean_404_is_not_catch_all():
    http = _Http(_Resp(404, "Not Found"))
    profile = await build_baseline(_ctx(http))
    assert len(profile.fingerprints) == 3
    assert profile.catch_all is False
