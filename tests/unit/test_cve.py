"""Tests for the pure NVD CVE matcher."""

from __future__ import annotations

from orthrus.core.schemas import Severity
from orthrus.scanners.cve_matcher import match_cves

NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Buffer overflow in nginx."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            },
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.25.0",
                                        "versionEndExcluding": "1.25.4",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}


def test_version_in_range_matches():
    matches = match_cves("nginx", "1.25.3", NVD_SAMPLE)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2024-0001"
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].score == 9.8


def test_version_outside_range_no_match():
    assert match_cves("nginx", "1.26.0", NVD_SAMPLE) == []
    assert match_cves("nginx", "1.24.9", NVD_SAMPLE) == []


def test_exact_version_cpe_matches():
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-9999",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {},
                    "configurations": [
                        {"nodes": [{"cpeMatch": [
                            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:2.0.1:*:*:*:*:*:*:*"}
                        ]}]}
                    ],
                }
            }
        ]
    }
    assert len(match_cves("widget", "2.0.1", nvd)) == 1
    assert match_cves("widget", "2.0.2", nvd) == []
