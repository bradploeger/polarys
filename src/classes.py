"""Record classes and retention rules.

Every record is assigned exactly one record class at ingest.  The class and
the resulting retention (a fixed ``retain_until`` date, an event-based
``retention_rule`` or ``indefinite``) are written into the envelope *before*
signing, so they are covered by the signature and the Merkle proof.

Retention rule syntax
---------------------
``P<n>D`` / ``P<n>Y``            fixed period from ``received_at``
``event:<name>+P<n>Y``           period starting at a later trigger event
                                 (record kept under indefinite lock until then)
``indefinite``                   never expires; an approved exception

The system maximum is 35 years.  Anything longer, and ``indefinite``, is an
exception that needs two-person approval when a class is configured
(``RecordClass.requires_exception``).

The default periods are proposals based on common US practice, not legal
advice; they are configuration and must be confirmed with counsel.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .util import rfc3339

MAX_RETENTION_YEARS = 35
_RULE = re.compile(r"^(?:event:(?P<event>[a-z_]+)\+)?P(?P<n>\d+)(?P<unit>[DY])$")


class RetentionError(ValueError):
    pass


@dataclass(frozen=True)
class Retention:
    rule: str  # as in the module docstring

    def __post_init__(self) -> None:
        if self.rule != "indefinite" and not _RULE.match(self.rule):
            raise RetentionError(f"invalid retention rule {self.rule!r}")

    @property
    def indefinite(self) -> bool:
        return self.rule == "indefinite"

    @property
    def event(self) -> str | None:
        m = _RULE.match(self.rule)
        return m.group("event") if m else None

    @property
    def years(self) -> float:
        if self.indefinite:
            return float("inf")
        m = _RULE.match(self.rule)
        n = int(m.group("n"))
        return n if m.group("unit") == "Y" else n / 365

    @property
    def exceeds_maximum(self) -> bool:
        return self.years > MAX_RETENTION_YEARS

    def retain_until(self, start: datetime) -> datetime | None:
        """Expiry measured from ``start``; ``None`` for indefinite retention.

        For event-based rules pass the event time, not the ingest time.
        """
        if self.indefinite:
            return None
        m = _RULE.match(self.rule)
        n = int(m.group("n"))
        if m.group("unit") == "D":
            return start + timedelta(days=n)
        return add_years(start, n)


def add_years(dt: datetime, years: int) -> datetime:
    try:
        return dt.replace(year=dt.year + years)
    except ValueError:  # 29 February -> 28 February
        return dt.replace(year=dt.year + years, day=28)


@dataclass(frozen=True)
class RetentionCase:
    """A conditional retention inside a class; the first matching case wins."""

    when: dict  # attribute -> required value; "severity_max" compares numerically
    retention: Retention
    label: str = ""

    def matches(self, attrs: dict) -> bool:
        for key, want in self.when.items():
            if key == "severity_max":
                sev = attrs.get("severity")
                if sev is None or int(sev) > want:
                    return False
            elif key == "severity_min":
                sev = attrs.get("severity")
                if sev is None or int(sev) < want:
                    return False
            elif attrs.get(key) != want:
                return False
        return True


@dataclass(frozen=True)
class RecordClass:
    id: str
    name: str
    default: Retention
    cases: tuple[RetentionCase, ...] = field(default_factory=tuple)
    sources: tuple[str, ...] = ("upload", "api")

    def retention_for(self, attrs: dict) -> Retention:
        for case in self.cases:
            if case.matches(attrs):
                return case.retention
        return self.default

    @property
    def requires_exception(self) -> bool:
        return any(r.exceeds_maximum for r in (self.default, *(c.retention for c in self.cases)))


def _r(rule: str) -> Retention:
    return Retention(rule)


# Syslog severities: 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug.
DEFAULT_CLASSES: tuple[RecordClass, ...] = (
    RecordClass(
        "device_logs",
        "Device Logs",
        default=_r("P90D"),
        cases=(
            RetentionCase({"security": True}, _r("P7Y"), "security and audit events"),
            RetentionCase({"severity_max": 4}, _r("P1Y"), "WARNING and above"),
            RetentionCase({"severity_min": 5}, _r("P90D"), "NOTICE and below"),
        ),
        sources=("syslog", "windows_event", "upload", "api"),
    ),
    RecordClass("sales_invoices", "Sales Receipts / Invoices", _r("P7Y")),
    RecordClass("expense_docs", "Expense Documentation", _r("P7Y")),
    RecordClass("payroll", "Payroll Records", _r("P7Y")),
    RecordClass(
        "employee",
        "Employee Records",
        default=_r("event:separation+P7Y"),
        cases=(RetentionCase({"permanent": True}, _r("indefinite"), "designated permanent records"),),
        sources=("upload",),
    ),
    RecordClass("customer_data", "Customer Data", _r("event:relationship_end+P7Y")),
    RecordClass("corporate", "Corporate Records", _r("indefinite"), sources=("upload",)),
    RecordClass("tax_returns", "Tax Returns", _r("indefinite"), sources=("upload",)),
    RecordClass("tax_support", "Tax Return Supporting Documentation", _r("event:return_filed+P7Y"), sources=("upload",)),
    RecordClass("insurance", "Insurance", _r("event:policy_expired+P10Y"), sources=("upload",)),
    RecordClass("accounts_payable", "Accounts Payable", _r("P7Y")),
    RecordClass("ppe", "Plant/Property/Equipment Records", _r("event:asset_disposed+P7Y"), sources=("upload",)),
    RecordClass("legal", "Legal Matters", _r("event:matter_closed+P10Y"), sources=("upload",)),
    RecordClass("correspondence", "Correspondence", _r("P3Y")),
    RecordClass(
        "workplace_safety",
        "Workplace Safety",
        default=_r("P5Y"),
        cases=(RetentionCase({"exposure_record": True}, _r("P30Y"), "exposure and medical records"),),
        sources=("upload",),
    ),
    RecordClass("public_relations", "Public Relations", _r("P3Y")),
)


class ClassRegistry:
    def __init__(self, classes: tuple[RecordClass, ...] = DEFAULT_CLASSES):
        self._by_id = {c.id: c for c in classes}
        if len(self._by_id) != len(classes):
            raise ValueError("duplicate record class id")

    def get(self, class_id: str) -> RecordClass:
        try:
            return self._by_id[class_id]
        except KeyError:
            raise KeyError(f"unknown record class {class_id!r}") from None

    def __iter__(self):
        return iter(self._by_id.values())

    def classify(self, source_type: str, requested_class: str | None = None) -> RecordClass:
        """Pick the class for a record.

        Device log sources always map to ``device_logs``.  Uploads and API
        submissions must name a class (the upload page's category or the API
        client's ``record_class``), and the class must accept that source.
        """
        if source_type in ("syslog", "windows_event"):
            return self.get("device_logs")
        if not requested_class:
            raise RetentionError("uploads and API submissions must specify a record class")
        cls = self.get(requested_class)
        if source_type not in cls.sources:
            raise RetentionError(f"record class {cls.id} does not accept source {source_type}")
        return cls

    def resolve(self, record_class: RecordClass, attrs: dict, received_at: datetime) -> dict:
        """Envelope retention fields: ``{"retention_rule", "retain_until"}``."""
        retention = record_class.retention_for(attrs)
        if retention.event or retention.indefinite:
            until = None
        else:
            until = retention.retain_until(received_at)
        return {"retention_rule": retention.rule, "retain_until": rfc3339(until) if until else None}
