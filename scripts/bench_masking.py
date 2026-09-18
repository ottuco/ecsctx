"""Time mask_sensitive_data on fixed log lines.

    uv run python scripts/bench_masking.py                  # this checkout
    uv run python scripts/bench_masking.py --compare v0.6.8 v0.7.2

--compare loads each tag's ecsctx straight from git (nothing is checked out)
and prints its numbers beside this checkout's. Figures are microseconds per
call, best of several runs, with the cost of copying the event subtracted.
"(full record)" is one record through get_logging_config()'s masking: the
handler filter, then the formatter's processor (processor only before 0.7.0).
Compare numbers from the same machine only.
"""

from __future__ import annotations

import argparse
import copy
import importlib.abc
import importlib.util
import json
import logging
import os
import subprocess
import sys
import timeit

GATEWAY_BODY = (
    '{"id":"pay_9f8e7d6c5b4a","status":"AUTHORIZED","amount":"100.000","currency":"KWD",'
    '"processorInformation":{"approvalCode":"831000","responseCode":"100",'
    '"transactionId":"7266500001234567"},"orderInformation":{"amountDetails":'
    '{"authorizedAmount":"100.000","currency":"KWD"}},"_links":{"self":'
    '{"href":"/pts/v2/payments/7266500001234567"}}}'
)

CONNECT_LINE = {
    "event": "pg.response_received from apitest.cybersource.com",
    "session_id": "b1e2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "merchant_id": "jade.ottu.dev",
    "payment": {"reference": "jade-oTTE45", "pg_code": "cs-direct"},
    "service": {"target": {"name": "cybersource"}},
    "labels": {
        "operation": "payment",
        "namespace": "cybersource",
        "direction": "outbound",
        "pg_result": "AUTHORIZED",
    },
    "http": {"request": {"method": "POST"}, "response": {"status_code": 201, "body": GATEWAY_BODY}},
    "url": {"full": "https://apitest.cybersource.com/pts/v2/payments/"},
}

FIXTURES = {
    "connect_boundary_line": (CONNECT_LINE, ("default",)),
    "connect_line_with_a_token": (
        {
            **CONNECT_LINE,
            "http": {
                "request": {"method": "POST"},
                "response": {
                    "status_code": 201,
                    "body": GATEWAY_BODY.replace('{"id"', '{"access_token":"abc123def456","id"', 1),
                },
            },
        },
        ("default",),
    ),
    "ottu_pg_card_line": (
        {
            "event": "pg.request_sent to MPGS",
            "session_id": "b1e2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "payload": {
                "sourceOfFunds": {
                    "provided": {
                        "card": {
                            "number": "4111111111111111",
                            "expiry": {"month": "01", "year": "27"},
                            "securityCode": "123",
                        }
                    }
                },
                "order": {"reference": "deltabRKJ5X_0", "amount": 20},
                "customer": {"email": "payer@example.com", "firstName": "Jane"},
            },
            "message_text": "card 4111 1111 1111 1111 cvv 123 for payer@example.com",
        },
        ("default", "pci", "financial_ids"),
    ),
}


def _forget_clean_strings():
    """Every call must see its strings for the first time, as a real gateway
    body is: otherwise the clean-string cache answers from the previous call."""
    try:
        from ecsctx.masking import patterns
    except ImportError:
        return lambda: None
    clean = getattr(patterns, "_clean", None)
    return clean.clear if clean is not None else (lambda: None)


def _measure(mask, event, number=2000, repeat=7):
    forget = _forget_clean_strings()

    def baseline():
        forget()
        copy.deepcopy(event)

    def call():
        forget()
        mask(None, "info", copy.deepcopy(event))

    copy_cost = min(timeit.repeat(baseline, number=number, repeat=repeat))
    total = min(timeit.repeat(call, number=number, repeat=repeat))
    return (total - copy_cost) / number * 1e6


def _full_record(mask_sensitive_data, filter_class):
    """What get_logging_config() does per structlog record: the handler's
    filter masks record.msg in place, then the formatter's processor masks the
    event again. Before 0.7.0 there was no filter, so the processor alone."""
    if filter_class is None:
        return mask_sensitive_data
    masking_filter = filter_class()

    def run(_logger, method, event):
        record = logging.LogRecord("bench", logging.INFO, __file__, 0, event, None, None)
        masking_filter.filter(record)
        return mask_sensitive_data(_logger, method, record.msg)

    return run


def run_here() -> dict[str, float]:
    from ecsctx.processors import mask_sensitive_data

    try:
        from ecsctx.masking.config import configure_masking_packs
    except ImportError:  # a tag from before packs existed
        configure_masking_packs = None
    try:
        from ecsctx.masking.filters import MaskPIIFilter
    except ImportError:  # before 0.7.0
        MaskPIIFilter = None

    full = _full_record(mask_sensitive_data, MaskPIIFilter)
    results = {}
    for name, (event, packs) in FIXTURES.items():
        if configure_masking_packs is not None:
            configure_masking_packs(packs)
        results[name] = _measure(mask_sensitive_data, event)
        results[f"{name} (full record)"] = _measure(full, event)
    return results


class _GitTagFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Import ecsctx from a git tag without checking it out."""

    def __init__(self, tag: str):
        self.tag = tag

    def _source(self, path):
        done = subprocess.run(
            ["git", "show", f"{self.tag}:{path}"], capture_output=True, text=True, check=False
        )
        return done.stdout if done.returncode == 0 else None

    def find_spec(self, name, path, target=None):
        if name != "ecsctx" and not name.startswith("ecsctx."):
            return None
        base = name.replace(".", "/")
        for candidate, is_package in ((f"{base}/__init__.py", True), (f"{base}.py", False)):
            source = self._source(candidate)
            if source is not None:
                spec = importlib.util.spec_from_loader(name, self, is_package=is_package)
                spec.origin = candidate
                spec.loader_state = source
                if is_package:
                    spec.submodule_search_locations = []
                return spec
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        spec = module.__spec__
        # Source from this repository's own git history, not external input.
        exec(compile(spec.loader_state, spec.origin, "exec"), module.__dict__)  # noqa: S102


def run_tag(tag: str) -> dict[str, float]:
    done = subprocess.run(
        [sys.executable, __file__, "--json-for-tag", tag],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "DJANGO_SETTINGS_MODULE": ""},
    )
    if done.returncode != 0:
        raise SystemExit(done.stderr)
    return json.loads(done.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--compare", nargs="*", default=[], metavar="TAG")
    parser.add_argument("--json-for-tag", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.json_for_tag:
        sys.meta_path.insert(0, _GitTagFinder(args.json_for_tag))
        print(json.dumps(run_here()))
        return

    columns = {tag: run_tag(tag) for tag in args.compare}
    columns["this checkout"] = run_here()
    rows = [row for name in FIXTURES for row in (name, f"{name} (full record)")]
    width = max(len(row) for row in rows)
    print(f"{'µs per call':<{width}}  " + "  ".join(f"{c:>14}" for c in columns))
    for row in rows:
        print(f"{row:<{width}}  " + "  ".join(f"{columns[c][row]:>14.1f}" for c in columns))


if __name__ == "__main__":
    main()
