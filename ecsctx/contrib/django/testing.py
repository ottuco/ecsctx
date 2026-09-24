"""Pluggable masking tests for a project's own test suite.

Mix MaskingTestsMixin into any TestCase in your project and you inherit the
whole suite — no test code to write:

    from django.test import SimpleTestCase
    from ecsctx.contrib.django.testing import MaskingTestsMixin

    class TestLogMasking(MaskingTestsMixin, SimpleTestCase):
        pass

Every test runs against the project's real, booted logging setup. Nothing is
reconfigured: each log call goes through structlog into the project's own
handlers, filters and formatter, and the test reads back what those handlers
wrote. The sample tables come from ecsctx.masking.samples, and each case is
checked against the engine alone as well, so a failure says whether a masking
rule or the project's logging setup is at fault. A case that needs an opt-in
masking pack (pci, financial_ids) is skipped unless the project turns that
pack on.

The helpers below are usable on their own, for a project that would rather
write its own assertions than inherit these.

It is a mixin rather than a TestCase subclass because test runners collect any
TestCase they find in a module, so an imported base class would run as a test
of its own.
"""

from __future__ import annotations

import io
import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

import structlog

from ecsctx.masking import samples

EVENT = "ecsctx_masking_check"
DEFAULT_LOGGER_NAME = "ecsctx.masking_check"

TEST_VALUES = {
    "api_token": "tok_leakcheck_9f8e7d6c5b4a3210",
    "card_number": "4111111111111111",
    "customer_name": "Leakcheck Testperson",
    "cvv": "7391",
    "email": "leak.check@example.com",
    "phone": "+96550012345",
}

EXPECTED_VALUES = {
    "api_token": "[SECRET-MASKED]",
    "card_number": "[CARD-MASKED:411111******1111]",
    "customer_name": "[NAME-MASKED]",
    "cvv": "[CVV-MASKED]",
    "email": "[EMAIL-MASKED]",
    "phone": "[PHONE-MASKED]",
}

# A project with PII tokenization logs a tokenizable value as a bare token
# (ptok:v1:…) instead of its [LABEL]; the token depends on its keyset.
_BARE_TOKEN = re.compile(r"ptok:v\d+:[A-Za-z0-9_-]+")
_TOKEN = "<token>"


class MaskingCaptureError(AssertionError):
    """Raised when a project's handlers wrote nothing readable to check."""


@lru_cache(maxsize=1)
def _tokenizable_labels() -> tuple[str, ...]:
    from ecsctx.masking.fields_rules import FIELD_RULES
    from ecsctx.masking.tokens import make_label

    return tuple(
        f"[{make_label(rule.field_type)}]"
        for rule in FIELD_RULES.values()
        if rule.tokenizable
    )


def as_logged(value):
    """value with every bare token and every tokenizable [LABEL] replaced by
    one placeholder, at any depth."""
    if isinstance(value, str):
        value = _BARE_TOKEN.sub(_TOKEN, value)
        for label in _tokenizable_labels():
            value = value.replace(label, _TOKEN)
        return value
    if isinstance(value, dict):
        return {key: as_logged(item) for key, item in value.items()}
    if isinstance(value, list):
        return [as_logged(item) for item in value]
    return value


def comparable(actual, expected):
    """(actual, expected) ready for an exact comparison.

    Unchanged without PII tokenization. With it, tokens and tokenizable labels
    are folded together, so a case written with labels matches what the
    project logs; non-tokenized labels (card, CVV, expiry) still compare as-is.
    """
    from ecsctx.pii import is_configured

    if is_configured():
        return as_logged(actual), as_logged(expected)
    return actual, expected


def _handlers_reached_by(logger: logging.Logger) -> Iterator[logging.Handler]:
    """Every handler a record on this logger reaches, as Logger.callHandlers walks them.

    A handler shared by two loggers on the route is yielded once, so a swap
    made on it is undone exactly once.
    """
    seen: set[int] = set()
    current: logging.Logger | None = logger
    while current is not None:
        for handler in current.handlers:
            if id(handler) not in seen:
                seen.add(id(handler))
                yield handler
        if not current.propagate:
            break
        current = current.parent


def _is_project_handler(handler: logging.Handler) -> bool:
    """pytest's capture handler belongs to the runner, not the project."""
    return not type(handler).__module__.startswith("_pytest")


def _is_ecs_json_handler(handler: logging.Handler) -> bool:
    """A stream handler whose formatter ends in ecsctx's ECSFormatter, so each line is one ECS JSON document."""
    from ecsctx.formatters import ECSFormatter

    formatter = handler.formatter
    return (
        isinstance(handler, logging.StreamHandler)
        and isinstance(formatter, structlog.stdlib.ProcessorFormatter)
        and any(
            isinstance(p, ECSFormatter) for p in getattr(formatter, "processors", ())
        )
    )


_UNSET = object()


def _recording_emit(handler: logging.Handler, buffer: io.StringIO):
    def emit(record):
        buffer.write(handler.format(record) + "\n" + record.getMessage() + "\n")

    return emit


@contextmanager
def capture_all_handlers(
    logger_name: str = DEFAULT_LOGGER_NAME,
) -> Iterator[list[tuple[str, io.StringIO, bool]]]:
    """Read back every project handler a record on this logger reaches.

    Yields (handler class, buffer, is ecsctx JSON) per handler.

    Stream handlers write to a buffer instead of their stream. Every other
    handler — email, HTTP, syslog, queue — has its emit() swapped for one that
    records handler.format(record) and sends nothing: its filters still run
    first, and the fake test values never leave the process.
    """
    buffers: list[tuple[str, io.StringIO, bool]] = []
    swapped_streams: list[tuple[logging.StreamHandler, object]] = []
    swapped_emits: list[tuple[logging.Handler, object]] = []
    for handler in _handlers_reached_by(logging.getLogger(logger_name)):
        if not _is_project_handler(handler):
            continue
        buffer = io.StringIO()
        buffers.append((type(handler).__name__, buffer, _is_ecs_json_handler(handler)))
        if isinstance(handler, logging.StreamHandler):
            swapped_streams.append((handler, handler.setStream(buffer)))
        else:
            swapped_emits.append((handler, handler.__dict__.get("emit", _UNSET)))
            handler.emit = _recording_emit(handler, buffer)
    try:
        yield buffers
    finally:
        for handler, original in swapped_streams:
            handler.setStream(original)
        for handler, original in swapped_emits:
            if original is _UNSET:
                del handler.emit
            else:
                handler.emit = original


@contextmanager
def capture_project_handlers(
    logger_name: str = DEFAULT_LOGGER_NAME,
) -> Iterator[list[io.StringIO]]:
    """Buffers of the route's stream handlers that write ecsctx JSON.

    Every other handler on the route is silenced meanwhile, so a test record
    logged at a raised level never reaches a real email or HTTP endpoint.
    Handlers in other formats are only covered by the leak check.
    """
    with capture_all_handlers(logger_name) as captured:
        yield [buffer for _name, buffer, is_json in captured if is_json]


def capture_handler_texts(
    message: str = EVENT,
    *,
    logger_name: str = DEFAULT_LOGGER_NAME,
    level: int = logging.WARNING,
    **kwargs,
) -> list[tuple[str, str]]:
    """Log one record through structlog; return (handler class, text) for every project handler it reached."""
    with capture_all_handlers(logger_name) as buffers:
        structlog.get_logger(logger_name).log(level, message, **kwargs)
    return [(name, buffer.getvalue()) for name, buffer, _is_json in buffers]


def project_routes(logging_config: dict | None = None) -> list[str]:
    """One logger name per route a record can take in this process.

    An unconfigured name stands in for root. Every logger in
    LOGGING["loggers"] is its own route, since it may have handlers or
    propagate: False of its own. So is every live logger carrying handlers of
    its own that LOGGING never mentions — Django's DEFAULT_LOGGING pass and
    packages that attach a handler on import put those there. A logger with no
    handlers of its own only hands records to a route already listed.
    """
    if logging_config is None:
        from django.conf import settings

        logging_config = settings.LOGGING
    names = [DEFAULT_LOGGER_NAME, *(logging_config or {}).get("loggers", {})]
    for name, logger in sorted(logging.Logger.manager.loggerDict.items()):
        if (
            name not in names
            and isinstance(logger, logging.Logger)
            and any(_is_project_handler(h) for h in logger.handlers)
        ):
            names.append(name)
    return names


def route_level(logger_name: str, minimum: int = logging.WARNING) -> int:
    """The lowest level that every project handler on this route accepts."""
    logger = logging.getLogger(logger_name)
    levels = [minimum, logger.getEffectiveLevel()]
    levels += [h.level for h in _handlers_reached_by(logger) if _is_project_handler(h)]
    return max(levels)


def _route_accepts(logger_name: str, level: int) -> bool:
    """Whether the route's logger passes a record on to handlers at all.

    Logger.handle() checks only the logger's own filters and disabled flag
    before calling any handler, so a throwaway record gets the same verdict a
    real one would. Sentry's sentry_sdk.errors, for one, drops everything
    unless Sentry debug mode is on — nothing on such a route ever reaches a
    handler, so there is nothing there to read or to leak.
    """
    logger = logging.getLogger(logger_name)
    probe = logger.makeRecord(logger_name, level, __file__, 0, EVENT, (), None)
    return not logger.disabled and bool(logger.filter(probe))


def _has_json_handler(logger_name: str) -> bool:
    return any(
        _is_ecs_json_handler(h) and _is_project_handler(h)
        for h in _handlers_reached_by(logging.getLogger(logger_name))
    )


def capture_log(
    message: str = EVENT,
    *,
    logger_name: str = DEFAULT_LOGGER_NAME,
    level: int = logging.WARNING,
    **kwargs,
) -> list[dict]:
    """Log one record through the project's handlers; return each handler's parsed output."""
    log = structlog.get_logger(logger_name)
    with capture_project_handlers(logger_name) as buffers:
        log.log(level, message, **kwargs)
    return _parse(
        [buffer.getvalue() for buffer in buffers if buffer.getvalue()],
        logger_name=logger_name,
        level=level,
        origin="capture_log",
    )


def capture_stdlib_log(
    message: str,
    *args,
    logger_name: str = DEFAULT_LOGGER_NAME,
    level: int = logging.WARNING,
) -> list[dict]:
    """Same as capture_log(), but emitted through plain stdlib logging.

    This is the path a third-party library takes — no structlog, %s args left
    for the handler to interpolate.
    """
    with capture_project_handlers(logger_name) as buffers:
        logging.getLogger(logger_name).log(level, message, *args)
    return _parse(
        [buffer.getvalue() for buffer in buffers if buffer.getvalue()],
        logger_name=logger_name,
        level=level,
        origin="capture_stdlib_log",
    )


def _parse(outputs: list[str], *, logger_name: str, level: int, origin: str) -> list[dict]:
    """Each handler's record for the one call made from origin().

    Selected by where it was logged from, since anything else logging at the
    same moment — a one-time warning, another thread — lands in the same buffer.
    """
    if not outputs:
        raise MaskingCaptureError(
            f"No project stream handler wrote anything for logger {logger_name!r} at level "
            f"{logging.getLevelName(level)}. Check that setup_logging() ran and that the level "
            "isn't filtered out, or set masking_log_level."
        )

    records = []
    for output in outputs:
        lines = [line for line in output.splitlines() if line.strip()]
        try:
            parsed = [json.loads(line) for line in lines]
        except ValueError:
            raise MaskingCaptureError(
                "A project handler wrote output that isn't ecsctx's JSON, so it can't be "
                f"compared field by field:\n{output}"
            ) from None
        ours = [
            record
            for record in parsed
            if record.get("log", {}).get("origin", {}).get("function") == origin
        ]
        if len(ours) != 1:
            raise MaskingCaptureError(
                f"Expected exactly one record logged from {origin}() per handler, got:\n{output}"
            )
        records.append(ours[0])
    return records


def masked_outputs(sample, **kwargs) -> list:
    """Run one sample through the project's logging and return what each handler emitted.

    A string sample is logged as the message; anything else is logged as a
    single kwarg. Values come back exactly as logged — see comparable().
    """
    if isinstance(sample, str):
        records = capture_log(sample, **kwargs)
        return [record.get("message") for record in records]
    records = capture_log(sample=sample, **kwargs)
    return [record.get("extra", {}).get("sample") for record in records]


def masked_directly(sample, *args):
    """One sample masked by the engine alone, with the project's packs.

    No logger, no handler, no formatter: the value goes on a record and
    MaskPIIFilter masks it, so a case is checked against the engine as well as
    against what the project's handlers write. With %-style args, the
    interpolated message comes back, as a handler would write it.
    """
    from ecsctx.masking.filters import MaskPIIFilter

    record = logging.LogRecord(EVENT, logging.WARNING, __file__, 0, sample, args or None, None)
    MaskPIIFilter().filter(record)
    return record.getMessage() if args else record.msg


def count_maskers(handler: logging.Handler) -> int:
    from ecsctx.masking.filters import MaskPIIFilter

    return sum(isinstance(f, MaskPIIFilter) for f in handler.filters)


class MaskingTestsMixin:
    masking_logger_names: list[str] | None = None
    masking_log_level = logging.WARNING
    masking_test_values = TEST_VALUES
    masking_expected_values = EXPECTED_VALUES

    def masking_routes(self) -> list[tuple[str, int]]:
        """(logger name, level) for every route: masking_logger_names if set,
        otherwise root plus every logger in settings.LOGGING["loggers"]."""
        names = self.masking_logger_names
        if names is None:
            names = project_routes()
        routes = [(name, route_level(name, self.masking_log_level)) for name in names]
        return [(name, level) for name, level in routes if _route_accepts(name, level)]

    def readable_routes(self) -> list[tuple[str, int]]:
        """Routes reaching a handler that writes ecsctx JSON, so its output can be compared field by field."""
        routes = [
            (name, level)
            for name, level in self.masking_routes()
            if _has_json_handler(name)
        ]
        self.assertTrue(
            routes,
            "No route reaches a stream handler using ecsctx's JSON formatter, so no output can be compared.",
        )
        return routes

    # -- the project's configuration -------------------------------------

    def test_logging_config_passes_masking_check(self):
        from django.conf import settings

        from ecsctx.contrib.django.checks import assert_no_masking_errors

        assert_no_masking_errors(settings.LOGGING, ignore_pytest_handlers=True)

    def test_masking_check_is_registered(self):
        from django.core.checks import Tags, registry

        checks = [
            c
            for c in registry.registry.get_checks()
            if getattr(c, "__name__", "") == "check_masking_configured"
        ]
        self.assertEqual(
            len(checks),
            1,
            "ecsctx's masking system check is not registered — the project never imported "
            "ecsctx.contrib.django (normally its MIDDLEWARE entry does that).",
        )
        self.assertIn(Tags.security, checks[0].tags)

    def test_masking_check_is_not_switched_off(self):
        from django.conf import settings

        self.assertFalse(
            getattr(settings, "ECSCTX_SKIP_MASKING_CHECK", False),
            "ECSCTX_SKIP_MASKING_CHECK switches the masking system check off in every "
            "environment, production included.",
        )

    def test_structural_metadata_is_not_masked(self):
        for name, level in self.readable_routes():
            for record in capture_log(logger_name=name, level=level):
                for key in ("service", "project", "log"):
                    with self.subTest(logger=name, field=key):
                        self.assertNotIn("-MASKED", json.dumps(record.get(key, {})))

    def test_no_handler_carries_a_duplicate_masker(self):
        for name, _level in self.masking_routes():
            for handler in _handlers_reached_by(logging.getLogger(name)):
                if _is_project_handler(handler):
                    with self.subTest(logger=name, handler=type(handler).__name__):
                        self.assertLessEqual(count_maskers(handler), 1)

    # -- what the project's handlers actually write ----------------------

    def test_log_output_is_masked(self):
        for name, level in self.readable_routes():
            with self.subTest(logger=name):
                for record in capture_log(
                    logger_name=name, level=level, **self.masking_test_values
                ):
                    fields = {**record, **record.get("extra", {})}
                    actual = {
                        field: fields.get(field) for field in self.masking_expected_values
                    }
                    self.assertEqual(
                        *comparable(actual, self.masking_expected_values),
                        f"Log record:\n{record}",
                    )

    def test_stdlib_log_with_percent_args_is_masked(self):
        """The path a third-party library takes: no structlog, %s args the
        handler interpolates. Only the handler-level filter can catch it."""
        email = self.masking_test_values["email"]
        for name, level in self.readable_routes():
            with self.subTest(logger=name):
                for record in capture_stdlib_log(
                    "third party %s signed in", email, logger_name=name, level=level
                ):
                    self.assertEqual(
                        *comparable(
                            record.get("message"), "third party [EMAIL-MASKED] signed in"
                        )
                    )

    def test_no_raw_value_reaches_any_handler(self):
        """Every project handler on every route — email, HTTP, syslog included —
        is read back and searched for the raw test values, whatever its format."""
        # Short values like a CVV can turn up inside a timestamp by chance.
        raw_values = {
            f: str(v) for f, v in self.masking_test_values.items() if len(str(v)) >= 8
        }
        reached = 0
        for name, level in self.masking_routes():
            for handler, text in capture_handler_texts(
                logger_name=name, level=level, **self.masking_test_values
            ):
                reached += 1
                with self.subTest(logger=name, handler=handler):
                    leaked = [field for field, raw in raw_values.items() if raw in text]
                    self.assertEqual(
                        leaked, [], f"Raw values reached {handler}:\n{text}"
                    )
        self.assertGreater(reached, 0, "No project handler was reached on any route.")

    def skip_if_safe_key(self, keys):
        """Skip a case that needs key names this project listed as safe.

        One listed key is enough: its field then comes through unmasked, so
        the expected value cannot match. A case masked by a content rule names
        no key — a safe key's value is still scanned.
        """
        if not keys:
            return
        from ecsctx.masking.config import get_masking_safe_keys

        safe = get_masking_safe_keys()
        listed = [key for key in keys if str(key).lower() in safe]
        if listed:
            self.skipTest(
                f"the project lists {', '.join(repr(key) for key in listed)} "
                "in ECSCTX_MASK_SAFE_KEYS"
            )

    def assert_samples_masked(self, cases, *, group: str | None = None):
        """Check (label, sample, expected) cases twice.

        First against the engine alone (masked_directly), then through every
        readable route, so a case that only the logging path gets wrong — a
        missing filter, a formatter that reshapes the value — is told apart
        from a rule that is wrong in the engine itself.

        group names a table in ecsctx.masking.samples; a case needing a pack
        this project doesn't enable is skipped. A case may carry a fourth
        item, the key names it needs masked by name; it is skipped where the
        project lists one of them as a safe key.
        """
        from ecsctx.masking import get_masking_packs

        packs = get_masking_packs()

        def check(sample, keys=()):
            """Skip what this project's configuration puts out of reach."""
            if group is not None:
                pack = samples.case_pack(group, sample)
                if pack not in packs:
                    self.skipTest(f"needs the {pack!r} masking pack")
            self.skip_if_safe_key(keys)

        for case in cases:
            label, sample, expected = case[:3]
            with self.subTest(check="engine", case=label):
                check(sample, case[3] if len(case) > 3 else ())
                self.assertEqual(*comparable(masked_directly(sample), expected))

        for name, level in self.readable_routes():
            for case in cases:
                label, sample, expected = case[:3]
                with self.subTest(logger=name, case=label):
                    check(sample, case[3] if len(case) > 3 else ())
                    for actual in masked_outputs(sample, logger_name=name, level=level):
                        self.assertEqual(*comparable(actual, expected))

    def assert_samples_unchanged(self, cases):
        self.assert_samples_masked([(label, sample, sample) for label, sample in cases])

    def assert_stdlib_args_masked(self, cases):
        """Check (label, message, args, expected, pack) cases twice.

        The message is logged through plain stdlib logging, the path a
        third-party library takes: the handler interpolates the arguments, so
        only a filter on the handler can mask them. A sixth item names the
        keys the case needs masked by name, as above.
        """
        from ecsctx.masking import get_masking_packs

        packs = get_masking_packs()

        def check(pack, keys=()):
            if pack not in packs:
                self.skipTest(f"needs the {pack!r} masking pack")
            self.skip_if_safe_key(keys)

        for case in cases:
            label, message, args, expected, pack = case[:5]
            with self.subTest(check="engine", case=label):
                check(pack, case[5] if len(case) > 5 else ())
                self.assertEqual(*comparable(masked_directly(message, *args), expected))

        for name, level in self.readable_routes():
            for case in cases:
                label, message, args, expected, pack = case[:5]
                with self.subTest(logger=name, case=label):
                    check(pack, case[5] if len(case) > 5 else ())
                    for record in capture_stdlib_log(
                        message, *args, logger_name=name, level=level
                    ):
                        self.assertEqual(*comparable(record.get("message"), expected))

    def assert_samples_unchanged_without_pack(self, cases):
        """Check (label, sample, pack) cases: text the pack would mask, on a
        project that leaves the pack off, must come through untouched."""
        from ecsctx.masking import get_masking_packs

        packs = get_masking_packs()
        for label, sample, pack in cases:
            with self.subTest(check="engine", case=label):
                if pack in packs:
                    self.skipTest(f"the {pack!r} pack is on, so this rule applies")
                self.assertEqual(masked_directly(sample), sample)

        for name, level in self.readable_routes():
            for label, sample, pack in cases:
                with self.subTest(logger=name, case=label):
                    if pack in packs:
                        self.skipTest(f"the {pack!r} pack is on, so this rule applies")
                    for actual in masked_outputs(sample, logger_name=name, level=level):
                        self.assertEqual(actual, sample)

    def test_masks_pem_key_blocks(self):
        self.assert_samples_masked(samples.PEM_MASKED_CASES, group="pem")

    def test_masks_credential_keywords(self):
        self.assert_samples_masked(samples.CREDENTIAL_MASKED_CASES, group="credential")

    def test_masks_cvv(self):
        self.assert_samples_masked(samples.CVV_KEYWORD_CASES, group="cvv")

    def test_masks_payment_ids(self):
        self.assert_samples_masked(samples.PAYMENT_ID_QUOTE_CASES, group="payment_id")

    def test_masks_ibans(self):
        self.assert_samples_masked(samples.IBAN_MASKED_CASES, group="iban")

    def test_masks_phone_numbers(self):
        self.assert_samples_masked(samples.PHONE_MASKED_CASES, group="phone")

    def test_masks_emails(self):
        self.assert_samples_masked(samples.EMAIL_MASKED_CASES, group="email")

    def test_masks_jwts(self):
        self.assert_samples_masked(samples.JWT_MASKED_CASES, group="jwt")

    def test_masks_card_numbers(self):
        self.assert_samples_masked(samples.CARD_NUMBER_CASES, group="card")

    def test_masks_ssns(self):
        self.assert_samples_masked(samples.SSN_MASKED_CASES, group="ssn")

    def test_masks_sensitive_dict_keys(self):
        self.assert_samples_masked(samples.DICT_KEY_VALUE_MASKING_CASES, group="dict_key")

    def test_masks_objects_and_leaves_primitives(self):
        self.assert_samples_masked(samples.OBJECT_AND_PRIMITIVE_CASES, group="object_and_primitive")

    def test_masks_stdlib_args(self):
        self.assert_stdlib_args_masked(samples.STDLIB_ARGS_CASES)

    def test_opt_in_rules_stay_off_until_enabled(self):
        self.assert_samples_unchanged_without_pack(samples.WITHOUT_PACK_CASES)

    def test_does_not_over_mask(self):
        self.assert_samples_unchanged(samples.NOT_MASKED)

    def test_accepted_leaks_are_unchanged(self):
        self.assert_samples_unchanged(samples.ACCEPTED_LEAK_CASES)
