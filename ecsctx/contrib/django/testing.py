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
wrote. The sample tables come from ecsctx.masking.samples.

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
    "card_number": "[CARD-MASKED]",
    "customer_name": "[NAME-MASKED]",
    "cvv": "[CVV-MASKED]",
    "email": "[EMAIL-MASKED]",
    "phone": "[PHONE-MASKED]",
}

# The token depends on the project's keyset, so only the label is compared.
_TOKEN_SUFFIX = re.compile(r":ptok:v\d+:[^\]]+\]")


class MaskingCaptureError(AssertionError):
    """Raised when a project's handlers wrote nothing readable to check."""


def strip_tokens(value):
    """Drop the :ptok:v1:… part of every masked value, at any depth."""
    if isinstance(value, str):
        return _TOKEN_SUFFIX.sub("]", value)
    if isinstance(value, dict):
        return {key: strip_tokens(item) for key, item in value.items()}
    if isinstance(value, list):
        return [strip_tokens(item) for item in value]
    return value


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


_UNSET = object()


def _recording_emit(handler: logging.Handler, buffer: io.StringIO):
    def emit(record):
        buffer.write(handler.format(record) + "\n" + record.getMessage() + "\n")

    return emit


@contextmanager
def capture_all_handlers(logger_name: str = DEFAULT_LOGGER_NAME) -> Iterator[list[tuple[str, io.StringIO, bool]]]:
    """Read back every project handler a record on this logger reaches.

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
        is_stream = isinstance(handler, logging.StreamHandler)
        buffers.append((type(handler).__name__, buffer, is_stream))
        if is_stream:
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
def capture_project_handlers(logger_name: str = DEFAULT_LOGGER_NAME) -> Iterator[list[io.StringIO]]:
    """The project's stream handlers' buffers for the duration of the block.

    Every other handler on the route is silenced meanwhile, so a test record
    logged at a raised level never reaches a real email or HTTP endpoint.
    """
    with capture_all_handlers(logger_name) as captured:
        yield [buffer for _name, buffer, is_stream in captured if is_stream]


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
    return [(name, buffer.getvalue()) for name, buffer, _is_stream in buffers]


def project_routes(logging_config: dict | None = None) -> list[str]:
    """One logger name per route the project configures.

    An unconfigured name stands in for root; every logger in
    LOGGING["loggers"] is its own route, since it may have handlers or
    propagate: False of its own.
    """
    if logging_config is None:
        from django.conf import settings

        logging_config = settings.LOGGING
    return [DEFAULT_LOGGER_NAME, *(logging_config or {}).get("loggers", {})]


def route_level(logger_name: str, minimum: int = logging.WARNING) -> int:
    """The lowest level that every project handler on this route accepts."""
    logger = logging.getLogger(logger_name)
    levels = [minimum, logger.getEffectiveLevel()]
    levels += [h.level for h in _handlers_reached_by(logger) if _is_project_handler(h)]
    return max(levels)


def _has_stream_handler(logger_name: str) -> bool:
    return any(
        isinstance(h, logging.StreamHandler) and _is_project_handler(h)
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
    )


def _parse(outputs: list[str], *, logger_name: str, level: int) -> list[dict]:
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
        if len(parsed) != 1:
            raise MaskingCaptureError(f"Expected exactly one record per handler, got:\n{output}")
        records.append(parsed[0])
    return records


def masked_outputs(sample, **kwargs) -> list:
    """Run one sample through the project's logging and return what each handler emitted.

    A string sample is logged as the message; anything else is logged as a
    single kwarg. Tokens are stripped, so results compare against bare labels.
    """
    if isinstance(sample, str):
        records = capture_log(sample, **kwargs)
        return [strip_tokens(record.get("message")) for record in records]
    records = capture_log(sample=sample, **kwargs)
    return [strip_tokens(record.get("extra", {}).get("sample")) for record in records]


def count_maskers(handler: logging.Handler) -> int:
    from ecsctx.masking.filters import MaskPIIFilter

    return sum(isinstance(f, MaskPIIFilter) for f in handler.filters)


class MaskingTestsMixin:
    masking_logger_name = DEFAULT_LOGGER_NAME
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
        return [
            (name, route_level(name, self.masking_log_level))
            for name in names
            if not logging.getLogger(name).disabled
        ]

    def readable_routes(self) -> list[tuple[str, int]]:
        """Routes with a stream handler whose output can be parsed as JSON."""
        routes = [(name, level) for name, level in self.masking_routes() if _has_stream_handler(name)]
        self.assertTrue(routes, "No route reaches a project stream handler, so no output can be read back.")
        return routes

    # -- the project's configuration -------------------------------------

    def test_logging_config_passes_masking_check(self):
        from django.conf import settings

        from ecsctx.contrib.django.checks import assert_no_masking_errors

        assert_no_masking_errors(settings.LOGGING, ignore_pytest_handlers=True)

    def test_masking_check_is_registered(self):
        from django.core.checks import Tags, registry

        checks = [c for c in registry.registry.get_checks() if getattr(c, "__name__", "") == "check_masking_configured"]
        self.assertEqual(
            len(checks),
            1,
            "ecsctx's masking system check is not registered — the project never imported "
            "ecsctx.contrib.django (normally its MIDDLEWARE entry does that).",
        )
        self.assertIn(Tags.security, checks[0].tags)

    def test_masking_check_is_not_silenced(self):
        from ecsctx.contrib.django.checks import masking_check_skip_reason

        reason = masking_check_skip_reason()
        self.assertIsNone(
            reason,
            f"The masking system check silences itself here, because {reason}. A masking gap "
            "would not fail the boot.",
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
                for record in capture_log(logger_name=name, level=level, **self.masking_test_values):
                    fields = {**record, **record.get("extra", {})}
                    actual = {field: strip_tokens(fields.get(field)) for field in self.masking_expected_values}
                    self.assertEqual(actual, self.masking_expected_values, f"Log record:\n{record}")

    def test_stdlib_log_with_percent_args_is_masked(self):
        """The path a third-party library takes: no structlog, %s args the
        handler interpolates. Only the handler-level filter can catch it."""
        email = self.masking_test_values["email"]
        for name, level in self.readable_routes():
            with self.subTest(logger=name):
                for record in capture_stdlib_log("third party %s signed in", email, logger_name=name, level=level):
                    self.assertEqual(strip_tokens(record.get("message")), "third party [EMAIL-MASKED] signed in")

    def test_no_raw_value_reaches_any_handler(self):
        """Every project handler on every route — email, HTTP, syslog included —
        is read back and searched for the raw test values, whatever its format."""
        # Short values like a CVV can turn up inside a timestamp by chance.
        raw_values = {f: str(v) for f, v in self.masking_test_values.items() if len(str(v)) >= 8}
        reached = 0
        for name, level in self.masking_routes():
            for handler, text in capture_handler_texts(logger_name=name, level=level, **self.masking_test_values):
                reached += 1
                with self.subTest(logger=name, handler=handler):
                    leaked = [field for field, raw in raw_values.items() if raw in text]
                    self.assertEqual(leaked, [], f"Raw values reached {handler}:\n{text}")
        self.assertGreater(reached, 0, "No project handler was reached on any route.")

    def assert_samples_masked(self, cases):
        for label, sample, expected in cases:
            with self.subTest(case=label):
                for actual in masked_outputs(
                    sample, logger_name=self.masking_logger_name, level=self.masking_log_level
                ):
                    self.assertEqual(actual, expected)

    def assert_samples_unchanged(self, cases):
        self.assert_samples_masked([(label, sample, sample) for label, sample in cases])

    def test_masks_pem_key_blocks(self):
        self.assert_samples_masked(samples.PEM_CASES)

    def test_masks_credential_keywords(self):
        self.assert_samples_masked(samples.CREDENTIAL_CASES)

    def test_masks_cvv(self):
        self.assert_samples_masked(samples.CVV_CASES)

    def test_masks_payment_ids(self):
        self.assert_samples_masked(samples.PAYMENT_ID_CASES)

    def test_masks_ibans(self):
        self.assert_samples_masked(samples.IBAN_CASES)

    def test_masks_phone_numbers(self):
        self.assert_samples_masked(samples.PHONE_CASES)

    def test_masks_emails(self):
        self.assert_samples_masked(samples.EMAIL_CASES)

    def test_masks_jwts(self):
        self.assert_samples_masked(samples.JWT_CASES)

    def test_masks_card_numbers(self):
        self.assert_samples_masked(samples.CARD_CASES)

    def test_masks_ssns(self):
        self.assert_samples_masked(samples.SSN_CASES)

    def test_masks_sensitive_dict_keys(self):
        self.assert_samples_masked(samples.DICT_KEY_CASES)

    def test_masks_objects_and_leaves_primitives(self):
        self.assert_samples_masked(samples.OBJECT_AND_PRIMITIVE_CASES)

    def test_does_not_over_mask(self):
        self.assert_samples_unchanged(samples.NOT_MASKED_CASES)

    def test_accepted_leaks_are_unchanged(self):
        self.assert_samples_unchanged(samples.ACCEPTED_LEAK_CASES)
