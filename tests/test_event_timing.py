"""Timing events (#159492).

`event.duration` is on 0.0% of application logs in production — all 1,150,892
documents carrying it are nginx's — because the library shipped no timer and
services computed the elapsed time only to discard it.
"""

import time

import pytest

from ecsctx.events import EventSpec, Timer, emit_pair, registry, timed

SENT = EventSpec(action="pg.request_sent", category=("network",), type=("connection",))
GOT = EventSpec(
    action="pg.response_received",
    terminal=True,
    category=("network",),
    type=("connection",),
)


@pytest.fixture(autouse=True)
def _clean():
    registry.reset()
    yield
    registry.reset()


class Recorder:
    def __init__(self):
        self.calls = []

    def __getattr__(self, level):
        def record(message, *args, **kwargs):
            self.calls.append((level, message, args, kwargs))

        return record


def ecs(call):
    return call[3]["ecs_event"]


class TestTimer:
    def test_it_measures_elapsed_time(self):
        with timed() as t:
            time.sleep(0.01)
        assert t.ns >= 10_000_000
        assert t.ms >= 10

    def test_ns_and_ms_describe_the_same_interval(self):
        # The unit confusion this module exists to prevent: a millisecond value
        # in event.duration indexes cleanly and misreports by 10^6.
        with timed() as t:
            time.sleep(0.005)
        assert t.ms == pytest.approx(t.ns / 1_000_000)

    def test_it_stops_when_the_block_ends(self):
        with timed() as t:
            pass
        first = t.ns
        time.sleep(0.005)
        assert t.ns == first

    def test_it_still_reports_when_the_block_raises(self):
        # A failure path's duration is usually the more interesting of the two.
        timer = None
        with pytest.raises(RuntimeError), timed() as t:
            timer = t
            time.sleep(0.005)
            raise RuntimeError("boom")
        assert timer.ns >= 5_000_000

    def test_it_reads_live_while_the_block_runs(self):
        with timed() as t:
            time.sleep(0.005)
            during = t.ns
            time.sleep(0.005)
            assert t.ns > during

    def test_it_uses_a_monotonic_clock(self):
        # A wall-clock adjustment mid-request would otherwise be able to produce
        # a negative duration, which EventSpec.ecs() rejects outright.
        t = Timer()
        assert t.ns >= 0


class TestEmitPair:
    def test_it_emits_both_events(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call", pg_code="mpgs"):
            pass
        assert [ecs(c)["action"] for c in log.calls] == [
            "pg.request_sent",
            "pg.response_received",
        ]

    def test_the_reply_carries_the_duration_in_nanoseconds(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call"):
            time.sleep(0.01)
        assert ecs(log.calls[1])["duration"] >= 10_000_000

    def test_the_request_carries_no_duration(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call"):
            pass
        assert "duration" not in ecs(log.calls[0])

    def test_success_is_inferred_when_the_block_completes(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call"):
            pass
        assert ecs(log.calls[1])["outcome"] == "success"

    def test_failure_is_inferred_when_the_block_raises(self):
        log = Recorder()
        with pytest.raises(RuntimeError), emit_pair(log, SENT, GOT, "Gateway call"):
            raise RuntimeError("boom")
        assert ecs(log.calls[1])["outcome"] == "failure"

    def test_the_exception_still_propagates(self):
        log = Recorder()
        with (
            pytest.raises(RuntimeError, match="boom"),
            emit_pair(log, SENT, GOT, "Gateway call"),
        ):
            raise RuntimeError("boom")

    def test_a_failure_attaches_exc_info_so_the_traceback_survives(self):
        # Without this the reply says only that it failed quickly, and the
        # traceback never reaches error.*.
        log = Recorder()
        with pytest.raises(RuntimeError), emit_pair(log, SENT, GOT, "Gateway call"):
            raise RuntimeError("boom")
        assert log.calls[1][3]["exc_info"] is True

    def test_a_failure_is_logged_at_the_failure_level(self):
        log = Recorder()
        with pytest.raises(RuntimeError), emit_pair(log, SENT, GOT, "Gateway call"):
            raise RuntimeError("boom")
        assert log.calls[1][0] == "error"

    def test_the_block_can_override_the_outcome(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call") as call:
            call.outcome = "failure"
            call.reason = "declined"
        assert ecs(log.calls[1])["outcome"] == "failure"
        assert ecs(log.calls[1])["reason"] == "declined"

    def test_fields_added_by_the_block_reach_only_the_reply(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call", pg_code="mpgs") as call:
            call.set(status_code=201)
        assert "http" not in log.calls[0][3]
        assert log.calls[1][3]["http"] == {"response": {"status_code": 201}}

    def test_opening_fields_reach_both(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call", pg_code="mpgs"):
            pass
        for c in log.calls:
            assert c[3]["payment"] == {"pg_code": "mpgs"}

    def test_the_block_sees_the_live_timer(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call") as call:
            time.sleep(0.005)
            assert call.ms >= 5
            assert call.ns >= 5_000_000

    def test_one_message_serves_both_because_the_action_distinguishes_them(self):
        # Making event.action authoritative rather than the prose is the point
        # of the vocabulary; the message is garnish.
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Gateway call"):
            pass
        assert [c[1] for c in log.calls] == ["Gateway call", "Gateway call"]

    def test_lazy_format_args_survive_to_both_lines(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "Calling %s", "mpgs"):
            pass
        assert [c[2] for c in log.calls] == [("mpgs",), ("mpgs",)]


class TestReservedFields:
    """emit_pair passes outcome/reason/duration_ns/exc_info to the closing
    event itself, so a field of the same name used to arrive twice and raise
    TypeError from inside the except handler.

    Every assertion here matches on "cannot be passed as" rather than on the
    field name alone. The *bug*'s message — "got multiple values for keyword
    argument 'outcome'" — also contains the field name, so matching that would
    pass against the unfixed code and pin nothing.
    """

    GUARD = "cannot be passed as"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("outcome", "success"),
            ("reason", "declined"),
            ("duration_ns", 1),
            ("level", "warning"),
        ],
    )
    def test_an_opening_field_that_clashes_is_rejected_before_anything_is_logged(
        self, field, value
    ):
        # Rejected at the call, not at block exit: without the guard the
        # opening event is emitted first and the collision surfaces on the way
        # out, so a half-logged pair reaches the index.
        log = Recorder()
        with (
            pytest.raises(TypeError, match=self.GUARD),
            emit_pair(log, SENT, GOT, "msg", **{field: value}),
        ):
            pass
        assert log.calls == []

    @pytest.mark.parametrize("field", ["outcome", "reason", "duration_ns", "exc_info"])
    def test_call_set_rejects_the_same_names(self, field):
        # Easy to reach for by mistake: Call exposes .reason as an attribute,
        # so call.set(reason=...) reads like it should work.
        log = Recorder()
        with (
            pytest.raises(TypeError, match=self.GUARD),
            emit_pair(log, SENT, GOT, "msg") as call,
        ):
            call.set(**{field: "x"})

    def test_the_error_names_the_mechanism_that_does_work(self):
        log = Recorder()
        with (
            pytest.raises(TypeError, match=r"call\.outcome"),
            emit_pair(log, SENT, GOT, "msg") as call,
        ):
            call.set(outcome="failure")

    def test_a_real_failure_is_not_masked_by_a_kwargs_error(self):
        # The serious form. Without the guard, call.set(reason=...) collided
        # inside the except handler, so a gateway timeout reached the caller as
        # a TypeError about keyword arguments and the real exception was
        # demoted to __context__.
        log = Recorder()
        with (
            pytest.raises(TypeError, match=self.GUARD),
            emit_pair(log, SENT, GOT, "msg") as call,
        ):
            call.set(reason="timeout")
            raise RuntimeError("THE REAL FAILURE")

    def test_the_attribute_override_still_reaches_the_closing_event(self):
        log = Recorder()
        with (
            pytest.raises(RuntimeError, match="THE REAL FAILURE"),
            emit_pair(log, SENT, GOT, "msg") as call,
        ):
            call.outcome = "failure"
            call.reason = "timeout"
            raise RuntimeError("THE REAL FAILURE")
        assert ecs(log.calls[1])["outcome"] == "failure"
        assert ecs(log.calls[1])["reason"] == "timeout"

    def test_ordinary_fields_are_unaffected(self):
        log = Recorder()
        with emit_pair(log, SENT, GOT, "msg", pg_code="mpgs") as call:
            call.set(status_code=200)
        assert log.calls[1][3]["http"] == {"response": {"status_code": 200}}


class TestControlKwargs:
    def test_exc_info_reaches_the_logger_rather_than_becoming_a_label(self):
        # It used to route like any other unknown scalar, so exc_info=True
        # became labels.exc_info: true and the traceback was simply lost.
        from ecsctx.events import emit

        log = Recorder()
        emit(log, GOT, "boom", outcome="failure", exc_info=True, status_code=500)
        kwargs = log.calls[0][3]
        assert kwargs["exc_info"] is True
        assert "labels" not in kwargs
        assert kwargs["http"] == {"response": {"status_code": 500}}

    @pytest.mark.parametrize("name", ["exc_info", "stack_info", "stacklevel"])
    def test_every_logging_control_kwarg_passes_through(self, name):
        from ecsctx.events import emit

        log = Recorder()
        emit(log, SENT, "msg", **{name: 2})
        assert name in log.calls[0][3]
        assert "labels" not in log.calls[0][3]
