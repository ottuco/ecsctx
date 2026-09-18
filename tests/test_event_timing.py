"""Timing events (#159492).

`event.duration` is on 0.0% of application logs in production — all 1,150,892
documents carrying it are nginx's — because the library shipped no timer and
services computed the elapsed time only to discard it.
"""

import time

import pytest

from ecsctx.events import Timer, timed


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

