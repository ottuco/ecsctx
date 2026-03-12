"""Tests for LoggingContext field shape and labels support."""

from ecsctx.context import LoggingContext


class TestFieldShape:
    def test_pg_code_under_payment(self):
        ctx = LoggingContext(pg_code="knet")
        result = ctx.to_dict()
        assert result["payment"]["pg_code"] == "knet"
        assert "pg_code" not in result

    def test_pg_code_merges_with_payment_fields(self):
        ctx = LoggingContext(pg_code="knet", orn="ORN123")
        result = ctx.to_dict()
        assert result["payment"] == {"pg_code": "knet", "orn": "ORN123"}

    def test_session_id_stays_flat(self):
        ctx = LoggingContext(session_id="s1")
        result = ctx.to_dict()
        assert result["session_id"] == "s1"
        assert "payment" not in result or "session_id" not in result.get("payment", {})

    def test_orn_and_reference_under_payment(self):
        ctx = LoggingContext(orn="ORN1", reference_number="REF1")
        result = ctx.to_dict()
        assert result["payment"] == {"orn": "ORN1", "reference": "REF1"}


class TestLabels:
    def test_labels_preserved_through_context(self):
        ctx = LoggingContext(labels={"env": "prod", "region": "us-east-1"})
        result = ctx.to_dict()
        assert result["labels"] == {"env": "prod", "region": "us-east-1"}

    def test_empty_labels_omitted(self):
        ctx = LoggingContext()
        result = ctx.to_dict()
        assert "labels" not in result

    def test_labels_merge_on_nesting(self):
        outer = LoggingContext(labels={"env": "prod"})
        inner = outer.merge(labels={"region": "eu-west-1"})
        result = inner.to_dict()
        assert result["labels"] == {"env": "prod", "region": "eu-west-1"}

    def test_labels_override_on_conflict(self):
        outer = LoggingContext(labels={"env": "staging"})
        inner = outer.merge(labels={"env": "prod"})
        result = inner.to_dict()
        assert result["labels"]["env"] == "prod"

    def test_labels_coerces_nested_dicts_to_string(self):
        ctx = LoggingContext(labels={"nested": {"a": 1}})
        result = ctx.to_dict()
        assert isinstance(result["labels"]["nested"], str)

    def test_labels_coerces_lists_to_string(self):
        ctx = LoggingContext(labels={"tags": ["a", "b"]})
        result = ctx.to_dict()
        assert isinstance(result["labels"]["tags"], str)

    def test_labels_allows_flat_values(self):
        ctx = LoggingContext(labels={"env": "prod", "count": 5, "active": True})
        result = ctx.to_dict()
        assert result["labels"] == {"env": "prod", "count": 5, "active": True}


class TestECSMapping:
    def test_span_id_nested(self):
        ctx = LoggingContext(span_id="abc-123")
        assert ctx.to_dict()["span"] == {"id": "abc-123"}

    def test_user_id_nested(self):
        ctx = LoggingContext(user_id=42)
        assert ctx.to_dict()["user"] == {"id": 42}

    def test_ip_nested(self):
        ctx = LoggingContext(ip="10.0.0.1")
        assert ctx.to_dict()["client"] == {"ip": "10.0.0.1"}

    def test_empty_context_produces_empty_dict(self):
        ctx = LoggingContext()
        assert ctx.to_dict() == {}

    def test_full_context(self):
        ctx = LoggingContext(
            span_id="s1",
            user_id=1,
            ip="1.2.3.4",
            session_id="sess",
            orn="orn1",
            pg_code="knet",
            reference_number="ref1",
            labels={"env": "test"},
        )
        result = ctx.to_dict()
        assert result["span"] == {"id": "s1"}
        assert result["user"] == {"id": 1}
        assert result["client"] == {"ip": "1.2.3.4"}
        assert result["session_id"] == "sess"
        assert result["payment"] == {
            "orn": "orn1",
            "pg_code": "knet",
            "reference": "ref1",
        }
        assert result["labels"] == {"env": "test"}
        # pg_code must NOT be flat
        assert "pg_code" not in result
