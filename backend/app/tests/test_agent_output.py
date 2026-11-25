"""AgentOutput accepts the shapes real models produce."""
from app.agents.schemas import AgentOutput


def _base(**kw):
    return {"summary": "s", "technical_explanation": "t", "recommended_verdict": "INCONCLUSIVE", **kw}


def test_limitations_given_as_strings_are_kept():
    out = AgentOutput.model_validate(_base(confidence_limitations=["a", "b"]))
    assert out.confidence_limitations == ["a", "b"]


def test_limitations_given_as_statement_objects_are_flattened():
    out = AgentOutput.model_validate(_base(confidence_limitations=[{"statement": "Network traffic may be an internal test or drill."}, "plain"]))
    assert out.confidence_limitations == ["Network traffic may be an internal test or drill.", "plain"]


def test_unknown_object_shape_is_still_kept_as_text():
    out = AgentOutput.model_validate(_base(confidence_limitations=[{"foo": 1, "bar": "x"}]))
    assert out.confidence_limitations == ["foo: 1; bar: x"]
