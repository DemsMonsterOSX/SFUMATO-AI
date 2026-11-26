"""Platform context for the Da Vinci agent: topic selection and the deterministic summary (no database, no model)."""
from app.services import platform_context as pc


def test_topics_follow_the_question():
    assert pc.topics_for("quel est le débit de Kafka avec 3 scorers ?") == ["scalability"]
    assert "architecture" in pc.topics_for("quelle VM fait quoi ?")
    assert "incidents" in pc.topics_for("combien d'incidents critiques ?")
    assert pc.topics_for("bonjour") == []


def test_describe_lists_every_machine_with_the_designed_layout_when_not_live():
    text = pc.describe({"architecture": {"live": False, "machines": pc.ARCHITECTURE}})
    assert "sfumato-kafka-1" in text and "sfumato-qwen" in text and "g2-standard-4 + NVIDIA L4" in text and "non lu" in text


def test_describe_uses_the_real_state_when_live():
    rows = [{**r, "state": "RUNNING", "machine_type": "e2-standard-4", "gpu": []} for r in pc.ARCHITECTURE[:1]]
    text = pc.describe({"architecture": {"live": True, "machines": rows, "running_vcpus": 30}})
    assert "état réel" in text and "running" in text and "30" in text


def test_describe_scalability_quotes_the_measured_figures():
    ctx = {"scalability": {"spark_input_gb": 6.89, "spark_prep_seconds_by_executors": {"2": 738, "4": 416},
                           "kafka_scorers_max_flows_per_s": {"2 scorers": 17865},
                           "flink_per_source_by_parallelism": {"1": {"avg_per_s": 236457}}}}
    text = pc.describe(ctx)
    assert "738" in text and "416" in text and "17865" in text and "236457" in text


def test_describe_incidents_when_empty_and_when_filled():
    assert "Aucun incident" in pc.describe({"incidents": {"total": 0}})
    full = pc.describe({"incidents": {"total": 3, "by_severity": {"high": 2}, "by_status": {"completed": 3}, "by_verdict": {"malicious": 1}, "needing_human_review": 1}})
    assert "3 au total" in full


def test_describe_returns_none_when_only_the_model_can_interpret():
    assert pc.describe({"open_set": {"families": []}}) is None
