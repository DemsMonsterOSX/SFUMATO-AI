from app.services import shuffle


def test_disabled_without_url(monkeypatch):
    monkeypatch.delenv("SHUFFLE_WEBHOOK_URL", raising=False)
    assert shuffle.notify("INC-1", "completed", {"verdict": "true_positive"}, 10) is False


def test_payload_is_a_summary_only():
    p = shuffle.build_payload("INC-1", "needs_review", {"verdict": "x", "threat_score": 80, "confidence": 0.9,
                                                         "human_review_required": 1, "raw": "secret"}, 1234)
    assert p["incident_id"] == "INC-1" and p["human_review_required"] is True and p["duration_ms"] == 1234
    assert "raw" not in p


def test_notify_posts_in_background(monkeypatch):
    sent = []
    monkeypatch.setenv("SHUFFLE_WEBHOOK_URL", "http://example.invalid/hook")
    monkeypatch.setattr(shuffle, "_post", lambda url, payload: sent.append((url, payload)))
    assert shuffle.notify("INC-2", "completed", {"verdict": "false_positive"}, 5) is True
    import time
    for _ in range(50):
        if sent:
            break
        time.sleep(0.02)
    assert sent and sent[0][0] == "http://example.invalid/hook" and sent[0][1]["verdict"] == "false_positive"
