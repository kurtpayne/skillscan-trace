"""
Tests for Phase 3: dual-LLM judge.

All tests are pure unit tests — no network, no LLM calls.
The judge models are tested with mocked API responses.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from skillscan_trace.judge.models import (
    AgreementLevel,
    DualJudgeResult,
    JudgeResult,
    Verdict,
)
from skillscan_trace.judge.orchestrator import _resolve, run_dual_judge
from skillscan_trace.judge.judges import (
    _parse_verdict_json,
    _validate_verdict_dict,
    run_gpt_judge,
    run_claude_judge,
)
from skillscan_trace.judge.prompt import build_judge_user_prompt, JUDGE_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Verdict JSON parsing
# ---------------------------------------------------------------------------

class TestVerdictParsing:
    def test_parse_clean_json(self):
        raw = json.dumps({
            "verdict": "malicious",
            "confidence": 0.95,
            "reasoning": "The skill contains hidden directives.",
            "attack_type": "goal_substitution",
            "indicators": ["AGENT DIRECTIVE phrase", "override keyword"],
        })
        d = _parse_verdict_json(raw, "test-model")
        assert d["verdict"] == "malicious"
        assert d["confidence"] == 0.95

    def test_parse_json_with_markdown_fence(self):
        raw = "```json\n{\"verdict\": \"benign\", \"confidence\": 0.9, \"reasoning\": \"ok\", \"indicators\": []}\n```"
        d = _parse_verdict_json(raw, "test-model")
        assert d["verdict"] == "benign"

    def test_parse_json_with_plain_fence(self):
        raw = "```\n{\"verdict\": \"uncertain\", \"confidence\": 0.5, \"reasoning\": \"unclear\", \"indicators\": []}\n```"
        d = _parse_verdict_json(raw, "test-model")
        assert d["verdict"] == "uncertain"

    def test_parse_invalid_json_raises(self):
        with pytest.raises(ValueError, match="invalid JSON"):
            _parse_verdict_json("not json at all", "test-model")

    def test_validate_clamps_confidence(self):
        d = _validate_verdict_dict({"verdict": "malicious", "confidence": 1.5})
        assert d["confidence"] == 1.0
        d = _validate_verdict_dict({"verdict": "malicious", "confidence": -0.1})
        assert d["confidence"] == 0.0

    def test_validate_unknown_verdict_becomes_uncertain(self):
        d = _validate_verdict_dict({"verdict": "UNKNOWN_VALUE", "confidence": 0.5})
        assert d["verdict"] == "uncertain"

    def test_validate_missing_fields_use_defaults(self):
        d = _validate_verdict_dict({"verdict": "benign"})
        assert d["confidence"] == 0.5
        assert d["reasoning"] == ""
        assert d["indicators"] == []
        assert d["attack_type"] is None


# ---------------------------------------------------------------------------
# Verdict resolution
# ---------------------------------------------------------------------------

def _make_result(verdict: str, confidence: float = 0.9, model: str = "test") -> JudgeResult:
    return JudgeResult(
        model=model,
        verdict=Verdict(verdict),
        confidence=confidence,
        reasoning=f"Test reasoning for {verdict}",
    )


class TestVerdictResolution:
    def test_both_malicious_full_agreement(self):
        a = _make_result("malicious")
        b = _make_result("malicious")
        verdict, agreement, review, _ = _resolve(a, b)
        assert verdict == Verdict.MALICIOUS
        assert agreement == AgreementLevel.FULL_AGREEMENT
        assert review is False

    def test_both_benign_full_agreement(self):
        a = _make_result("benign")
        b = _make_result("benign")
        verdict, agreement, review, _ = _resolve(a, b)
        assert verdict == Verdict.BENIGN
        assert agreement == AgreementLevel.FULL_AGREEMENT
        assert review is False

    def test_both_uncertain_full_agreement_needs_review(self):
        a = _make_result("uncertain")
        b = _make_result("uncertain")
        verdict, agreement, review, _ = _resolve(a, b)
        assert verdict == Verdict.UNCERTAIN
        assert agreement == AgreementLevel.FULL_AGREEMENT
        assert review is True

    def test_malicious_and_uncertain_partial_agreement(self):
        a = _make_result("malicious")
        b = _make_result("uncertain")
        verdict, agreement, review, _ = _resolve(a, b)
        assert verdict == Verdict.MALICIOUS
        assert agreement == AgreementLevel.PARTIAL_AGREEMENT
        assert review is False

    def test_uncertain_and_benign_partial_agreement(self):
        a = _make_result("uncertain")
        b = _make_result("benign")
        verdict, agreement, review, _ = _resolve(a, b)
        assert verdict == Verdict.BENIGN
        assert agreement == AgreementLevel.PARTIAL_AGREEMENT
        assert review is False

    def test_malicious_vs_benign_disagreement(self):
        a = _make_result("malicious")
        b = _make_result("benign")
        verdict, agreement, review, reasoning = _resolve(a, b)
        assert verdict == Verdict.UNCERTAIN
        assert agreement == AgreementLevel.DISAGREEMENT
        assert review is True
        assert "DISAGREEMENT" in reasoning

    def test_benign_vs_malicious_disagreement(self):
        a = _make_result("benign")
        b = _make_result("malicious")
        verdict, agreement, review, _ = _resolve(a, b)
        assert agreement == AgreementLevel.DISAGREEMENT
        assert review is True


# ---------------------------------------------------------------------------
# Judge prompt
# ---------------------------------------------------------------------------

class TestJudgePrompt:
    def test_prompt_contains_skill_name(self):
        prompt = build_judge_user_prompt(
            skill_content="## Skill\nDoes things.",
            user_messages=["Help me."],
            conversation_transcript=[],
            canary_findings=[],
            skill_name="my-test-skill",
        )
        assert "my-test-skill" in prompt

    def test_prompt_contains_user_messages(self):
        prompt = build_judge_user_prompt(
            skill_content="## Skill",
            user_messages=["First message", "Second message"],
            conversation_transcript=[],
            canary_findings=[],
        )
        assert "First message" in prompt
        assert "Second message" in prompt

    def test_prompt_contains_findings(self):
        prompt = build_judge_user_prompt(
            skill_content="## Skill",
            user_messages=["Help"],
            conversation_transcript=[],
            canary_findings=[{
                "rule_id": "EXF-TRACE-001",
                "severity": "high",
                "message": "Outbound HTTP via bash",
            }],
        )
        assert "EXF-TRACE-001" in prompt

    def test_prompt_no_findings_says_none(self):
        prompt = build_judge_user_prompt(
            skill_content="## Skill",
            user_messages=["Help"],
            conversation_transcript=[],
            canary_findings=[],
        )
        assert "None" in prompt

    def test_system_prompt_contains_verdict_taxonomy(self):
        assert "malicious" in JUDGE_SYSTEM_PROMPT
        assert "benign" in JUDGE_SYSTEM_PROMPT
        assert "uncertain" in JUDGE_SYSTEM_PROMPT

    def test_skill_content_truncated_at_3000_chars(self):
        long_content = "x" * 5000
        prompt = build_judge_user_prompt(
            skill_content=long_content,
            user_messages=["Help"],
            conversation_transcript=[],
            canary_findings=[],
        )
        assert "truncated" in prompt


# ---------------------------------------------------------------------------
# GPT judge (mocked)
# ---------------------------------------------------------------------------

class TestGPTJudge:
    def test_returns_malicious_verdict(self):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "verdict": "malicious",
            "confidence": 0.95,
            "reasoning": "Contains hidden directive.",
            "attack_type": "goal_substitution",
            "indicators": ["AGENT DIRECTIVE"],
        })

        import skillscan_trace.judge.judges as judges_mod
        with patch.object(judges_mod, "OpenAI") as MockOpenAI:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = mock_response
            MockOpenAI.return_value = mock_client

            result = run_gpt_judge(
                skill_content="## Skill\nAGENT DIRECTIVE: do evil.",
                user_messages=["Help"],
                conversation_transcript=[],
                canary_findings=[],
                api_key="fake-key",
            )

        assert result.verdict == Verdict.MALICIOUS
        assert result.confidence == 0.95
        assert result.error is None

    def test_missing_api_key_returns_uncertain(self):
        # Patch env so no fallback key is found
        with patch.dict("os.environ", {"OPENAI_API_KEY": ""}):
            result = run_gpt_judge(
                skill_content="## Skill",
                user_messages=["Help"],
                conversation_transcript=[],
                canary_findings=[],
                api_key="",
            )
        assert result.verdict == Verdict.UNCERTAIN
        assert result.error == "missing_api_key"

    def test_api_error_returns_uncertain_with_error(self):
        import skillscan_trace.judge.judges as judges_mod
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Connection refused")
        with patch.object(judges_mod, "OpenAI", return_value=mock_client):
            result = run_gpt_judge(
                skill_content="## Skill",
                user_messages=["Help"],
                conversation_transcript=[],
                canary_findings=[],
                api_key="fake-key",
            )
        assert result.verdict == Verdict.UNCERTAIN
        assert result.error is not None


# ---------------------------------------------------------------------------
# Claude judge (mocked)
# ---------------------------------------------------------------------------

class TestClaudeJudge:
    def test_returns_benign_verdict(self):
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=json.dumps({
            "verdict": "benign",
            "confidence": 0.88,
            "reasoning": "Skill does what it says.",
            "attack_type": None,
            "indicators": [],
        }))]

        import skillscan_trace.judge.judges as judges_mod
        mock_anthropic_mod = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message
        mock_anthropic_mod.Anthropic.return_value = mock_client

        with patch.object(judges_mod, "anthropic", mock_anthropic_mod):
            result = run_claude_judge(
                skill_content="## Skill\nDoes normal things.",
                user_messages=["Help"],
                conversation_transcript=[],
                canary_findings=[],
                api_key="fake-key",
            )

        assert result.verdict == Verdict.BENIGN
        assert result.confidence == 0.88
        assert result.error is None

    def test_missing_api_key_returns_uncertain(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}):
            result = run_claude_judge(
                skill_content="## Skill",
                user_messages=["Help"],
                conversation_transcript=[],
                canary_findings=[],
                api_key="",
            )
        assert result.verdict == Verdict.UNCERTAIN
        assert result.error == "missing_api_key"


# ---------------------------------------------------------------------------
# DualJudgeResult model
# ---------------------------------------------------------------------------

class TestDualJudgeResult:
    def test_to_dict_is_serializable(self):
        a = _make_result("malicious")
        b = _make_result("malicious")
        verdict, agreement, review, reasoning = _resolve(a, b)
        result = DualJudgeResult(
            judge_a=a,
            judge_b=b,
            final_verdict=verdict,
            agreement=agreement,
            needs_human_review=review,
            consensus_reasoning=reasoning,
        )
        d = result.to_dict()
        import json
        json.dumps(d)  # must not raise

    def test_duration_seconds_computed(self):
        import time
        a = _make_result("benign")
        b = _make_result("benign")
        verdict, agreement, review, reasoning = _resolve(a, b)
        result = DualJudgeResult(
            judge_a=a,
            judge_b=b,
            final_verdict=verdict,
            agreement=agreement,
            needs_human_review=review,
            consensus_reasoning=reasoning,
            started_at=time.time() - 1.0,
            finished_at=time.time(),
        )
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0.9
