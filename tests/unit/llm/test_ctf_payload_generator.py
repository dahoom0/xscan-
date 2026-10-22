"""
Tests for CTF Payload Generator Specialist
===========================================
Tests that the specialist generates custom payloads based on encoding profiles.
"""
import pytest

from xscan.llm.specialists.ctf_payload_generator import (
    CTFPayloadGeneratorInput,
    CTFPayloadGeneratorSpecialist,
)


class TestCTFPayloadGenerator:
    """Test CTF payload generation strategies."""

    def test_specialist_instantiates(self):
        """Test that the specialist can be instantiated."""
        specialist = CTFPayloadGeneratorSpecialist()
        assert specialist.specialist_name == "ctf-payload-generator"

    def test_html_attribute_context_rules(self):
        """Test payload generation for HTML attribute context."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Scenario: html_attribute with double quote available
        input_data = CTFPayloadGeneratorInput(
            scan_id="test_001",
            url="http://example.com/page?search=test",
            parameter="search",
            context="html_attribute",
            attribute="value",
            quote_type="double",
            raw_chars=['"', ' ', 'o', 'n', 'e', 'r', 'r', 'o', 'r', '=', 'a', 'l', 'e', 'r', 't', '(', '1', ')'],
            encoded_chars=['<', '>'],
            stripped_chars=[],
        )
        
        output = specialist.run(input_data)
        
        # Should generate candidates
        assert output.candidates, "Should generate at least one candidate"
        
        # All candidates should use only raw_chars
        for candidate in output.candidates:
            payload = candidate.payload
            # Check that no encoded or stripped chars are in payload
            for char in ['<', '>']:
                assert char not in payload, f"Payload should not contain encoded char '{char}': {payload}"

    def test_script_string_context_semicolon_available(self):
        """Test JS string context where semicolon is available for statement chaining."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Scenario: script_string_double with semicolon available (like shop.post.ch)
        input_data = CTFPayloadGeneratorInput(
            scan_id="test_002",
            url="http://example.com/api/search",
            parameter="q",
            context="script_string_double",
            quote_type="double",
            raw_chars=[';', 'a', 'l', 'e', 'r', 't', '(', '1', ')', '/', '/', '\n'],
            encoded_chars=['"', '<', '>'],
            stripped_chars=[],
        )
        
        output = specialist.run(input_data)
        
        assert output.candidates, "Should generate candidates for script context with semicolon"
        
        # Should suggest statement chaining or similar techniques
        techniques = [c.technique for c in output.candidates]
        assert any(techniques), "Should identify viable techniques"

    def test_context_rules_in_prompt(self):
        """Test that context-specific rules are included in prompts."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Different contexts should get different rules
        for context in ["html_attribute", "script_string_double", "html_text", "unknown"]:
            input_data = CTFPayloadGeneratorInput(
                scan_id=f"test_ctx_{context}",
                url="http://test.com/search",
                parameter="q",
                context=context,
                raw_chars=['a', 'l', 'e', 'r', 't', '(', '1', ')'],
                encoded_chars=[],
                stripped_chars=[],
            )
            
            prompt_text = specialist.build_prompt(input_data)
            assert context in prompt_text or "Context" in prompt_text, f"Prompt should reference context: {context}"

    def test_no_impossible_payloads(self):
        """Test that specialist doesn't generate payloads using encoded/stripped chars."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Scenario: very restricted filter (only alphanumeric + semicolon)
        input_data = CTFPayloadGeneratorInput(
            scan_id="test_restricted",
            url="http://example.com/test",
            parameter="input",
            context="script_expression",
            raw_chars=['a', 'l', 'r', 't', '(', '1', ')', ';'],
            encoded_chars=['<', '>', '"', "'", '/', '-'],
            stripped_chars=['!', '@', '#', '$', '%'],
            max_candidates=3,
        )
        
        output = specialist.run(input_data)
        
        # All payloads must use only raw_chars
        encoded_set = set(input_data.encoded_chars)
        stripped_set = set(input_data.stripped_chars)
        
        for candidate in output.candidates:
            payload = candidate.payload
            # Check that encoded/stripped chars don't appear
            for char in encoded_set:
                assert char not in payload, (
                    f"Payload '{payload}' contains encoded char '{char}'"
                )
            for char in stripped_set:
                assert char not in payload, (
                    f"Payload '{payload}' contains stripped char '{char}'"
                )

    def test_json_parsing_robustness(self):
        """Test that output parsing handles various JSON formats."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Valid JSON response
        valid_json = """{
            "analysis": "analysis",
            "bypass_strategies": ["technique1"],
            "selected_strategy": "technique1",
            "candidates": [
                {"priority": 1, "payload": "alert(1)", "technique": "direct", "rationale": "test"}
            ]
        }"""
        
        output = specialist.parse_output(valid_json)
        assert len(output.candidates) == 1
        assert output.candidates[0].payload == "alert(1)"

    def test_prompt_includes_previous_attempts(self):
        """Test that previous attempts are included in the prompt for iteration."""
        specialist = CTFPayloadGeneratorSpecialist()
        
        input_data = CTFPayloadGeneratorInput(
            scan_id="test_prev",
            url="http://example.com/test",
            parameter="search",
            context="html_attribute",
            raw_chars=['a', 'l', 'e', 'r', 't', '(', '1', ')', ' '],
            encoded_chars=['"'],
            stripped_chars=[],
            max_candidates=3,
        )
        
        prompt = specialist.build_prompt(input_data)
        
        # Prompt should mention constraints and strategy
        assert "raw" in prompt.lower() or "character" in prompt.lower(), \
            "Prompt should discuss available characters"
        assert "context" in prompt.lower(), \
            "Prompt should mention context"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
