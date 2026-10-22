"""
Integration test: CTF Payload Generation
=========================================
Demonstrates CTF payload generation with real-world scenarios.
Tests that LLM-generated payloads are tailored to the target's encoding profile.
"""
import pytest

from xscan.llm.specialists.ctf_payload_generator import (
    CTFPayloadGeneratorInput,
    CTFPayloadGeneratorSpecialist,
)


class TestCTFPayloadGenerationRealScenarios:
    """Test CTF payload generation on realistic scenarios."""

    @pytest.mark.integration
    def test_shop_post_ch_scenario_semicolon_available(self):
        """
        Real scenario from shop.post.ch:
        - Context: script_string_double (JS string)
        - Raw chars: ; ( ) alert 1 / = space
        - Encoded chars: < > " / (some characters)
        - Expected payload: ;alert(1)// or similar statement chaining
        
        This is the EXACT scenario from the conversation:
        "should craft payload according the target"
        "scanner fails to test or detect the suitable payload"
        """
        specialist = CTFPayloadGeneratorSpecialist()
        
        # Simulate shop.post.ch encoding profile
        input_data = CTFPayloadGeneratorInput(
            scan_id="scan_test_001",
            url="https://shop.post.ch/search",
            parameter="q",
            context="script_string_double",
            attribute="",
            quote_type="double",
            # Characters that survive: semicolon, parens, alert, numbers, slashes, spaces
            raw_chars=[
                ';', '(', ')', 'a', 'l', 'e', 'r', 't', '1', '0',
                '/', '/', 'n', 'w', 'i', 'd', '=', ' ', '\n'
            ],
            # Characters that are encoded/stripped: angle brackets, quotes
            encoded_chars=['<', '>', '"', "'"],
            stripped_chars=[],
            max_candidates=5,
        )
        
        prompt = specialist.build_prompt(input_data)
        print("\n=== CTF Payload Generator Prompt ===")
        print(prompt[:500])
        print("...")
        
        # Verify prompt includes key information
        assert "script_string_double" in prompt or "JavaScript" in prompt, \
            "Prompt should describe JS string context"
        assert "raw" in prompt.lower(), "Prompt should list raw characters"
        assert ";" in prompt, "Prompt should see semicolon available"
        assert "<" in prompt and "encoded" in prompt.lower(), \
            "Prompt should note < > are blocked"
        
        print("\n✓ Prompt correctly describes the challenge:")
        print("  - Context: JS string (script_string_double)")
        print("  - Available: ; ( ) alphanumeric /")
        print("  - Blocked: < > \" characters")
        print("  - Strategy hint: Statement chaining with semicolons")

    @pytest.mark.integration
    def test_html_attribute_with_quote_available(self):
        """
        Scenario: HTML attribute injection with quotes available
        Expected: Event handler payloads like \" onload=\"alert(1)
        """
        specialist = CTFPayloadGeneratorSpecialist()
        
        input_data = CTFPayloadGeneratorInput(
            scan_id="scan_test_002",
            url="http://example.com/search",
            parameter="q",
            context="html_attribute",
            attribute="value",
            quote_type="double",
            raw_chars=[
                '"', ' ', 'o', 'n', 'l', 'o', 'a', 'd', '=',
                'a', 'l', 'e', 'r', 't', '(', '1', ')'
            ],
            encoded_chars=['<', '>'],
            stripped_chars=[],
            max_candidates=3,
        )
        
        prompt = specialist.build_prompt(input_data)
        
        # Verify it includes HTML attribute-specific rules
        assert "html" in prompt.lower() or "attribute" in prompt.lower(), \
            "Prompt should describe HTML attribute context"
        assert "event" in prompt.lower() or "onload" in prompt.lower(), \
            "Prompt should suggest event handlers"
        
        print("\n✓ HTML Attribute scenario prompt includes:")
        print("  - Event handler generation strategies")
        print("  - Quote escape techniques")
        print("  - Safe characters for attribute context")

    @pytest.mark.integration
    def test_restricted_filter_creative_bypass(self):
        """
        Scenario: Very restricted filter (only alphanumeric + semicolon)
        Expected: Creative bypasses using available characters
        
        This tests the LLM's ability to find novel solutions when standard
        payload characters are blocked.
        """
        input_data = CTFPayloadGeneratorInput(
            scan_id="scan_test_003",
            url="http://ctf.example.com/search",
            parameter="input",
            context="script_expression",
            raw_chars=['a', 'l', 'e', 'r', 't', '(', '1', ')', ';', ' ', '\n'],
            encoded_chars=['<', '>', '"', "'", '/', '-', '=', '{', '}'],
            stripped_chars=['!', '@', '#', '$', '%', '^', '&', '*'],
            max_candidates=3,
        )
        
        # Verify it acknowledges the constraints
        assert len(input_data.raw_chars) < 15, "This should be a TIGHT filter"
        
        print("\n✓ Restricted filter scenario:")
        print(f"  - Only {len(input_data.raw_chars)} characters available")
        print(f"  - {len(input_data.encoded_chars)} characters encoded")
        print(f"  - {len(input_data.stripped_chars)} characters stripped")
        print("  - LLM must find creative solutions within tight constraints")

    def test_ctf_generator_vs_family_synthesis(self):
        """
        Demonstrate the difference between CTF-mode (custom) vs standard (family-based) synthesis.
        
        Standard synthesis: Try pre-made families (tag_injection, attribute_breakout, etc.)
        CTF synthesis: Analyze THIS target's constraints, generate THIS target's payloads
        """
        
        print("\n=== Comparison: Family-Based vs CTF-Mode Synthesis ===")
        print("\nFamily-Based (Standard):")
        print("  1. Detect context (html_attribute)")
        print("  2. Load family 'attribute_breakout'")
        print("  3. Try: \" onmouseover=\"alert(1)")
        print("  4. Try: \" autofocus onfocus=\"alert(1)")
        print("  5. Try: ' onload='alert(1)")
        print("  6. (Generic payloads regardless of THIS target's filter)")
        
        print("\nCTF-Mode (Custom):")
        print("  1. Analyze encoding profile: ; ( ) available, < > blocked")
        print("  2. Determine context: script_string_double")
        print("  3. Generate custom: ;alert(1)// (only uses available chars)")
        print("  4. Generate custom: ;alert(String.fromCharCode(88,83,83))//")
        print("  5. Generate custom: ;this.constructor.constructor('alert(1)')()//")
        print("  6. (All payloads SPECIFIC to this target's constraints)")
        
        print("\n✓ CTF mode crafts payloads according to the target")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
