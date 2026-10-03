package pl.aibron.aigate.inspection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Soft signals of prompt injection. None of them is proof on its own, so they are combined into a 0..1 risk score
 * (noisy-OR: 1 - product of (1 - weight)). The profile decides which score goes straight to block and which goes
 * to the guard models for a second opinion.
 */
@Component
public class RiskScorer {

    public record Signal(String id, double weight) { }

    public record Assessment(double score, List<Signal> signals) { }

    private record Rule(String id, double weight, Pattern pattern) { }

    private static final int LONG_INPUT_CHARS = 8000;

    private static final List<Rule> RULES = List.of(
            new Rule("injection.override_instructions", 0.6, Pattern.compile(
                    "(?i)\\b(ignore|disregard|forget|override)\\b.{0,30}\\b(previous|prior|above|earlier|all|your|system)\\b.{0,30}\\b(instructions?|rules|prompts?|guidelines|directives)\\b")),
            new Rule("injection.override_instructions_pl", 0.6, Pattern.compile(
                    "(?iuU)\\b(zignoruj|pomi[nń]|zapomnij)\\b.{0,30}\\b(poprzednie|wcze[sś]niejsze|wszystkie|swoje)\\b.{0,30}\\b(instrukcj\\w*|polece[nń]\\w*|zasad\\w*)")),
            new Rule("injection.reveal_prompt", 0.5, Pattern.compile(
                    "(?i)\\b(reveal|show|print|repeat|output|tell me)\\b.{0,30}\\b(system prompt|your (instructions|prompt|rules)|initial prompt|hidden prompt)")),
            new Rule("injection.reveal_prompt_pl", 0.5, Pattern.compile(
                    "(?iuU)\\b(poka[zż]|wypisz|powt[oó]rz|zdrad[zź])\\b.{0,30}\\b(prompt\\w* systemow\\w*|swoje instrukcje|instrukcje systemowe)")),
            new Rule("injection.persona", 0.4, Pattern.compile(
                    "(?i)\\b(you are now|from now on you are|act as|pretend (to be|you are)|roleplay as)\\b.{0,40}\\b(DAN|unrestricted|unfiltered|jailbroken|no (rules|restrictions|limits)|evil)")),
            new Rule("injection.known_jailbreak", 0.5, Pattern.compile(
                    "(?i)\\b(do anything now|developer mode (enabled|on)|jailbreak mode|AIM mode|STAN mode|godmode)\\b")),
            new Rule("injection.disable_safety", 0.6, Pattern.compile(
                    "(?i)\\b(disabled?|disabling|turn(ed)? off|bypass(ed|ing)?|without)\\b.{0,30}\\b(safety|filter(s|ing)?|guardrails|content polic(y|ies)|safety polic(y|ies))\\b")),
            new Rule("exfiltration.forward_conversation", 0.5, Pattern.compile(
                    "(?i)\\b(forward|send|post|upload|exfiltrate|leak)\\b.{0,40}\\b(conversation|chat history|messages|context|system prompt|credentials)\\b.{0,40}(https?://|\\S+@\\S+)")),
            new Rule("injection.fake_system_turn", 0.5, Pattern.compile(
                    "(?im)^\\s*(###\\s*)?(system|assistant)\\s*:|<\\|im_start\\|>|\\[INST\\]|<\\|system\\|>")),
            new Rule("injection.hidden_html_comment", 0.6, Pattern.compile(
                    "(?is)<!--.{0,300}\\b(assistant|system|ignore|instructions?|forward|send|exfiltrate)\\b.{0,300}-->")),
            new Rule("exfiltration.markdown_image", 0.5, Pattern.compile(
                    "!\\[[^\\]]*\\]\\(https?://[^)\\s]+\\?[^)\\s]*=")),
            new Rule("obfuscation.base64_blob", 0.3, Pattern.compile("[A-Za-z0-9+/]{60,}={0,2}")),
            new Rule("obfuscation.invisible_chars", 0.4, Pattern.compile("[\\u200B-\\u200F\\u2060-\\u2064\\uFEFF\\u202A-\\u202E\\x{E0000}-\\x{E007F}]")),
            new Rule("roleplay.hypothetical", 0.15, Pattern.compile(
                    "(?i)\\b(hypothetically|in a fictional (world|story)|for a novel|let'?s play a game)\\b")));

    public Assessment assess(String text) {
        var signals = new ArrayList<Signal>();
        if (text == null || text.isEmpty()) {
            return new Assessment(0, signals);
        }
        for (var rule : RULES) {
            if (rule.pattern().matcher(text).find()) {
                signals.add(new Signal(rule.id(), rule.weight()));
            }
        }
        if (text.length() > LONG_INPUT_CHARS) {
            signals.add(new Signal("size.long_input", 0.2));
        }
        double keep = 1.0;
        for (var s : signals) {
            keep *= 1 - s.weight();
        }
        return new Assessment(1 - keep, signals);
    }
}
