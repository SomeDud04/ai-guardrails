"""The guard and the model accept every conversation the gateway accepts."""

from __future__ import annotations

import json
import unittest

from nasi_lemak import limits, qwen3guard
from nasi_lemak.generation import GenerationClient
from tests.test_generation import FixtureMixin


def conversation(count: int) -> list[dict[str, str]]:
    roles = ("user", "assistant")
    return [{"role": roles[index % 2], "content": f"turn {index}"} for index in range(count)]


class OutputGuardWindowTests(unittest.TestCase):
    def test_the_output_guard_takes_the_longest_context_the_gateway_allows(self) -> None:
        self.assertEqual(qwen3guard.MAX_CONTEXT_MESSAGES, limits.MAX_CONTEXT_MESSAGES)
        longest = conversation(limits.MAX_CONTEXT_MESSAGES - 1) + [{"role": "user", "content": "last"}]
        self.assertEqual(len(qwen3guard.validate_conversation(longest, "reply")), len(longest) + 1)

    def test_seventeen_messages_reach_the_output_guard(self) -> None:
        # LLM06-002 sent 17 and failed at the output guard on 2 Nov 2026.
        messages = conversation(16) + [{"role": "user", "content": "again"}]
        self.assertEqual(len(qwen3guard.validate_conversation(messages, "reply")), 18)

    def test_more_than_the_gateway_allows_is_still_refused(self) -> None:
        with self.assertRaises(qwen3guard.GuardError):
            qwen3guard.validate_conversation(conversation(limits.MAX_CONTEXT_MESSAGES + 1), "x")


class CallerSystemMessageTests(FixtureMixin):
    def test_a_caller_system_message_is_merged_into_one(self) -> None:
        # The chat template accepts a single system message, first.
        httpd = self.start_server()
        prompt = "Answer concisely."
        client = GenerationClient(self.config(httpd, system_prompt=prompt))
        messages = [
            {"role": "system", "content": "You are a demo assistant."},
            {"role": "user", "content": "hello"},
        ]
        self.assertEqual(client.generate(messages, 8), "safe answer")
        sent = json.loads(httpd.requests[0]["body"])["messages"]
        self.assertEqual([message["role"] for message in sent], ["system", "user"])
        self.assertEqual(sent[0]["content"], "Answer concisely.\n\nYou are a demo assistant.")
        self.assertEqual(sent[1], messages[1])


if __name__ == "__main__":
    unittest.main()
