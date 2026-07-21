
import pytest
from unittest.mock import MagicMock

from depsafe.agent import DepSafeAgent
from depsafe.exceptions import Submitted


def test_agent_starts_with_empty_messages():
    agent = DepSafeAgent()
    assert agent.messages == []

def test_submitted_exception_adds_exit_message():
    agent = DepSafeAgent()
    agent.step = MagicMock(side_effect=Submitted({"role": "exit", "content": "done"}))
    agent.run("test_submitted_exception_adds_exit_message")
    assert len(agent.messages) == 3
    assert agent.messages[-1]["role"] == "exit"
    assert agent.messages[-1]["content"] == "done"

def test_run_adds_system_and_user_message():
    agent = DepSafeAgent()
    agent.step = MagicMock(side_effect=Submitted({"role": "exit", "content": "done"}))
    agent.run("test_run_adds_system_and_user_message")
    assert agent.messages[0]["role"] == "system"
    assert agent.messages[1]["role"] == "user"
    assert "test_run_adds_system_and_user_message" in agent.messages[1]["content"]

