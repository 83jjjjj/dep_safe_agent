
import os
import yaml
import platform
from pathlib import Path
from jinja2 import StrictUndefined, Template

from depsafe import package_dir
from depsafe.model import LitellmModel
from depsafe.exceptions import Submitted
from depsafe.environment import LocalEnvironment

class DepSafeAgent:
    def __init__(self):
        self.config = yaml.safe_load(Path(package_dir / "config" / "default.yaml").read_text(encoding='utf-8'))["agent"]
        self.model = LitellmModel("deepseek/deepseek-v4-flash", os.getenv("DEEPSEEK_API_KEY"))
        self.messages = []
        self.env = LocalEnvironment()

    def run(self, task: str):
        self.config["task"] = task
        self.config.update(platform.uname()._asdict())
        self.messages.append({"role": "system", "content": Template(self.config["system_template"], undefined=StrictUndefined).render(**self.config)})
        self.messages.append({"role": "user", "content": Template(self.config["instance_template"], undefined=StrictUndefined).render(**self.config)})
        while True:
            try:
                self.step()
            except Submitted as e:
                self.messages.append(e.message)
            if self.messages[-1]["role"] == "exit":
                break
    
    def step(self):
        ai_message = self.query()
        self.execute(ai_message)
    
    def query(self) -> dict:
        ai_message = self.model.query(self.messages)
        self.messages.append(ai_message)
        return ai_message

    def execute(self, message: dict):
        results = [self.env.execute(action) for action in message.get("extra").get("actions")]
        self.messages += self.model.format_toolcall_observation_results(message, results)
