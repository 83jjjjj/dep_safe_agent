
import typer
import logging

from depsafe.agent import DepSafeAgent

app = typer.Typer()


@app.command()
def main(
    task: str = typer.Option(..., "-t", "--task", help="Task/problem statement", show_default=False, prompt=True),
) -> DepSafeAgent:
    logging.basicConfig(level=logging.DEBUG)
    agent = DepSafeAgent()
    agent.run(task)
    return agent


if __name__ == "__main__":
    app() 