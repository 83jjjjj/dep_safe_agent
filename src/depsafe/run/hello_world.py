import logging

import typer

from depsafe.agent import DepSafeAgent

app = typer.Typer()


@app.command()
def main(
    task: str | None = typer.Option(None, "-t", "--task", help="Task description (omit to auto-scan current project)"),
) -> DepSafeAgent:
    logging.basicConfig(level=logging.DEBUG)
    try:
        agent = DepSafeAgent()
    except RuntimeError as e:
        typer.echo(f"❌ {e}", err=True)
        raise typer.Exit(code=1)
    agent.run(task)
    return agent


if __name__ == "__main__":
    app()
