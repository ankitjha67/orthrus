"""Enable ``python -m orthrus`` (and serve as the PyInstaller entry point)."""

from orthrus.main import cli

if __name__ == "__main__":
    cli()
