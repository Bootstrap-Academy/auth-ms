def _get_version() -> str:
    import tomllib
    from pathlib import Path
    from typing import cast

    with Path(__file__).parent.parent.joinpath("pyproject.toml").open("rb") as file:
        return cast(str, tomllib.load(file)["tool"]["poetry"]["version"])


__version__ = _get_version()
