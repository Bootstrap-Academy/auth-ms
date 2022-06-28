<p>

  [![CI](https://github.com/Bootstrap-Academy/backend/actions/workflows/ci.yml/badge.svg)](https://github.com/Bootstrap-Academy/backend/actions/workflows/ci.yml)
  [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

</p>

# backend

Bootstrap Academy backend

## Development

### Prerequisites
- [Python 3.10](https://python.org/)
- [Poetry](https://python-poetry.org/) + [poethepoet](https://pypi.org/project/poethepoet/)
- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/) + [docker-compose](https://docs.docker.com/compose/) (recommended)
- [PyCharm Community/Professional](https://www.jetbrains.com/pycharm/) (recommended)

### Clone the repository

#### SSH (recommended)
```bash
git clone --recursive git@github.com:Defelo/fastapi-template.git
```

#### HTTPS
```bash
git clone --recursive https://github.com/Defelo/fastapi-template.git
```

### Setup development environment

After cloning the repository, you can setup the development environment by running the following command:

```bash
poe setup
```

This will create a virtual environment, install the dependencies, create a `.env` file and install the pre-commit hook.

### PyCharm configuration

- Open PyCharm and go to `Settings` ➔ `Project` ➔ `Python Interpreter`
- Open the menu `Python Interpreter` and click on `Show All...`
- Click on the plus symbol
- Click on `Poetry Environment`
- Select `Existing environment` (setup the environment first by running `poe setup`)
- Confirm with `OK`
- Change the working directory to root path  ➔ `Edit Configurations`  ➔ `Working directory`
