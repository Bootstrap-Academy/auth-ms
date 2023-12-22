[![check](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/check.yml/badge.svg)](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/check.yml)
[![test](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/test.yml/badge.svg)](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/test.yml)
[![build](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/build.yml/badge.svg)](https://github.com/Bootstrap-Academy/auth-ms/actions/workflows/build.yml) <!--
https://app.codecov.io/gh/Bootstrap-Academy/auth-ms/settings/badge
[![codecov](https://codecov.io/gh/Bootstrap-Academy/auth-ms/branch/develop/graph/badge.svg?token=changeme)](https://codecov.io/gh/Bootstrap-Academy/auth-ms) -->
![Version](https://img.shields.io/github/v/tag/Bootstrap-Academy/auth-ms?include_prereleases&label=version)

# Bootstrap Academy Auth Microservice
The official auth microservice of [Bootstrap Academy](https://bootstrap.academy/).

If you would like to submit a bug report or feature request, or are looking for general information about the project or the publicly available instances, please refer to the [Bootstrap-Academy repository](https://github.com/Bootstrap-Academy/Bootstrap-Academy).

## Development Setup
1. Install [Python 3.11](https://python.org/), [Poetry](https://python-poetry.org/) and [poethepoet](https://pypi.org/project/poethepoet/).
2. Clone this repository and `cd` into it.
3. Run `poe setup` to install the dependencies.
4. Start a [PostgreSQL](https://www.postgresql.org/) database, for example using [Docker](https://www.docker.com/) or [Podman](https://podman.io/):
    ```bash
    podman run -d --rm \
        --name postgres \
        -p 127.0.0.1:5432:5432 \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        postgres:alpine
    ```
5. Create the `academy-auth` database:
    ```bash
    podman exec postgres \
        psql -U postgres \
        -c 'create database "academy-auth"'
    ```
6. Start a [Redis](https://redis.io/) instance, for example using [Docker](https://www.docker.com/) or [Podman](https://podman.io/):
    ```bash
    podman run -d --rm \
        --name redis \
        -p 127.0.0.1:6379:6379 \
        redis:alpine
    ```
7. Run `poe migrate` to run the database migrations.
8. Run `poe api` to start the microservice. You can find the automatically generated swagger documentation on http://localhost:8000/docs.

## Poetry Scripts
```bash
poe setup           # setup dependencies, .env file and pre-commit hook
poe api             # start api locally
poe test            # run unit tests
poe pre-commit      # run pre-commit checks
  poe lint          # run linter
    poe format      # run auto formatter
      poe isort     # sort imports
      poe black     # reformat code
    poe ruff        # check code style
    poe mypy        # check typing
    poe flake8      # check code style
  poe coverage      # run unit tests with coverage
poe alembic         # use alembic to manage database migrations
poe migrate         # run database migrations
poe env             # show settings from .env file
poe jwt             # generate a jwt with the given payload and ttl in seconds
poe hash-password   # hash a given password using argon2
```

## PyCharm configuration
Configure the Python interpreter:

- Open PyCharm and go to `Settings` ➔ `Project` ➔ `Python Interpreter`
- Open the menu `Python Interpreter` and click on `Show All...`
- Click on the plus symbol
- Click on `Poetry Environment`
- Select `Existing environment` (setup the environment first by running `poe setup`)
- Confirm with `OK`

Setup the run configuration:

- Click on `Add Configuration...` ➔ `Add new...` ➔ `Python`
- Change target from `Script path` to `Module name` and choose the `api` module
- Change the working directory to root path  ➔ `Edit Configurations`  ➔ `Working directory`
- In the `EnvFile` tab add your `.env` file
- Confirm with `OK`
