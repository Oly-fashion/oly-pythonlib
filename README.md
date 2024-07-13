# Summary
Python libraries for the Oly Application

# Tooling Setup for Local Development
All instructions are for MacOS

You will need
- Brew
- Python 3.11
- Poetry

## Install Brew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## Install Pyenv

```bash
brew install pyenv
```

## Install Python 3.11

```bash
pyenv install 3.11
```

## Install Poetry

Set your python version before you install poetry
```bash
pyenv shell 3.11
```

Install Poetry
```bash
pip install poetry
```

## Install Pre-commit

```bash
brew install pre-commit
```

# Install Project

## Initialize python environment

You will run these two commands every time you open a new shell environment for this project.
The commands must be run in the project's root directory.

```bash
pyenv shell 3.11
poetry shell
```
## Install project dependencies

```bash
poetry install --sync --with=dev
```

## Setup Pre-commit

```bash
pre-commit install
```
