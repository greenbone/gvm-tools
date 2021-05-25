# Release instructions

Before creating a new release please do a careful consideration about the
version number for the new release. We are following [Calendar Versioning](https://calver.org)
and [PEP440](https://www.python.org/dev/peps/pep-0440/).

## Preparing the Required Python Packages

* Install development dependencies

  ```sh
  poetry install
  ```

* Install twine for pypi package uploads

  ```sh
  python3 -m pip install --user --upgrade twine
  ```

## Configuring the Access to the Python Package Index (PyPI)

*Note:* This is only necessary for users performing the release process for the
first time.

* Create an account at [Test PyPI](https://packaging.python.org/guides/using-testpypi/).

* Create an account at [PyPI](https://pypi.org/).

* Create a pypi configuration file `~/.pypirc` with the following content (Note:
  `<username>` must be replaced):

  ```ini
  [distutils]
  index-servers =
      pypi
      testpypi

  [pypi]
  username = <username>

  [testpypi]
  repository = https://test.pypi.org/legacy/
  username = <username>
  ```

## Create a GitHub Token for uploading the release files

This step is only necessary if the token has to be created for the first time or
if it has been lost.

* Open Github Settings at https://github.com/settings/tokens
* Create a new token
* Copy token and store it carefully
* Export token and GitHub user name in your current shell

  ```sh
  export GITHUB_TOKEN=<token>
  export GITHUB_USER=<name>
  ```


## Prepare testing the to be released version

* Fetch upstream changes

  ```sh
  git remote add upstream git@github.com:greenbone/gvm-tools.git
  git fetch upstream
  git rebase update/master
  ```

* Get the current version number

  ```sh
  poetry run python -m pontos.version show
  ```

* Update the version number to some dev version e.g.

  ```sh
  poetry run python -m pontos.version update 20.8.2dev1
  ```

## Uploading to the PyPI Test Instance

* Create a source and wheel distribution:

  ```sh
  rm -rf dist build python_gvm.egg-info
  poetry build
  ```

* Upload the archives in `dist` to [Test PyPI](https://test.pypi.org/):

  ```sh
  twine upload -r testpypi dist/*
  ```

* Check if the package is available at <https://test.pypi.org/project/gvm-tools>.

## Testing the Uploaded Package

* Create a test directory:

  ```sh
  mkdir gvm-tools-install-test
  cd gvm-tools-install-test
  python3 -m venv test-env
  source test-env/bin/activate
  pip install -U pip  # ensure the environment uses a recent version of pip
  pip install --pre -I --extra-index-url https://test.pypi.org/simple/ gvm-tools
  ```

* Check install version with a Python script:

  ```sh
  python3 -c "from gvm import __version__; print(__version__)"
  ```

* Remove test environment:

  ```sh
  deactivate
  cd ..
  rm -rf gvm-tools-install-test
  ```

## Prepare the Release

* Run pontos-release prepare

  ```sh
  poetry run pontos-release --release-version <version> --next-release-version <dev-version> --project gvm-tools --space greenbone --git-signing-key <your-public-gpg-key> --git-remote-name upstream prepare
  ```

* Check git log and tag

  ```
  git log -p

  # is the changelog correct?
  # does the version look right?
  # does the tag point to the correct commit?
  ```

* If something did go wrong delete the tag, revert the commits and remove the
  temporary file for the release changelog

  ```
  git tag -d v<version>
  git reset <last-commit-id-before-running-pontos-release> --hard
  rm .release.txt.md
  ```

## Create the Release

* Run pontos-release release

  ```sh
  poetry run pontos-release --release-version <version> --next-release-version <dev-version> --project gvm-tools --space greenbone --git-signing-key <your-public-gpg-key> --git-remote-name upstream release

## Uploading to the 'real' PyPI

* Uploading to PyPI is done automatically after creating a release via GitHub
  Actions

* Check if new version is available at <https://pypi.org/project/gvm-tools>.

## Check the Release

* Check the Github release:

  See https://github.com/greenbone/gvm-tools/releases
