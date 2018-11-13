# Release instructions

Before creating a new release please do a careful consideration about the
version number for the new release. We are following [Semantic Versioning](https://semver.org/)
and [PEP440](https://www.python.org/dev/peps/pep-0440/).

* Install twine for pypi package uploads and update setuptools, pipenv and wheel packages

  ```sh
  python3 -m pip install --user --upgrade twine setuptools wheel pipenv
  ```

* Fetch upstream changes and create release branch

  ```sh
  git fetch upstream
  git checkout -b create-new-release upstream/master
  ```

* Open [gvmtools/__init__.py](https://github.com/greenbone/gvm-tools/blob/master/gvmtools/__init__.py)
  and increment the version number.

* Update [CHANGELOG.md](https://github.com/greenbone/gvm-tools/blob/master/CHANGELOG.md)

* Create a source and wheel distribution

  ```sh
  rm -rf dist build python_gvm.egg-info
  pipenv install
  pipenv run python setup.py sdist bdist_wheel
  ```

* Create a git commit

  ```sh
  git add .
  git commit -m "Prepare release <version>"
  ```

* Create an account at [Test PyPI](https://packaging.python.org/guides/using-testpypi/)

* Upload the archives in dist to [Test PyPI](https://test.pypi.org/)

  ```sh
  twine upload --repository-url https://test.pypi.org/legacy/ dist/*
  ```

* Check if the package is available at https://test.pypi.org/project/gvm-tools

* Create a test directory

  ```sh
  mkdir gvm-tools-install-test
  cd gvm-tools-install-test
  pipenv run pip install --pre -I --extra-index-url https://test.pypi.org/simple/ gvm-tools
  ```

* Check install version with a python script

  ```sh
  pipenv run python -c "from gvmtools import get_version; print(get_version())"
  ```

* Remove test environment

  ```sh
  pipenv --rm
  cd ..
  rm -rf gvm-tools-install-test
  ```

* Create an account at [PyPI](https://pypi.org/) if not exist already

* Upload to real [PyPI](https://pypi.org/)

  ```sh
  twine upload dist/*
  ```

* Check if new version is available at https://pypi.org/project/gvm-tools

* Create a git tag

  ```sh
  git tag v<version>
  ```

  or even signed with your gpg key

  ```sh
  git tag -s v<version>
  ```

* Update version in [gvmtools/__init__.py](https://github.com/greenbone/gvm-tools/blob/master/gvmtools/__init__.py)

  Use a development version like `(1, 0, 0, 'beta', 1, 'dev', 1)` or
  `(1, 1, 0, 'dev', 1)`

* Create a commit

  ```sh
  git commit -m "Update version after <version> release"
  ```

* Push changes and tag to Github

  ```sh
  git push --tags upstream master
  ```

* Create a Github release

  See https://help.github.com/articles/creating-releases/
