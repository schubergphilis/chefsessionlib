=====
Usage
=====


To develop on chefsessionlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scripts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scripts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use chefsessionlib in a project:

.. code-block:: python

    from chefsessionlib import ChefSession
    username = 'dummy_user'
    private_key_contents = 'Private RSA Key contents here...'
    session = ChefSession(username, private_key_contents)
    response = session.get('some url from chef server')
