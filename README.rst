=============
yara-metadata
=============

Pre-commit hook for maintaining updates to yara rules


* Free software: MIT license


Features
--------

* Parse commit history to find when rules were created and last modified
* Update the last modified field automatically when rules are changed via pre-commit
* Yara-x formatting via pre-commit

Usage
-----


For your first run use the ``--initial`` flag to parse the entire git history.  Combine this with ``--hash`` and check your results for any hashes that changed all files (such as project restructuring).

Take hashes from ``--hash`` that you do not want in your history and add them to the ``--ignored-hashes`` list until you get the intended result.

Run with ``pre-commit run --all-files`` with the following ``.pre-commit-config.yaml``

Once you process all your yara files the first time commit them and then add the commit hash to the ``--ignored-hashes`` list.

.. code-block::

    repos:
    - repo: https://github.com/ciphertechsolutions/yara-metadata
      rev: v1.0.0
      hooks:
      - id: yara-metadata
        name: yara-metadata
        args: [
          "--initial",
          "--ignored-hashes", "84c7193de60aedd62e45f8b1c0e4a580ae1b872d",
          "--ignored-hashes", "dc5f89a76cd713f064c9c217c5a0b28fa36a92c7",
          "--hash"
        ]

After your initial run and commit you should be able to remove the ``--initial`` ``--hash`` and ``--ignored-hashes`` options.

.. code-block::

    repos:
    - repo: https://github.com/ciphertechsolutions/yara-metadata
      rev: v1.0.0
      hooks:
      - id: yara-metadata
        name: yara-metadata

For consistent yara rule formatting use the yarax fmt command as a pre-commit hook by adding the following to your ``.pre-commit-config.yaml``

.. code-block::

    repos:
    - repo: https://github.com/ciphertechsolutions/yara-metadata
      rev: v1.0.0
      hooks:
      - id: yarax-format
        name: yarax-format
        args: ["-C", ".yara-x.toml", "fmt"]

Code indentation issues
-----------------------

At the time of writing this yara-x version 1.6.0 has issues formatting tabs to spaces in multiline comments.  Yaramod (the tool used to insert/manage metadata in rules) only outputs with tabs.
This interaction between the two can cause formatting issues.  Until this behavior is fixed you can use another pre-commit hook to turn the yaramod tabs back into spaces using the following configuration.

.. code-block::

- repo: https://github.com/ciphertechsolutions/yara-metadata
  rev: v1.0.0
  hooks:
    - id: yara-metadata
      name: yara-metadata
      args: [
        "--initial",
        "--ignored-hashes", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--ignored-hashes", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      ]
- repo: https://github.com/Lucas-C/pre-commit-hooks
  rev: v1.5.5
  hooks:
    - id: remove-tabs
      files: ".yara$|.yar$"
- repo: https://github.com/ciphertechsolutions/yara-metadata
  rev: v1.0.0
  hooks:
    - id: yarax-format
      name: yarax-format
      args: ["-C", "src/acce_parsers/resources/rules/.yara-x.toml", "fmt"]
