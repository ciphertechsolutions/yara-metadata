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

For use in CI you must run the tool in a different fashion.  When the hook is run locally it assumes all files passed to it have been updated (because that's generally how pre-commit works).
When pre-commit is run in ci it is generally used with --all-files, this ensures issues are caught even when a developer didn't have pre-commit setup locally.
To get around this we run a limited scope git history parse on the diff between the merge request branch and the target branch, this is the same strategy as with ``--initial``, 
but without going through potentially thousands of commits.  Merge request mode is automatically done when ``YARA_METADATA_BRANCH_FROM`` and ``YARA_METADATA_BRANCH_TO`` environment variables are set.
Values can be branch names, tags, or commits, for branches and tags you'll likely need to includes origin/ since CI doesn't always pull the all git information.


For consistent yara rule formatting use the yarax fmt command as a pre-commit hook by adding the following to your ``.pre-commit-config.yaml``

.. code-block::

    repos:
    - repo: https://github.com/ciphertechsolutions/yara-metadata
      rev: v1.0.0
      hooks:
      - id: yarax-format
        name: yarax-format
        args: ["-C", ".yara-x.toml", "fmt"]
