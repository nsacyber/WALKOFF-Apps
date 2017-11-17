pyvas: OMPv7 for Python
=======================

|Build Status| |Coverage|

An OpenVAS Managment Protocol (OMP) v7+ client for Python.

Installation
------------

To install pyvas, simply run:

.. code-block:: bash
    
    $ pip install pyvas

Usage
-----

.. code-block:: python
    
    >>> from pyvas import Client
    >>> with Client(hostname, username='username', password='password') as cli:
    >>>     r = cli.list_tasks()
    >>>     r.ok
    True
    >>>     r.data
    [{u'@id': '...', ...}, {u'@id': '...', ...}]
    >>>     r = cli.get_task(task[0]["@id"])
    >>>     r.ok
    True
    >>>     r.data
    {u'@id': '...', ...}

Documentation
-------------

Documentation is currently a work in progress, please check back soon.


How to Contribute
-----------------

#. Look for open issues or report an issue
#. Checkout a new branch from master and work away
#. Remember to include tests 
#. Submit a pull request!

.. |Build Status| image:: https://travis-ci.org/mpicard/pyvas.svg?branch=master
   :target: https://travis-ci.org/mpicard/pyvas

.. |Coverage| image:: https://coveralls.io/repos/github/mpicard/pyvas/badge.svg
    :target: https://coveralls.io/github/mpicard/pyvas
