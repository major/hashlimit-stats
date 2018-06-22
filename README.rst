hashlimit-stats
---------------

This script allows a user to query basic statistics from the iptables
hashlimit module. The hashlimit module populates files within
``/proc/sys/ipt_hashlimit/``. The filename is based on the name provided with
``--hashlimit-name`` when the hashlimit rule is created with ``iptables``.

If a hashlimit was created with the name ``http-limit``, you can run the
script like this:

.. code-block:: console:

    $ ./hashlimit-stats http-limit
    Total table entries: 123,602
    Entries allowed/disallowed: ✓ 1,536 ✗ 122,066

The output shows that there are 123,602 entries in the hashlimit table, and
only 1,536 of those entries are under the cap. If you have ``iptables``
configured to ``DROP`` packets that exceed the cap, then those allowed
entries are permitted through the firewall.

In the above example, the vast majority of the entries (122,066) will be
dropped by the firewall until more credit is available or the requester slows
their request rate.

Pull requests are welcome!

`-- Major`
