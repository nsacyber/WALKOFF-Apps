Usage:
======

Merge the provided folders into your WALKOFF directory, with the demo logs, graphs, etc. in the root of the WALKOFF directory.
```
e.g.:

bro_netmap_interface
├── apps
│   ├── Bro
│   └── AlienVault
├── interfaces
│   └── Bro
├── workflows
├── dns.log
└── http.log

Merged into the WALKOFF directory would look like:

WALKOFF
├── apps
│   ├── HelloWorld
│   ├── DailyQuote
│   ├── Utilities
│   ├── Walkoff
│   ├── Bro
│   └── AlienVault
├── interfaces
│   ├── Sample
│   ├── HelloWorld
│   └── Bro
├── workflows
├── walkoff.py
├── dns.log
├── http.log
└── etc.
```

Then, run WALKOFF (ensure that no errors are thrown\*), and execute the provided workflow.

Finally, open the Bro interface in WALKOFF to examine the stacked results, and check messages for any notifications.

(As WALKOFF is being constantly developed and updated, these demos may break - if they have not been updated or if there are any issues, let us know.)

