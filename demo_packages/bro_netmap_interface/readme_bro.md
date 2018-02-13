Usage:
======

Merge the provided folders into your WALKOFF directory, with the demo logs, graphs, etc. in the root of the WALKOFF directory.

Then, run WALKOFF (ensure that no errors are thrown\*), and execute the provided workflow.

Finally, open the Bro interface in WALKOFF to examine the stacked results, and check messages for any notifications.

(As WALKOFF is being constantly developed and updated, these demos may break - if they have not been updated or if there are any issues, let us know.)

Demo Specific Notes
===================

The included AlienVault OTX indicators have been modified from the source to include a dummy indicator for the interface.

The provided Bro logs have been modified from their original source to include requests that match the aforementioned dummy indicator.

The interface will utilize the sample data by default and can be accessed immediately without running a workflow. You can run the provided workflow on your own Bro logs as well. Bro can turn a pcap packet capture into logs with `bro -r name.pcap`. More information and options are available on the Bro website.

The provided Workflow will work as-is if all files are copied over. The AlienVault app action "download indicators" (detached from the workflow by default) will require you to create a WALKOFF device with an AlienVault OTX API key (comes with creation of a free account on their website).