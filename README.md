# linux-smart-enumeration
Linux enumeration tools for pentesting and CTFs


## What is it?

This script will show relevant information about the security of the local Linux system.

It has 3 levels of verbosity so you can control how much information you see.

In the default level you should see the highly important security flaws in the system. The level `1` (`./lse.sh -l1`) shows
interesting information that should help you to privesc. The level `2` (`./lse.sh -l2`) will just dump all the information it
gathers about the system.

By default it will ask you some questions: mainly the current user password (if you know it ;) so it can do some additional tests.
