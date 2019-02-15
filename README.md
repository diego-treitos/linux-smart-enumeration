# linux-smart-enumeration
Linux enumeration tools for pentesting and CTFs

This project was inspired by https://github.com/rebootuser/LinEnum and uses
many of its tests.

Unlike LinEnum, `lse` tries to gradualy expose the information depending on its importance from a privesc point of view.

## What is it?

This script will show relevant information about the security of the local Linux system.

It has 3 levels of verbosity so you can control how much information you see.

In the default level you should see the highly important security flaws in the system. The level `1` (`./lse.sh -l1`) shows
interesting information that should help you to privesc. The level `2` (`./lse.sh -l2`) will just dump all the information it
gathers about the system.

By default it will ask you some questions: mainly the current user password (if you know it ;) so it can do some additional tests.

## How to use it?

The idea is to get the information gradually.

First you should execute it just like `./lse.sh`. If you see some green `yes!`, you probably have already some good stuff to work with.

If not, you should try the `level 1` verbosity with `./lse.sh -l1` and you will see some more information that can be interesting.

If that does not help, `level 2` will just dump everything you can gather about the service using `./lse.sh -l2`.
