### Background

Alice is a Bitcoinj variant that provides additional functionality:

* support for arbitrary HD paths (BIP44 etc)

The intention is after proving the viability of the code that the changes will be pushed upstream to the main Bitcoinj
so that the code can be used by others.

### Alice update instructions

Alice tracks the upstream Bitcoinj as closely as possible so the patching process is as follows:

1. Clone Alice locally 

`git clone https://github.com/bitcoin-solutions/bitcoinj-alice`

2. Add a remote repo `upstream` to link it to Bitcoinj

`git remote add upstream https://github.com/bitcoinj/bitcoinj.git`

3. Fetch all the branches of that remote into remote-tracking branches, such as upstream/master:

`git fetch upstream`

4. Switch to the `master` branch (Bitcoinj uses it as the equivalent of `develop` in Git Flow process)

`git checkout master`

5. Rewrite `master` so that any commits of yours that aren't already in `upstream/master` are replayed over the upstream changes:

`git rebase upstream/master`

6. Force push your local changes up to `origin/master`

`git push -f origin master`

