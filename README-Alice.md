### Background

Alice is a Bitcoinj variant that provides additional functionality:

* support for arbitrary HD paths (BIP44 etc)

The intention is after proving the viability of the code that the changes will be pushed upstream to the main Bitcoinj
so that the code can be used by others.

### Alice update instructions

Alice tracks the upstream Bitcoinj as closely as possible so the patching process is as follows:

1. Clone Alice locally 

`git clone https://github.com/bitcoin-solutions/bitcoinj-alice`

2. Add a remote repo `bitcoinj-canonical` to link it to Bitcoinj

`git remote add bitcoinj-canonical https://github.com/bitcoinj/bitcoinj.git`

3. Fetch all the branches of that remote into remote-tracking branches, such as bitcoinj-canonical/master:

`git fetch bitcoinj-canonical`

4. Switch to the `master` branch (Bitcoinj uses it as the equivalent of `develop` in Git Flow process)

`git checkout master`


5. Checkout the alice develop branch
`git checkout develop`
or
`git checkout -b develop` # to create

6. Merge in the bitcoinj-canonical/master (which is their 'current development' branch)
`git merge bitcoinj-canonical/master`

7. Keep a list of ALL files that are changed.
   Fix merge errors. Run all the Junit tests. Check that MBHD develop branch works with the alice develop snapshot.

8.a Once all changes are acceptable, merge alice develop into alice master.
`git checkout master`
'git merge develop`


ALTERNATE MERGE PROCEDURE
#5. Rewrite `master` so that any commits of yours that aren't already in `bitcoinj-canonical/master` are replayed over the bitcoinj-canonical changes:
#
#`git rebase bitcoinj-canonical/master`
#
#6. Force push your local changes up to `origin/master`
#
#`git push -f origin master`