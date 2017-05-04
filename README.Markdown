Ed25519
=======

This is a portable implementation of [Ed25519](http://ed25519.cr.yp.to/) based
on the SUPERCOP "ref10" implementation. Additionally there is key exchanging
and scalar addition included to further aid building a PKI using Ed25519. All
code is licensed under the permissive zlib license.

License
-------
All code is released under the zlib license. See license.txt for details.

This repository
---------------
This repository is a command line utility to exercise [the original library](https://github.com/rdebath/ed25519/blob/devl/readme.md)


Usage
-----

    Usage: ed25519 [options]
    Options:
	-h FILE              # SHA512 of file's contents
	-H String            # SHA512 of string (no NL)
      
	-rk                  # Print matched private(seed) and public keys.
	-r                   # Print 32 random bytes in hex
	-k S..S              # Generate public key from seed key.
	-K S..S              # Generate private key from seed key.

	-s S..S FILE         # Create signature of file from seed key.
	-p X..X -v V..V FILE # Validate signature of file from public key.

	-h -s S..S FILE      # Create signature of SHA512 of FILE.
	-hpv X..X V..V FILE  # Validate signature of SHA512 of FILE.
     
    The S..S is the 64 hex digit secret seed key.
    The S..S is the 128 hex digit private key.
    The X..X is the 64 hex digit public key
    The V..V is the 128 hex digit signature for validating.
