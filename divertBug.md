## The grasp.py O_DIVERT fix of 20220316

Parsa Ghaderi (Concordia University) reported that only one relayed
discovery result is delivered, even when there are multiple hosts
supporting the required objective beyond the relay.

My test network being too small to observe this (diagram below),
I simulated the problem by patching the code in _mchandler that builds
and sends a M_RESPONSE message to send a second one with a different
(bogus) IPv6 address. That version of grasp.py is called grasp-fake2.py.
I also made a version of the Gray.py demo ASA to display multiple
discovered locators (if any). That's Gray-fake2.py.

[Briggs and Gray are a pair of demo ASAs that work together.]

This reproduced the problem - the second locator was *not* discovered
via the relay, but it was discovered in the relay machine.

This is probably a very old bug since I never had a test network big
enough to detect it.

Then I started looking at the code and studying test mode logs.

First issue: the format of M_RESPONSE messages containing an O_DIVERT
option proved to be wrong on the wire, i.e. not conforming to RFC8990.

Wire format of the O_DIVERT was:

[[O_DIVERT, [[O_IPv6_LOCATOR,...], [O_IPv6_LOCATOR,...]]]]

According to RFC8990, it should be:

[O_DIVERT, [O_IPv6_LOCATOR,...], [O_IPv6_LOCATOR,...]]

This error concealed several others, so the fix involved the following:

_ass_message() simply did not insert an O_DIVERT option correctly;
it used to work by luck, because of a catch-all at the end of
message assembly.

_parse_opt() had a blatant Python bug such it only handled the first
entry in an O_DIVERT.

_opt_to_asa_loc() had some rubbish code that was never executed because
of the other errors.

_mchandler failed to use grasp.py's _option class when building the option.
That was really the biggest problem since all the other code relied on
that class.

_mchandler therefore created the elaborate and incorrect wire format
shown above.

While studying this code and running tests on the fixes, I noticed
that the discover() API call sometimes returned duplicate responses.
That was because _drloop(), which stores discovered locators in
the discovery cache, did not check for duplicate entries. This bug
was hidden by the O_DIVERT bug. So I fixed this too.

(This issue of duplicate discovery cache entries is not discussed
in RFC8990, because it is not a protocol issue. But all
implementations need to handle it.)

~~~~

  remote node         relay node           user node

 -------------        -------------        -------------
 | R-PI      |        | Linux     |        | Windows   |
 | running   |________| running   |________| running   |
 | grasp-fake2        | Gray-fake2|        | Gray-fake2|
 | + Briggs  |        |           |        |           |
 -------------        -------------        -------------

 responds with         2 locators           1 locator
 2 locators            discovered           discovered

~~~~