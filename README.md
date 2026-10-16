# SpacePoW

> Because captchas are overrated.

## Why?

We need automated way to limit requests / make them more difficult in a way in which we won't require user input. PoW was proven sucessful at least partially and offers a semi-reasonable way of verifying the requests are are not flooding in.

End goal is to allow server to respond with 402 request that will require some computational work - resulting in both

- limit of requests
- possibly banning simple DoS attacks (or increasing the cost of such)
- not actually banning any individual IP
- still working over anonymous networks where origin of a request is not known
- cheap to generate in memory
- cheap to check