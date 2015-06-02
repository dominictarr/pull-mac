# pull-mac

add robust Message Authentication Codes to a binary pull-stream

## Example - send

``` js

var mac = require('pull-mac')
pull(
  dataStream1,
  mac.createAuthStream(secret),
  insecureTransportOut
)

```

## Example - receive

``` js

var mac = require('pull-mac')
pull(
  insecureTransportIn,
  mac.createVerifyStream(secret),
  dataStream2
)
```

`dataStream2` will either be exactly the same as `dataStream1`
or will have an error. Packet boundries may have changed if
packets in dataStream are longer than 4096 (4k) bytes.

Each packet is prepended with a header (auth) packet
that includes a length, sequence number, hash of the packet to follow,
and a hmac. If any bits are flipped (including in length)
the hmac will fail immediately.

Then the following packet is read, hashed, and the hash checked with
the authenticated hash.

To be secure you must use a different secret for every stream.
And of course, the authenticating and validating secrets must be the same.

## License

MIT
