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

## Protocol

### Authentication

for every incoming packet, if it's longer than 4k split into chunks 4k
or less bytes long. Then for each chunk, prepend a header:


The header is separated into an authenticated section, and a authenticator
(hmac). The header is always a fixed size, `2 + 4 + 32 + 32 = 70` bytes.

``` js
[
 Authed = [
    incrementing counter, (4 bytes: 32 bit big endian unsigned integer)
    chunk length, (2 bytes: 16 bit bigendian unsigned integer)
    hash (chunk), (32 bytes, sha256)
  ],
  Auth: hmac(authed, secret) (32 bytes: hmac-sha256)
]
```

If any bits where flipped then a mac error will be detected.

The header and the following chunk can then be sent.
The counter is incremented for the next chunk.

### Verification

read 70 bytes from the input to get the authenticated header,
then take the first 38 bytes to get the authed header, and verify
that it matches the last 32 bytes in the header, else fail with mac error.

Check the packet counter is the expected value.

Take the length field, and read that many bytes from the input.
Hash this, and check it matches the hash in bytes 6-38 of the header,
if it does, pass this chunk to the user, else fail with mac error.

## Properties

If an attacker flips any bytes in a header it will immediately produce a mac
error. The verifier always reads a fixed number of bytes before verifying,
so an attacker cannot trick the verifier into reading more than than the
authenticator intended.

(see also: [https://github.com/calvinmetcalf/hmac-stream/issues/5](denial of service via malleable length in streaming hmac))

## License

MIT
