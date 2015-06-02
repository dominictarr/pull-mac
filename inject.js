var Reader = require('pull-reader')
var deepEqual = require('deep-equal')

var split = require('split-buffer')
var through = require('pull-through')


module.exports = function (sodium, exports) {

  exports = exports || {}

  var hash = sodium.crypto_hash_sha256
  var auth = sodium.crypto_auth
  var verify = sodium.crypto_auth_verify

  var max = 4096

  var HASH_LEN = hash(new Buffer([0])).length
  var AUTH_LEN = auth(hash(new Buffer([0])), hash(new Buffer([1]))).length

  var AUTHED_LEN = 2+4+HASH_LEN
  var HEADER_LEN = AUTHED_LEN+AUTH_LEN

  //authenticate a single chunk
  function createHeader (chunk, count, secret) {
    if(chunk.length > max)
      throw new Error('chunk *must not* be longer than ' + max + ' bytes')

    var header = new Buffer(HEADER_LEN) //header with length, hash, hmac

    //write the chunk length, and packet counter.
    header.writeUInt16BE(chunk.length, 0)
    header.writeUInt32BE(count, 2)

    //write the hash of the chunk
    hash(chunk).copy(header, 6, 0, HASH_LEN)

    // authenticate the hash, length, count.
    auth(header.slice(0, AUTHED_LEN), secret)
      .copy(header, AUTHED_LEN, 0, HASH_LEN)

    return header
  }

  function verifyHeader (header, count, secret) {

    //check counter correct
    var _count = header.readUInt32BE(2)
    if(_count !== count)
      throw new Error('packet out of order, expected:' + count + ' found: ' + _count)

    //check no flipped bits!
    var head = header.slice(0, AUTHED_LEN)
    var mac  = header.slice(AUTHED_LEN, HEADER_LEN)
    if(0 !== verify(mac, head, secret))
      throw new Error('bits flipped in header')

    return {
      length: header.readUInt16BE(0),
      count: _count,
      hash:  header.slice(6, AUTHED_LEN)
    }
  }

  exports.createAuthStream = function (secret) {
    var i = 0
    return through(function (data) {
      var queue = this.queue
      //break data into max_len packets.
      var chunks = split(data, max)
      for(var j = 0; j < chunks.length; j++) {
        this.queue(createHeader(chunks[j], i++, secret))
        this.queue(chunks[j])
      }
    })
  }

  exports.createVerifyStream = function (secret) {
    var reader = Reader(), i = 0
    return function (read) {
      reader(read)
      return function (abort, cb) {
        reader.read(HEADER_LEN, function (err, header) {
          if(err) return cb(err)
          var parsed
          try {
            parsed = verifyHeader(header, i++, secret)
          } catch (err) {
            return cb(err)
          }
          reader.read(parsed.length, function (err, data) {
            if(err) return cb(err)
            if(!deepEqual(hash(data), parsed.hash))
              return cb(Error('flipped bits in body'))
            return cb(null, data)
          })
        })
      }
    }
  }

  return exports
}
