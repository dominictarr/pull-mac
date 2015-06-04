

var tape = require('tape')
var pull = require('pull-stream')
var crypto = require('crypto')
var mac = require('../')
var split = require('pull-randomly-split')

var input = [], l = 1024

while(l--)
  input.push(crypto.randomBytes(1024))

tape('validate and verify a stream', function (t) {

  var key = crypto.randomBytes(32)

  pull(
    pull.values(input),
    mac.createAuthStream(key),
    split(),
    mac.createVerifyStream(key),
    pull.collect(function (err, output) {
      if(err) throw err
      t.deepEqual(output, input)
      t.end()
    })
  )

})

tape('protect against a bitflipper', function (t) {

  var key = crypto.randomBytes(32)

  pull(
    pull.values(input),
    mac.createAuthStream(key),
    pull.map(function (data) {

      if(Math.random() < 0.1) {
        var rbit = 1<<(8*Math.random())
        var i = ~~(Math.random()*data.length)
        data[i] = data[i]^rbit
      }

      return data

    }),
    mac.createVerifyStream(key),
    pull.collect(function (err, output) {
      t.ok(err)
      t.notEqual(output.length, input.length)
      t.end()
    })
  )

})

function rand(i) {
  return ~~(i*Math.random())
}

tape('protect against reordering', function (t) {

  var key = crypto.randomBytes(32)

  pull(
    pull.values(input),
    mac.createAuthStream(key),
    pull.collect(function (err, valid) {
      //randomly switch two blocks
      var invalid = valid.slice()
      //since every even packet is a header,
      //moving those will produce valid messages
      //but the counters will be wrong.
      var i = rand(valid.length/2)*2
      var j = rand(valid.length/2)*2
      invalid[i] = valid[j]
      invalid[i+1] = valid[j+1]
      invalid[j] = valid[i]
      invalid[j+1] = valid[i+1]
      pull(
        pull.values(invalid),
        mac.createVerifyStream(key),
        pull.collect(function (err, output) {
          t.notEqual(output.length, input.length)
          t.ok(err)
          console.log(err)
          t.end()
        })
      )
    })
  )
})

tape('detect a premature hangup', function (t) {

  var input = [
    new Buffer('I <3 TLS\n'),
    new Buffer('...\n'),
    new Buffer("NOT!!!")
  ]

  var key = crypto.randomBytes(32)

  pull(
    pull.values(input),
    mac.createAuthStream(key),
    pull.take(4), //header packet header packet.
    mac.createVerifyStream(key),
    pull.collect(function (err, data) {
      console.log(err)
      t.ok(err) //expects an error
      t.equal(data.join(''), 'I <3 TLS\n...\n')
      t.end()
    })
  )
})
