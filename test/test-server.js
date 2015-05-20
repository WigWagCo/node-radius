var radius = require('../lib/radius');
var dgram = require("dgram");


// this does not work with UniFi AP and probably most RADIUS defaults
// 

// AVP: l=10  t=User-Name(1): jlpicard
// AVP: l=15  t=EAP-Message(79) Last Segment[1]
// AVP: l=18  t=Message-Authenticator(80): 48518a9fd8c7a92a5fe34cd7bdf9f7ac

// The Message-Authenticator is the password. node-radius does not support this
// but the library does have the decode function for this hash

// See: http://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/118673-technote-radius-00.html#anc7




//var secret = 'radius_secret';
var secret = 'test1234';
var server = dgram.createSocket("udp4");

server.on("message", function (msg, rinfo) {
  var code, username, password, packet;
  packet = radius.decode({packet: msg, secret: secret});

  if (packet.code != 'Access-Request') {
    console.log('unknown packet type: ', packet.code);
    return;
  }

  username = packet.attributes['User-Name'];
  password = packet.attributes['User-Password'];

  console.log('Access-Request for ' + username + " pass:" + password );

  if (username == 'jlpicard' && password == 'beverly123') {
    code = 'Access-Accept';
  } else {
    code = 'Access-Reject';
  }

  var response = radius.encode_response({
    packet: packet,
    code: code,
    secret: secret
  });

  console.log('Sending ' + code + ' for user ' + username);
  server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, bytes) {
    if (err) {
      console.log('Error sending response to ', rinfo);
    }
  });
});

server.on("listening", function () {
  var address = server.address();
  console.log("radius server listening " +
      address.address + ":" + address.port);
});

server.bind(1812);

