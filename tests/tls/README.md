# tls fixtures

a test certificate authority (`ca.pem`) and a certificate it signed for
`127.0.0.1` (`server.pem`, with its key in `server.key`). the tests in
`src/source/reading.rs` serve https with them, to check that `collect` trusts
the certificates in `SSL_CERT_FILE` instead of the ones divinate ships with.
both certificates are valid until the end of 9999, and the authority’s key
wasn’t kept.

to make new ones, with openssl 3.5 or later:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout ca.key -out ca.pem -subj '/CN=divinate test ca' \
  -not_after 99991231235959Z \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign'
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout server.key -out server.pem -subj '/CN=127.0.0.1' \
  -CA ca.pem -CAkey ca.key -not_after 99991231235959Z \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'extendedKeyUsage=serverAuth' \
  -addext 'subjectAltName=IP:127.0.0.1'
rm ca.key
```
