
var assert = require('assert');

function as_proof(req) {
    let asreq = req.body;
    assert (asreq.keys && asreq.resources);
    if (asreq.keys.proof === 'mtls') {
        let cert = req.headers['SSL_CLIENT_CERT'];
        if (!cert) {
            cert = req.socket.getPeerCertificate(true);
        }
        if (!cert.raw) {
            throw "no client certificate"
        }
        return Promise.value(cert);
    } else if (asreq.keys.proof === 'httpsign') {
        throw "httpsign is not implemented"
    } else if (asreq.keys.proof === 'test' && TEST_MODE === 'true') {
        proof_ok = true;
    } else {
        throw "no supported proof method"
    }
}

export function transact(req, ) {
    as_proof(req).then()
}