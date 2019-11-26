
const express = require('express');
const https = require('https');
const http = require('http');
const chokidar = require('chokidar');
const cors = require('cors');
const fs = require('fs');
const bodyParser = require('body-parser');
const hex_sha1 = require('./sha1.js');
const fetch = require('node-fetch');
const x509 = require('@ghaiklor/x509');
const BigInt = require('BigInt');
const jose = require('jose');
const { transform } = require('camaro');


const HOST = process.env.HOST || "0.0.0.0";
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || "";
const MDQ_SERVER = process.env.MDQ_SERVER;
const KEYSTORE = process.env.KEYSTORE || "keystore.jwks";
const AUDIENCE = process.env.AUDIENCE;
const TEST_MODE = process.env.TEST_MODE || "false"; // This is dangerous and turns off security - only for debugging
const EXPIRES_IN = process.env.EXPIRES_IN || "10d";

const template = {
  'keys': ['.//md:KeyDescriptor', {'use': '@use', 'cert': './/ds:X509Certificate'}]
};

const app = express();
app.use(bodyParser.json());

function _sha1_id(s) {
    return "{sha1}"+hex_sha1(s);
}

let keystore = undefined;
if (fs.existsSync(KEYSTORE)) {
    keystore = jose.JWKS.asKeyStore(JSON.parse(fs.readFileSync(KEYSTORE)))
} else {
    keystore = new jose.JWKS.KeyStore();
    keystore.generateSync('EC', 'P-256');
    fs.writeFileSync(KEYSTORE, JSON.stringify(keystore.toJWKS(true)));
}

const signing_key = keystore.get();

function xml_mdq_get(id, mdq_url) {
    let opts = {method: 'GET', headers: {'Accept':'application/samlmetadata+xml'}};
    let url = mdq_url + '/' + id;
    return fetch(url, opts).then(function (response) {
        if (response.status == 404) {
           throw new URIError(`${url}: not found`);
        }
        return response;
    }).then(function (response) {
        let contentType = response.headers.get("content-type");
        if(contentType && contentType.includes("application/samlmetadata+xml")) {
            return response.text();
        }
        throw new SyntaxError("MDQ didn't provide an XML response");
    }).then(async function(text) {
        return await transform(text, template);
    }).then(entities => {
        entities.keys.forEach(key => {
            const pem = '-----BEGIN CERTIFICATE-----'+key.cert+'-----END CERTIFICATE-----';
            key.cert = x509.parseCert(pem);
        });
        return entities;
    });
}

function error(res, status, message) {
    res.status(status);
    res.send(JSON.stringify({'message': message, 'status': status}));
}

app.get('/.well-known/jwks.json', function(req, res) {
    return res.json(keystore.toJWKS(false));
});

app.get('/.well-known/jwk.json', function(req, res) {
    return res.json(signing_key.toJWK(false));
});

app.get('/.well-known/public.pem', function(req, res) {
    res.set('Content-Type', 'application/x-pem-file');
    res.send(signing_key.toPEM(false));
});

app.post('/transaction', function(req, res) {
    const asreq = req.body;
    try {
        if (!asreq.keys) {
            res.status(400).send('No key provided');
        }
        if (!asreq.keys.kid) {
            res.status(400).send('No key id provided');
        }
        const entity_id = asreq.keys.kid;
        const origins = asreq.resources.origins || [];
        console.log(origins);
        xml_mdq_get(_sha1_id(entity_id)+".xml", MDQ_SERVER).then(entity => {
            let proof_ok = false;
            if (asreq.keys.proof === 'mtls') {
                let cert = req.headers['SSL_CLIENT_CERT'];
                if (!cert) {
                    cert = req.socket.getPeerCertificate(true);
                }
                if (!cert.raw) {
                    throw "no client certificate"
                }
                proof_ok = entity.keys.some(key => {
                    return key.cert.fingerprint == cert.fingerprint;
                });
            } else if (asreq.keys.proof === 'httpsign') {
                throw "httpsign is not implemented"
            } else if (asreq.keys.proof === 'test' && TEST_MODE === 'true') {
                proof_ok = true;
            } else {
                throw "no supported proof method"
            }

            if (proof_ok) {
                let asrep = {};
                const payload = {'origins': origins};
                const options = {audience: AUDIENCE, expiresIn: EXPIRES_IN};
                let token = jose.JWT.sign(payload, signing_key, options);
                asrep.access_token = {'type': 'bearer', 'value': token};
                console.log(`OK:${entity_id}:${AUDIENCE}:${origins}`);
                return res.json(asrep);
            } else {
                throw "permission denied"
            }
        }).catch(ex => {
            console.log(JSON.stringify(asreq) + " -> " + ex);
            error(res, 401, `Permission denied: ${entity_id} not found or no valid proof supplied`);
        });
    } catch (err) {
        console.log(err);
        error(res, 500, `${err}`);
    }
});

if (process.env.SSL_KEY && process.env.SSL_CERT) {
    let options = {
        key: fs.readFileSync(process.env.SSL_KEY),
        cert: fs.readFileSync(process.env.SSL_CERT),
        requestCert: true,
        rejectUnauthorized: false
    };
    https.createServer(options, app).listen(PORT, function () {
        console.log(`HTTPS listening on ${HOST}:${PORT}`);
    });
} else {
    http.createServer(app).listen(PORT, function () {
        console.log(`HTTP listening on ${HOST}:${PORT}`);
    })
}
