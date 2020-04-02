const crypto = require('crypto');


const message = "message";

const keyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: {
        type: 'spki',
        format: 'der'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der'
    }
})

const signer = crypto.createSign("ec")