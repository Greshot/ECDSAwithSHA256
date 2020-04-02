const signButton = document.getElementById("sign_button");
const verifyButton = document.getElementById("verify_button");
const message = document.getElementById("message");
const error = document.getElementById("error");
const publicKeyInput = document.getElementById("public_key");
const signatureInput = document.getElementById("signature");

let encodedMessage = null
signButton.addEventListener('click', async () => {
    if (!message.value) {
        toogleError(true, "Please enter a message to sign");
        return;
    }

    let keyPair = await generateKeyPair();
    showPublicKey(keyPair.publicKey);
    signMessage(str2ab(message.value), keyPair.privateKey);
});

verifyButton.addEventListener('click', async () => {
    if (!signatureInput.value || !publicKeyInput.value || !message.value) {
        toogleError(true, "Public Key, message and Signature are required to verify original message");
        return;
    }

    try {
        let cryptoPublicKey = await window.crypto.subtle.importKey(
            "spki",
            str2ab(atob(publicKeyInput.value)),
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["verify"]
        );

        let result = await window.crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" },
            },
            cryptoPublicKey,
            str2ab(atob(signatureInput.value)),
            str2ab(message.value)
        );

        alert(result);
    } catch (error) {
        console.log(error);
    }
});

function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );
}

async function showPublicKey(publicKeyArrayBufer) {
    const spkiFormat = await crypto.subtle.exportKey("spki", publicKeyArrayBufer);
    const strSpki = ab2str(spkiFormat)
    const base64Spki = btoa(strSpki)
    publicKeyInput.value = base64Spki;
}

async function signMessage(encodedMessage, privateKey) {
    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" },
        },
        privateKey,
        encodedMessage
    );

    showSignature(signature);
}


function showSignature(signature) {
    const derSignature = _P1363ToDer(signature);
    const strSignature = ab2str(derSignature);
    const base64Signature = btoa(strSignature);
    signatureInput.value = base64Signature;
}

function toogleError(show, message) {
    if (show) {
        error.style = "display: block;"
    } else {
        error.style = "display: none;"
    }

    if (message) {
        error.innerHTML = message;
    }
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function str2ab(str) {
    var buf = new ArrayBuffer(str.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function _P1363ToDer(sig) {
    const signatureArray = new Uint8Array(sig);
    const signature = Array.from(signatureArray, x => ('00' + x.toString(16)).slice(-2)).join('');
    let r = signature.substr(0, signature.length / 2);
    let s = signature.substr(signature.length / 2);
    r = r.replace(/^(00)+/, '');
    s = s.replace(/^(00)+/, '');
    if ((parseInt(r, 16) & '0x80') > 0) r = `00${r}`;
    if ((parseInt(s, 16) & '0x80') > 0) s = `00${s}`;
    const rString = `02${(r.length / 2).toString(16).padStart(2, '0')}${r}`;
    const sString = `02${(s.length / 2).toString(16).padStart(2, '0')}${s}`;
    const derSig = `30${((rString.length + sString.length) / 2).toString(16).padStart(2, '0')}${rString}${sString}`;
    return new Uint8Array(derSig.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
}