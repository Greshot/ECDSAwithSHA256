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
    const strSignature = ab2str(signature);
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