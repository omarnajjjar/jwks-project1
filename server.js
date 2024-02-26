// Required modules
const uniqueIdentifier = require("uuid");
const expressFramework = require("express");
const jsonwebtoken = require("jsonwebtoken");
const httpLogger = require("morgan");
const secureCrypto = require("crypto");

const webApp = expressFramework();
const httpPort = 8080;

webApp.use(httpLogger("dev"));

let rsaKeys = {};

// RSA key pair generation function
function createRSAKeyPair() {
    return secureCrypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
}

// Generate key pairs and assign them kids and expiry
const firstKid = uniqueIdentifier.v4();
const secondKid = uniqueIdentifier.v4();

rsaKeys[firstKid] = { keySet: createRSAKeyPair(), validUntil: Date.now() + 3600000 }; // 1 hour expiry
rsaKeys[secondKid] = { keySet: createRSAKeyPair(), validUntil: Date.now() + 7200000 }; // 2 hours expiry

// Endpoint for serving JWKS
webApp.get("/jwks", (request, response) => {
    const currentTime = Date.now();
    const availableKeys = Object.entries(rsaKeys)
        .filter(([kid, keyDetails]) => keyDetails.validUntil > currentTime)
        .map(([kid, keyDetails]) => ({
            kid,
            kty: "RSA",
            use: "sig",
            alg: "RS256",
            nbf: Math.floor(currentTime / 1000),
            exp: Math.floor(keyDetails.validUntil / 1000),
            n: keyDetails.keySet.publicKey.split(" ")[1],
            e: "AQAB",
        }));

    response.json({ keys: availableKeys });
});

// Endpoint to issue JWTs
webApp.post("/auth", (request, response) => {
    const { kid, expired } = request.query;
    const keyForSigning = rsaKeys[kid];

    if (!keyForSigning) {
        return response.status(404).json({ error: "Key not found" });
    }

    const keysToUse = expired === "true" ? keyForSigning.keySet : createRSAKeyPair();
    const jwtToken = jsonwebtoken.sign({ data: "payload" }, keysToUse.privateKey, {
        algorithm: "RS256",
        keyid: kid,
    });

    response.json({ token: jwtToken });
});

webApp.listen(httpPort, () => {
    console.log(`Web server listening at http://localhost:${httpPort}`);
});

module.exports = webApp;
