const express = require('express');
const msal = require('@azure/msal-node');
const jwt = require('jsonwebtoken');
const jwks = require('jwks-rsa');

const config = {
    auth: {
        authority: "https://login.microsoftonline.com/<tenant-id>",
        clientId: "<client-id>",
        clientSecret: "<client-secret>",
        scopes: ["user.read"]
    }
};

const validateJwt = (req, res, next) => {
    const token = req.headers.authorization.split(" ")[1];

    if (token) {

        const validationOptions = {
            audience: config.auth.clientId,
            issuer: config.auth.authority + "/v2.0"
        }

        jwt.verify(token, getSigningKeys, validationOptions, (err, payload) => {
            if (err) {
                return res.sendStatus(403);
            }

            next();
        });

    } else {
        res.sendStatus(401);
    }
};

const getSigningKeys = (header, callback) => {
    const jwksClient = jwks({
        jwksUri: 'https://login.microsoftonline.com/common/discovery/keys'
    });

    jwksClient.getSigningKey(header.kid, function (err, key) {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
};

const cca = new msal.ConfidentialClientApplication(config);
const app = express();
const server_port = 3000;

app.get('/auth', validateJwt, (req, res) => {
    const authHeader = req.headers.authorization.split(" ")[1];

    const oboRequest = {
        oboAssertion: authHeader,
        scopes: config.scopes
    };

    cca.acquireTokenOnBehalfOf(oboRequest).then((data) => {
        res.status(200).send(data.accessToken);
    }).catch((error) => {
        res.status(500).send(error);
    });
});

app.listen(server_port, () => {
    console.log(`app listening at http://localhost:${server_port}/auth`);
});
