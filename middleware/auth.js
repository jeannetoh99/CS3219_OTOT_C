const config = require("../config/config");
const jwt = require('jsonwebtoken')

exports.verifyUserToken = (req, res, next) => {
    let token = req.headers.authorization;
    if (!token) return res.status(401).send("Unauthenticated request");

    try {
        token = token.split(' ')[1] // Remove Bearer from string

        if (token === 'null' || !token) return res.status(401).send('Unauthenticated request');

        let verifiedUser = jwt.verify(token, config.TOKEN_SECRET);   // config.TOKEN_SECRET => 'secretKey'
        if (!verifiedUser) return res.status(401).send('Unauthenticated request')

        req.user = verifiedUser; // user_id & user_type_id
        next();

    } catch (error) {
        res.status(400).send("Invalid Token");
    }
}

exports.IsUser = (req, res, next) => {
    if (req.user.user_type_id === 0) {
        next();
    } else {
        return res.status(403).send("Unauthorized!");   
    }
}

exports.IsAdmin = (req, res, next) => {
    if (req.user.user_type_id === 1) {
        next();
    } else {
        return res.status(403).send("Unauthorized!");
    }
}