const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user.js");
const config = require("../config/config.js");

// Connect to Mongoose and set connection variable
mongoose.connect('mongodb://localhost/mongo');
var db = mongoose.connection;

// Added check for DB connection
if(!db)
    console.log("Error connecting db")
else
    console.log("Db connected successfully")

exports.register = async (req, res) => {
    //Hash password
    const salt = await bcrypt.genSalt(10);
    const hasPassword = await bcrypt.hash(req.body.password, salt);

    // Create an user object
    let user = new User({
        email: req.body.email,
        name: req.body.name,
        password: hasPassword,
        user_type_id: req.body.user_type_id
    })

    // Save User in the database
    user.save((err, registeredUser) => {
        if (err) {
            console.log(err)
        } else {
            // create payload then Generate an access token
            let payload = { id: registeredUser._id, user_type_id: req.body.user_type_id || 0 };
            const token = jwt.sign(payload, config.TOKEN_SECRET);

            res.status(200).send({ token })
        }
    })
}

exports.login = async (req, res) => {
    User.findOne({ email: req.body.email }, async (err, user) => {
        if (err) {
            console.log(err)
        } else {
            if (user) {
                const validPass = await bcrypt.compare(req.body.password, user.password);
                if (!validPass) return res.status(401).send("Email or Password is wrong");

                // Create and assign token
                let payload = { id: user._id, user_type_id: user.user_type_id };
                const token = jwt.sign(payload, config.TOKEN_SECRET);

                res.status(200).header("auth-token", token).send({ "token": token });
            }
            else {
                res.status(401).send('Invalid email')
            }

        }
    })
}

// No authentication required
exports.noAuthEvent = (req, res) => {
    res.json('everyone can view this!');
};

// Authentication token required
exports.authEvent = (req, res) => {
    res.json('hello authenticated user!');
};

// Access authorized users only
exports.userEvent = (req, res) => {
    res.json('hello user!')
};

// Access authorized admins only
exports.adminEvent = (req, res) => {
    res.json('hello admin!')
}
