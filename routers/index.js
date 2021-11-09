const router = require('express').Router();
const { verifyUserToken, IsAdmin, IsUser } = require("../middleware/auth");
const userController = require('../controllers/user');

// Register a new User
router.post('/register', userController.register);

// Login
router.post('/login', userController.login);

// No authentication required
router.get('/no-auth', userController.noAuthEvent);

// Authentication required
router.get('/auth', verifyUserToken, userController.authEvent);

// Authenticated users only
router.get('/user', verifyUserToken, IsUser, userController.userEvent);

// Authorized (admin) users only
router.get('/admin', verifyUserToken, IsAdmin, userController.adminEvent);

module.exports = router;