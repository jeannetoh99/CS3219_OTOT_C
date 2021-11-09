const express = require('express');
const app = express();

app.use(express.json()); 

// Import Routes
const authRoute = require('./routers/index');

// Route Middlewares
app.use('/api', authRoute);

const port = 3000;
app.listen(port, function() {
    console.log("Server running on localhost:" + port);
});