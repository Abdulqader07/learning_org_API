const express = require('express');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(require('./routes/auth'));
app.use('/resources', require('./routes/resources'));

module.exports = app;