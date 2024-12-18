const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://my.tapfeed.dk',
  credentials: true
}));

// ... rest of the code ... 