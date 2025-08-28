const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// routes (dummy for now)
app.post('/api/signup', (req, res) => {
  // TODO: validate body later
  res.status(201).json({ token: 'dummy-token' });
});

app.post('/api/login', (req, res) => {
  // TODO: real check later
  res.json({ token: 'dummy-token' });
});

app.listen(PORT, () => {
  console.log(`Cranium server listening on http://localhost:${PORT}`);
});
