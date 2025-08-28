const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const app = express();
const PORT = process.env.PORT || 7860;

const DB_PATH = path.join(__dirname, 'database', 'users.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function readUsers() {
  try {
    const data = await fs.readFile(DB_PATH, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function writeUsers(users) {
  await fs.writeFile(DB_PATH, JSON.stringify(users, null, 2));
}

function generateToken(userId) {
  return Buffer.from(`${userId}:${Date.now()}`).toString('base64');
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

app.post('/api/signup', async (req, res) => {
  try {
    const { username, gmail, password } = req.body;

    if (!username || !gmail || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (!validateEmail(gmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const users = await readUsers();
    
    const existingUser = users.find(u => u.gmail === gmail || u.username === username);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists with this email or username' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = uuidv4();
    
    const newUser = {
      id: userId,
      username,
      gmail,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      lastLogin: null
    };

    users.push(newUser);
    await writeUsers(users);

    const token = generateToken(userId);
    
    res.status(201).json({ 
      success: true,
      token,
      user: {
        id: userId,
        username,
        gmail
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: 'Email/Username and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    const users = await readUsers();
    const user = users.find(u => u.gmail === emailOrUsername || u.username === emailOrUsername);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.lastLogin = new Date().toISOString();
    await writeUsers(users);

    const token = generateToken(user.id);
    
    res.json({ 
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        gmail: user.gmail
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = Buffer.from(token, 'base64').toString();
    const [userId] = decoded.split(':');
    
    const users = await readUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        gmail: user.gmail
      }
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Cranium server running on http://localhost:${PORT}`);
});