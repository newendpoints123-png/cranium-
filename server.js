const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const extract = require('extract-zip');
const app = express();

const PORT = process.env.PORT || 7860;

const DB_PATH = path.join(__dirname, 'database', 'users.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}


app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function readUsers() {
  try {
    const data = await fs.promises.readFile(DB_PATH, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function writeUsers(users) {
  await fs.promises.writeFile(DB_PATH, JSON.stringify(users, null, 2));
}

function generateToken(userId) {
  return jwt.sign({ id: userId }, 'your-secret-key', { expiresIn: '1h' });
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Middleware to authenticate and get user
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, 'your-secret-key');
    const users = await readUsers();
    const user = users.find(u => u.id === decoded.id);

    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOADS_DIR, req.user.username);
    const destinationPath = req.body.path ? path.join(userDir, req.body.path) : userDir;

    // Prevent directory traversal
    if (!destinationPath.startsWith(userDir)) {
      return cb(new Error('Forbidden'));
    }

    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }
    cb(null, destinationPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });


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

app.get('/api/verify', authenticate, async (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      gmail: req.user.gmail
    }
  });
});

app.post('/api/upload', authenticate, upload.single('file'), (req, res) => {
  res.json({ success: true, message: 'File uploaded successfully' });
});

app.post('/api/files', authenticate, async (req, res) => {
  try {
    const { currentPath } = req.body;
    const userDir = path.join(UPLOADS_DIR, req.user.username);
    const requestedPath = currentPath ? path.join(userDir, currentPath) : userDir;

    // Prevent directory traversal
    if (!requestedPath.startsWith(userDir)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (!fs.existsSync(requestedPath)) {
      return res.json([]);
    }

    const files = await fs.promises.readdir(requestedPath, { withFileTypes: true });
    const fileDetails = files.map(file => ({
      name: file.name,
      isDirectory: file.isDirectory()
    }));

    res.json(fileDetails);
  } catch (error) {
    console.error('File list error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/unzip', authenticate, async (req, res) => {
  try {
    const { filename } = req.body;
    if (!filename) {
      return res.status(400).json({ error: 'Filename is required' });
    }

    const userDir = path.join(UPLOADS_DIR, req.user.username);
    const filePath = path.join(userDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    await extract(filePath, { dir: userDir });

    res.json({ success: true, message: 'File unzipped successfully' });
  } catch (error) {
    console.error('Unzip error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/delete', authenticate, async (req, res) => {
  try {
    const { pathToDelete } = req.body;
    if (!pathToDelete) {
      return res.status(400).json({ error: 'Path is required' });
    }

    const userDir = path.join(UPLOADS_DIR, req.user.username);
    const itemPath = path.join(userDir, pathToDelete);

    // Prevent directory traversal
    if (!itemPath.startsWith(userDir)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (!fs.existsSync(itemPath)) {
      return res.status(404).json({ error: 'File or folder not found' });
    }

    const stats = await fs.promises.stat(itemPath);
    if (stats.isDirectory()) {
      await fs.promises.rm(itemPath, { recursive: true, force: true });
    } else {
      await fs.promises.unlink(itemPath);
    }

    res.json({ success: true, message: 'Item deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Cranium server running on http://localhost:${PORT}`);
});