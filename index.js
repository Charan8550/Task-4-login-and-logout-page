const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Secret key (in production, keep in .env)
const JWT_SECRET = 'your_access_token_secret';

// Databases
const users = Datastore.create('Users.db');
const invalidTokens = Datastore.create('InvalidTokens.db');

// Root route
app.get('/', (req, res) => {
  res.send('Task 4: Login and Logout REST API');
});

// Register route
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(422).json({ message: 'All fields are required' });
  }

  if (await users.findOne({ email })) {
    return res.status(409).json({ message: 'Email already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await users.insert({ name, email, password: hashedPassword });

  res.status(201).json({
    message: 'User registered successfully',
    id: newUser._id
  });
});

// Login route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).json({ message: 'Email and password are required' });
  }

  const user = await users.findOne({ email });

  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const accessToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({
    id: user._id,
    name: user.name,
    email: user.email,
    accessToken
  });
});

// Middleware for authentication
async function ensureAuthenticated(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  if (await invalidTokens.findOne({ token })) {
    return res.status(401).json({ message: 'Token has been invalidated (logged out)' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.userId };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// Logout route
app.post('/api/auth/logout', ensureAuthenticated, async (req, res) => {
  const token = req.headers.authorization;

  await invalidTokens.insert({ token });

  res.status(200).json({ message: 'Logged out successfully' });
});

// Protected route
app.get('/api/protected', ensureAuthenticated, (req, res) => {
  res.status(200).json({ message: `Hello User ${req.user.id}, this is a protected route` });
});

// Start server
app.listen(3000, () => console.log('Server started on port 3000'));
