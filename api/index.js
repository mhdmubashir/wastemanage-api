import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import cors from 'cors';
import http from 'http';
import { Server } from 'socket.io';

dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.json());

// Response Formatter
const formatResponse = (status, message, code, title, data = null, error = null) => ({
  status,
  message,
  code,
  title,
  data,
  error
});

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI || '');
    console.log('Database connected successfully');
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};
connectDB();

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  address: { type: String },
  refreshToken: { type: String }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  prodImage: { type: String },
  description: { type: String },
  price: { type: Number, required: true },
  stock: { type: Number, required: true, default: 0 },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['Available', 'Sold Out'], default: 'Available' }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json(
      formatResponse('fail', 'No token provided', 401, 'Authentication Failed', null, { detail: 'Token missing' })
    );
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '');
    req.user = decoded.user;
    next();
  } catch (error) {
    return res.status(401).json(
      formatResponse('fail', 'Invalid token', 401, 'Authentication Failed', null, { detail: error.message })
    );
  }
};

// Routes
// User Registration
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, phone, address } = req.body;

  try {
    if (!name || !email || !password) {
      return res.status(400).json(
        formatResponse('fail', 'All fields are required', 400, 'Validation Error', null, { fields: ['name', 'email', 'password'] })
      );
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json(
        formatResponse('fail', 'User already exists', 400, 'Duplicate User', null, { field: 'email' })
      );
    }

    const user = new User({ name, email, password, phone, address });
    await user.save();

    const payload = { user: { id: user.id } };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET || '', { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET || '', { expiresIn: '7d' });

    user.refreshToken = refreshToken;
    await user.save();

    res.status(201).json(
      formatResponse('success', 'User registered successfully', 201, 'User Created', { accessToken, refreshToken })
    );
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json(
        formatResponse('fail', 'Email and password are required', 400, 'Validation Error', null, { fields: ['email', 'password'] })
      );
    }

    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json(
        formatResponse('fail', 'Invalid credentials', 401, 'Authentication Failed', null, { detail: 'Email or password incorrect' })
      );
    }

    const payload = { user: { id: user.id } };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET || '', { expiresIn: '1h' });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET || '', { expiresIn: '7d' });

    user.refreshToken = refreshToken;
    await user.save();

    res.json(
      formatResponse('success', 'Login successful', 200, 'User Authenticated', {
        accessToken,
        refreshToken,
        user: { id: user.id, name: user.name, email: user.email }
      })
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Token Refresh
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json(
      formatResponse('fail', 'Refresh token required', 401, 'Authentication Failed', null, { detail: 'Token missing' })
    );
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || '');
    const user = await User.findById(decoded.user.id);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json(
        formatResponse('fail', 'Invalid refresh token', 401, 'Authentication Failed', null, { detail: 'Token invalid or expired' })
      );
    }

    const payload = { user: { id: user.id } };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET || '', { expiresIn: '1h' });

    res.json(
      formatResponse('success', 'Token refreshed successfully', 200, 'Token Refreshed', { accessToken })
    );
  } catch (error) {
    res.status(401).json(
      formatResponse('fail', 'Invalid refresh token', 401, 'Authentication Failed', null, { detail: error.message })
    );
  }
});

// Public Product Routes (for guest users)
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ status: 'Available' })
      .select('-userId')
      .sort({ createdAt: -1 });

    res.json(
      formatResponse('success', 'Products retrieved successfully', 200, 'Product List', products)
    );
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Protected Product Routes
app.post('/api/products', authenticate, async (req, res) => {
  const { name, category, prodImage, description, price, stock } = req.body;

  try {
    if (!name || !category || !price) {
      return res.status(400).json(
        formatResponse('fail', 'Required fields missing', 400, 'Validation Error', null, { fields: ['name', 'category', 'price'] })
      );
    }

    const product = new Product({
      name,
      category,
      prodImage,
      description,
      price,
      stock,
      userId: req.user.id
    });

    await product.save();
    res.status(201).json(
      formatResponse('success', 'Product created successfully', 201, 'Product Created', product)
    );
  } catch (error) {
    console.error('Product creation error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Get user's products
app.get('/api/my-products', authenticate, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.user.id });
    res.json(
      formatResponse('success', 'User products retrieved successfully', 200, 'User Product List', products)
    );
  } catch (error) {
    console.error('Error fetching user products:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
