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
  refreshToken: { type: String },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
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

// Category Schema
const categorySchema = new mongoose.Schema({
  categoryName: { type: String, required: true, unique: true },
  icon: { type: String },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

const Category = mongoose.model('Category', categorySchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  prodImage: { type: String },
  description: { type: String },
  price: { type: Number, required: true },
  stock: { type: Number, required: true, default: 0 },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['Available', 'Sold Out'], default: 'Available' },
  isPurchased: { type: Boolean, default: false },
  purchasedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// Offer Schema
const offerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  offerPercentage: { type: Number, required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  productImage: { type: String },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true }
}, { timestamps: true });

const Offer = mongoose.model('Offer', offerSchema);

// Carousel Schema
const carouselSchema = new mongoose.Schema({
  image: { type: String, required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: false }
}, { timestamps: true });

const Carousel = mongoose.model('Carousel', carouselSchema);

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
    req.user = await User.findById(decoded.user.id).select('-password');
    next();
  } catch (error) {
    return res.status(401).json(
      formatResponse('fail', 'Invalid token', 401, 'Authentication Failed', null, { detail: error.message })
    );
  }
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json(
      formatResponse('fail', 'Admin access required', 403, 'Forbidden', null, { detail: 'Unauthorized' })
    );
  }
  next();
};

// Auth Routes
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
      formatResponse('success', 'User registered successfully', 201, 'User Created', { 
        accessToken, 
        refreshToken,
        role: user.role 
      })
    );
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

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
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
      })
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

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

// User Management Routes (Admin Only)
app.get('/api/users', authenticate, isAdmin, async (req, res) => {
  try {
    const users = await User.find({ role: 'user' }).select('-password -refreshToken');
    res.json(
      formatResponse('success', 'Users retrieved successfully', 200, 'User List', users)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -refreshToken');
    if (!user || user.role === 'admin') {
      return res.status(404).json(
        formatResponse('fail', 'User not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'User retrieved successfully', 200, 'User Details', user)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/users/:id/purchases', authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json(
        formatResponse('fail', 'User not found', 404, 'Not Found')
      );
    }
    const purchases = await Product.find({ purchasedBy: req.params.id })
      .populate('category', 'categoryName icon');
    res.json(
      formatResponse('success', 'User purchases retrieved', 200, 'Purchase List', purchases)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.put('/api/users/:id', authenticate, isAdmin, async (req, res) => {
  const { name, email, phone, address } = req.body;

  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json(
        formatResponse('fail', 'User not found', 404, 'Not Found')
      );
    }

    user.name = name || user.name;
    user.email = email || user.email;
    user.phone = phone || user.phone;
    user.address = address || user.address;

    await user.save();
    const updatedUser = await User.findById(req.params.id).select('-password -refreshToken');

    res.json(
      formatResponse('success', 'User updated successfully', 200, 'User Updated', updatedUser)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.delete('/api/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json(
        formatResponse('fail', 'User not found', 404, 'Not Found')
      );
    }
    await User.findByIdAndDelete(req.params.id);
    res.json(
      formatResponse('success', 'User deleted successfully', 200, 'User Deleted')
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Category Routes
app.post('/api/categories', authenticate, isAdmin, async (req, res) => {
  const { categoryName, icon } = req.body;
  try {
    const category = new Category({ categoryName, icon, createdBy: req.user.id });
    await category.save();
    res.status(201).json(
      formatResponse('success', 'Category created', 201, 'Category Created', category)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(
      formatResponse('success', 'Categories retrieved', 200, 'Category List', categories)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.put('/api/categories/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const category = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!category) {
      return res.status(404).json(
        formatResponse('fail', 'Category not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Category updated', 200, 'Category Updated', category)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.delete('/api/categories/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) {
      return res.status(404).json(
        formatResponse('fail', 'Category not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Category deleted', 200, 'Category Deleted')
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Product Routes
app.post('/api/products', authenticate, async (req, res) => {
  const { name, category, prodImage, description, price, stock, userId } = req.body;

  try {
    if (!name || !category || !price) {
      return res.status(400).json(
        formatResponse('fail', 'Required fields missing', 400, 'Validation Error', null, { fields: ['name', 'category', 'price'] })
      );
    }

    const categoryExists = await Category.findById(category);
    if (!categoryExists) {
      return res.status(400).json(
        formatResponse('fail', 'Invalid category', 400, 'Validation Error', null, { field: 'category' })
      );
    }

    let productData = {
      name,
      category,
      prodImage,
      description,
      price,
      stock,
      userId: req.user.id
    };

    if (req.user.role === 'admin' && userId) {
      const targetUser = await User.findById(userId);
      if (!targetUser) {
        return res.status(400).json(
          formatResponse('fail', 'Invalid userId', 400, 'Validation Error', null, { field: 'userId' })
        );
      }
      productData.userId = userId;
    }

    const product = new Product(productData);
    await product.save();

    const populatedProduct = await Product.findById(product._id).populate('category', 'categoryName icon');
    res.status(201).json(
      formatResponse('success', 'Product created successfully', 201, 'Product Created', populatedProduct)
    );
  } catch (error) {
    console.error('Product creation error:', error);
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ status: 'Available' })
      .populate('category', 'categoryName icon')
      .select('-userId');
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

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate('category', 'categoryName icon')
      .select('-userId');
    if (!product) {
      return res.status(404).json(
        formatResponse('fail', 'Product not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Product retrieved', 200, 'Product Details', product)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/products/category/:categoryId', async (req, res) => {
  try {
    const products = await Product.find({ 
      category: req.params.categoryId, 
      status: 'Available' 
    }).populate('category', 'categoryName icon');

    if (products.length === 0) {
      return res.json(formatResponse('success', 'No products found', 200, 'No Products Available', []));
    }

    const categoryName = products[0].category.categoryName; // Extract category name

    res.json(
      formatResponse('success', `Category ${categoryName} retrieved`, 200, `Category ${categoryName} List`, products)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});


app.put('/api/products/:id', authenticate, async (req, res) => {
  try {
    let product;
    if (req.user.role === 'admin') {
      product = await Product.findById(req.params.id);
    } else {
      product = await Product.findOne({ _id: req.params.id, userId: req.user.id });
    }

    if (!product) {
      return res.status(404).json(
        formatResponse('fail', 'Product not found or unauthorized', 404, 'Not Found')
      );
    }

    const updatedProduct = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true })
      .populate('category', 'categoryName icon');
    res.json(
      formatResponse('success', 'Product updated', 200, 'Product Updated', updatedProduct)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  try {
    let product;
    if (req.user.role === 'admin') {
      product = await Product.findById(req.params.id);
    } else {
      product = await Product.findOne({ _id: req.params.id, userId: req.user.id });
    }

    if (!product) {
      return res.status(404).json(
        formatResponse('fail', 'Product not found or unauthorized', 404, 'Not Found')
      );
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json(
      formatResponse('success', 'Product deleted', 200, 'Product Deleted')
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.post('/api/products/:id/purchase', authenticate, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product || product.status !== 'Available' || product.stock <= 0) {
      return res.status(400).json(
        formatResponse('fail', 'Product not available', 400, 'Purchase Failed')
      );
    }
    product.isPurchased = true;
    product.purchasedBy = req.user.id;
    product.stock -= 1;
    if (product.stock === 0) product.status = 'Sold Out';
    await product.save();

    const populatedProduct = await Product.findById(product._id).populate('category', 'categoryName icon');
    res.json(
      formatResponse('success', 'Product purchased', 200, 'Purchase Successful', populatedProduct)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Offer Routes
app.post('/api/offers', authenticate, isAdmin, async (req, res) => {
  const { name, offerPercentage, productId, productImage, startDate, endDate } = req.body;
  try {
    const offer = new Offer({ name, offerPercentage, productId, productImage, startDate, endDate });
    await offer.save();
    res.status(201).json(
      formatResponse('success', 'Offer created', 201, 'Offer Created', offer)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/offers', async (req, res) => {
  try {
    const offers = await Offer.find({ endDate: { $gte: new Date() } })
      .populate('productId', 'name price prodImage');
    res.json(
      formatResponse('success', 'Offers retrieved', 200, 'Offer List', offers)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.put('/api/offers/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const offer = await Offer.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!offer) {
      return res.status(404).json(
        formatResponse('fail', 'Offer not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Offer updated', 200, 'Offer Updated', offer)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.delete('/api/offers/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const offer = await Offer.findByIdAndDelete(req.params.id);
    if (!offer) {
      return res.status(404).json(
        formatResponse('fail', 'Offer not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Offer deleted', 200, 'Offer Deleted')
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Carousel Routes
app.post('/api/carousel', authenticate, isAdmin, async (req, res) => {
  const { image, productId } = req.body;
  try {
    const carousel = new Carousel({ image, productId });
    await carousel.save();
    res.status(201).json(
      formatResponse('success', 'Carousel created', 201, 'Carousel Created', carousel)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.get('/api/carousel', async (req, res) => {
  try {
    const carouselItems = await Carousel.find();
    res.json(
      formatResponse('success', 'Carousel retrieved', 200, 'Carousel List', carouselItems)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.put('/api/carousel/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const carousel = await Carousel.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!carousel) {
      return res.status(404).json(
        formatResponse('fail', 'Carousel not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Carousel updated', 200, 'Carousel Updated', carousel)
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

app.delete('/api/carousel/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const carousel = await Carousel.findByIdAndDelete(req.params.id);
    if (!carousel) {
      return res.status(404).json(
        formatResponse('fail', 'Carousel not found', 404, 'Not Found')
      );
    }
    res.json(
      formatResponse('success', 'Carousel deleted', 200, 'Carousel Deleted')
    );
  } catch (error) {
    res.status(500).json(
      formatResponse('error', 'Server error', 500, 'Internal Server Error', null, { detail: error.message })
    );
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
