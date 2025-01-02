import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';

dotenv.config();

// Connect to MongoDB
const connectDB = async () => {
    try {
      await mongoose.connect(process.env.MONGO_URI || '');
      console.log('Connecting to MongoDB:', process.env.MONGO_URI);

      console.log('Database connected!s poli');

    } catch (error) {
      console.error('Database connection error:', error);
      process.exit(1);
    }
  };
// Initialize Express app
const app = express();
connectDB();

// Middleware to parse JSON requests
app.use(bodyParser.json());

// Middleware for Authentication
const authenticate = (req, res, next) => {
  //const token = req.header('Authorization');
      const token = req.header('Authorization') && req.header('Authorization').split(' ')[1]; // Extract token

  console.log('Token received:', req.header('Authorization'));

  if (!token) {
    res.status(401).json({ msg: 'No token, authorization denied' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || '');
console.log('Decoded payload:', decoded);

    req.user = decoded.user;
    next();
  } catch (error) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// User Model
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String },
    address: { type: String },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// Pickup Model
const pickupSchema = new mongoose.Schema(
  {
    wasteType: { type: String, required: true },
    date: { type: Date, required: true },
    timeSlot: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, default: 'Scheduled' },
  },
  { timestamps: true }
);

const Pickup = mongoose.model('Pickup', pickupSchema);

// Routes

// Sign up route
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, phone, address } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create new user
    const newUser = new User({ name, email, password, phone, address });
    await newUser.save();

    // Generate JWT token
    const payload = { user: { id: newUser.id } };
    const token = jwt.sign(payload, process.env.JWT_SECRET || '', { expiresIn: '1h' });

    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // Compare password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // Generate JWT token
    const payload = { user: { id: user.id } };
    const token = jwt.sign(payload, process.env.JWT_SECRET || '', { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});


//Pickup
//create a new pickup
app.post('/api/pickups', authenticate, async (req, res) => {
    try {
      const { wasteType, date, timeSlot } = req.body;
      if (!req.user || !req.user.id) {
        return res.status(400).json({ msg: 'User ID is missing' });
      }
      const pickup = await Pickup.create({
        wasteType,
        date,
        timeSlot,
        userId: req.user.id,
      });
      res.status(201).json(pickup);
    } catch (error) {
      console.error('Pickup creation error:', error);
      res.status(500).json({ msg: 'Server error' });
    }
  });


  //show all pickups
  app.get('/api/pickups/all', async (req, res) => {
    try {
      const pickups = await Pickup.find();
      res.json(pickups);
    } catch (error) {
      console.error(error);
      res.status(500).json({ msg: 'Server error' });
    }
  });
  

// Get all pickups for authenticated user
app.get('/api/pickups', authenticate, async (req, res) => {
    try {
      const pickups = await Pickup.find({ userId: req.user.id });
      res.json(pickups);
    } catch (error) {
      console.error(error);
      res.status(500).json({ msg: 'Server error' });
    }
  });
  
  // Get a single pickup by ID
  app.get('/api/pickups/:id', authenticate, async (req, res) => {
    try {
      const pickup = await Pickup.findById(req.params.id);
      if (!pickup || pickup.userId.toString() !== req.user.id) {
        return res.status(404).json({ msg: 'Pickup not found' });
      }
      res.json(pickup);
    } catch (error) {
      console.error(error);
      res.status(500).json({ msg: 'Server error' });
    }
  });
  
//   // Update a pickup
//   app.put('/api/pickups/:id', authenticate, async (req, res) => {
//     const { wasteType, date, timeSlot, status } = req.body;
  
//     try {
//       let pickup = await Pickup.findById(req.params.id);
//       if (!pickup || pickup.userId.toString() !== req.user.id) {
//         return res.status(404).json({ msg: 'Pickup not found' });
//       }
  
//       pickup = await Pickup.findByIdAndUpdate(
//         req.params.id,
//         { wasteType, date, timeSlot, status },
//         { new: true }
//       );
  
//       res.json(pickup);
//     } catch (error) {
//       console.error(error);
//       res.status(500).json({ msg: 'Server error' });
//     }
//   });
  
//   // Delete a pickup
//   app.delete('/api/pickups/:id', authenticate, async (req, res) => {
//     try {
//       const pickup = await Pickup.findById(req.params.id);
//       if (!pickup || pickup.userId.toString() !== req.user.id) {
//         return res.status(404).json({ msg: 'Pickup not found' });
//       }
  
//       await pickup.remove();
//       res.json({ msg: 'Pickup deleted' });
//     } catch (error) {
//       console.error(error);
//       res.status(500).json({ msg: 'Server error' });
//     }
//   });
  





// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
