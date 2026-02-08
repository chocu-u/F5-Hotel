const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware to verify admin token
    const verifyAdminToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user is admin
        const user = await User.findById(decoded.userId);
        if (!user || !user.isAdmin) {   
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin privileges required.' 
            });
        }

        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ 
            success: false, 
            message: 'Invalid or expired token' 
        });
    }
};

// Validation middleware
const signupValidation = [
    body('email').isEmail().normalizeEmail(),
    body('username').trim().isLength({ min: 4 }),
    body('password').isLength({ min: 8 }),
    body('firstName').trim().notEmpty(),
    body('lastName').trim().notEmpty(),
    body('contactNumber').trim().notEmpty(),
    body('dateOfBirth').isISO8601()
];

const loginValidation = [
    body('username').trim().notEmpty(),
    body('password').notEmpty()
];

const updateUserValidation = [
    body('email').optional().isEmail().normalizeEmail(),
    body('username').optional().trim().isLength({ min: 4 }),
    body('firstName').optional().trim().notEmpty(),
    body('lastName').optional().trim().notEmpty(),
    body('contactNumber').optional().trim().notEmpty(),
    body('dateOfBirth').optional().isISO8601(),
    body('isAdmin').optional().isBoolean()
];

// Register new user
router.post('/signup', signupValidation, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const { firstName, middleName, lastName, dateOfBirth, email, contactNumber, username, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: existingUser.email === email 
                    ? 'Email already registered' 
                    : 'Username already taken'
            });
        }

        // Create new user
        const user = new User({
            firstName,
            middleName,
            lastName,
            dateOfBirth,
            email,
            contactNumber,
            username,
            password
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            message: 'Account created successfully',
            token,
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during signup',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Login user
router.post('/login', loginValidation, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const { username, password } = req.body;

        // Find user by username
        const user = await User.findOne({ 
            username
        });

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Admin login - Only for admin accounts
router.post('/admin-login', loginValidation, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const { username, password } = req.body;

        // Find user by username
        const user = await User.findOne({ 
            username
        });

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid admin credentials' 
            });
        }

        // Check if user is an admin
        if (!user.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin privileges required.' 
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid admin credentials' 
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token with admin flag
        const token = jwt.sign(
            { userId: user._id, username: user.username, isAdmin: true },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            success: true,
            message: 'Admin login successful',
            token,
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during admin login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get user profile (protected route example)
router.get('/profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        res.status(200).json({
            success: true,
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(401).json({ 
            success: false, 
            message: 'Invalid or expired token' 
        });
    }
});

// Update own profile (regular users)
router.put('/profile', updateUserValidation, async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const updateData = req.body;

        // Don't allow password or isAdmin update through this endpoint
        delete updateData.password;
        delete updateData.isAdmin;

        // Check if email already exists (if being updated)
        if (updateData.email) {
            const existingUser = await User.findOne({
                _id: { $ne: decoded.userId },
                email: updateData.email
            });

            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered'
                });
            }
        }

        // Check if username already exists (if being updated)
        if (updateData.username) {
            const existingUser = await User.findOne({
                _id: { $ne: decoded.userId },
                username: updateData.username
            });

            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            decoded.userId,
            { $set: updateData },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error updating profile',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get all users (admin only)
router.get('/users', verifyAdminToken, async (req, res) => {
    try {
        const users = await User.find().select('-password -dateOfBirth -contactNumber').sort({ createdAt: -1 });
        res.status(200).json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error fetching users' 
        });
    }
});

// Update user (admin only)
router.put('/users/:id', verifyAdminToken, updateUserValidation, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const userId = req.params.id;
        const updateData = req.body;

        // Don't allow password update through this endpoint
        delete updateData.password;

        // Check if username or email already exists (if being updated)
        if (updateData.username || updateData.email) {
            const existingUser = await User.findOne({
                _id: { $ne: userId },
                $or: [
                    updateData.username ? { username: updateData.username } : null,
                    updateData.email ? { email: updateData.email } : null
                ].filter(Boolean)
            });

            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: existingUser.username === updateData.username 
                        ? 'Username already taken' 
                        : 'Email already registered'
                });
            }
        }

        // Find and update user
        const user = await User.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user: user.getSafeProfile()
        });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error updating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Delete user (admin only)
router.delete('/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const userId = req.params.id;

        // Prevent admin from deleting themselves
        if (userId === req.userId.toString()) {
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account'
            });
        }

        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'User deleted successfully',
            deletedUser: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error deleting user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

module.exports = router;