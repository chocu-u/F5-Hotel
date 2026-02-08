const dns = require('dns').promises;
dns.setServers(['8.8.8.8', '8.8.4.4']);

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const morgan = require('morgan');

// Import routes
const authRoutes = require('./routes/auth');
const bookingRoutes = require('./routes/bookings');

const app = express();

// ====================
// SECURITY MIDDLEWARE
// ====================

// 1. Set Security HTTP Headers (Helmet)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
        },
    },
}));

// 2. Rate Limiting - General API Protection
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// 3. Strict Rate Limiting for Authentication Endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per windowMs
    message: 'Too many login attempts, please try again after 15 minutes.',
    skipSuccessfulRequests: true,
});

// 4. CORS Configuration - Restrict Origins
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' 
        ? process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000'
        : '*',
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// 5. Body Parser with Size Limits (Prevent DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 6. Data Sanitization Against NoSQL Injection
app.use(mongoSanitize());

// 7. Prevent HTTP Parameter Pollution
app.use(hpp());

// 8. Security Logging
if (process.env.NODE_ENV === 'production') {
    app.use(morgan('combined')); // Detailed logs in production
} else {
    app.use(morgan('dev')); // Concise logs in development
}

// Serve static files
app.use(express.static(path.join(__dirname)));

// API Routes with Rate Limiting
app.use('/api/auth/login', authLimiter); // Strict limit for login
app.use('/api/auth/signup', authLimiter); // Strict limit for signup
app.use('/api', apiLimiter); // General API rate limiting
app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET'];
const mongoURI = process.env.MONGODB_URI || process.env.MONGO_URI;

if (!mongoURI) {
    console.error('✗ MONGODB_URI (or MONGO_URI) not defined in .env');
    process.exit(1);
}

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`✗ ${envVar} not defined in .env`);
        process.exit(1);
    }
}

if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.error('✗ JWT_SECRET must be at least 32 characters long');
    process.exit(1);
}

// FIXED: Removed deprecated options
mongoose.connect(mongoURI)
.then(() => {
    console.log('✓ Connected to MongoDB Atlas successfully');
})
.catch(err => {
    console.error('✗ MongoDB connection error:', err.message);
    process.exit(1);
});

// Security-Enhanced Error Handling
app.use((err, req, res, next) => {
    // Log error details for monitoring
    console.error('Error occurred:', {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        ip: req.ip,
        error: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
    
    // Send safe error response
    res.status(err.status || 500).json({
        success: false,
        message: process.env.NODE_ENV === 'production' 
            ? 'An error occurred while processing your request'
            : err.message,
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

const PORT = process.env.PORT || 3000;

// FIXED: Added error handling for EADDRINUSE
const server = app.listen(PORT, () => {
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ Frontend: http://localhost:${PORT}/login.html`);
    console.log(`✓ API: http://localhost:${PORT}/api/auth`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`✗ Port ${PORT} is already in use!`);
        console.error('  Solutions:');
        console.error(`  1. Stop the process using port ${PORT}`);
        console.error(`  2. Use a different port: PORT=3002 npm start`);
        console.error(`  3. Run: taskkill /IM node.exe /F (Windows)`);
        process.exit(1);
    } else {
        console.error('✗ Server error:', err.message);
        process.exit(1);
    }
});