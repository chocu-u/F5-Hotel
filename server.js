require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

// Import routes
const authRoutes = require('./routes/auth');
const bookingRoutes = require('./routes/bookings');

const app = express();

// Trust proxy - needed for secure cookies behind reverse proxy
app.set('trust proxy', 1);

// Disable x-powered-by header (prevents server version leaks)
app.disable('x-powered-by');

// CORS Configuration - Whitelist specific origins
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['http://localhost:3000', 'http://127.0.0.1:3000'];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 600 // Cache preflight for 10 minutes
};

// Apply CORS
app.use(cors(corsOptions));

// Content Security Policy Configuration
const cspConfig = {
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
            "'self'",
            "https://fonts.googleapis.com",
            "https://cdn.jsdelivr.net",
            "https://code.jquery.com",
            "https://cdnjs.cloudflare.com"
        ],
        styleSrc: [
            "'self'",
            "https://fonts.googleapis.com",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        fontSrc: [
            "'self'",
            "https://fonts.gstatic.com",
            "https://cdn.jsdelivr.net",
            "data:"
        ],
        imgSrc: [
            "'self'",
            "data:",
            "https:",
            "blob:"
        ],
        connectSrc: ["'self'"],
        frameSrc: ["https://www.google.com"], // Google Maps embed
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
    }
};

// Helmet Configuration - Comprehensive security headers
app.use(helmet({
    contentSecurityPolicy: cspConfig,
    crossOriginEmbedderPolicy: false, 
    crossOriginResourcePolicy: { policy: "cross-origin" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' }, 
    hsts: {
        maxAge: 31536000, 
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true, 
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true
}));

app.use(cookieParser());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware to sanitize responses - remove sensitive data
app.use((req, res, next) => {
    const originalJson = res.json;
    res.json = function(data) {
        if (data && typeof data === 'object') {
            if (process.env.NODE_ENV === 'production' && data.stack) {
                delete data.stack;
            }
        }
        return originalJson.call(this, data);
    };
    next();
});

app.use(express.static(path.join(__dirname)));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);

const mongoURI = process.env.MONGODB_URI || process.env.MONGO_URI;
if (!mongoURI) {
    console.error('✗ MONGODB_URI (or MONGO_URI) not defined in .env');
    process.exit(1);
}

mongoose.connect(mongoURI)
.then(() => {
    console.log('✓ Connected to MongoDB Atlas successfully');
})
.catch(err => {
    console.error('✗ MongoDB connection error:', err.message);
    process.exit(1);
});

// Error handling - Sanitize error messages
app.use((err, req, res, next) => {
    console.error('Error occurred:', {
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        timestamp: new Date().toISOString()
    });

    const statusCode = err.statusCode || 500;

    const errorResponse = {
        success: false,
        message: err.message || 'An error occurred',
    };

    // Only include detailed error info in development
    if (process.env.NODE_ENV === 'development') {
        errorResponse.error = err.message;
        errorResponse.stack = err.stack;
    } else {
        if (statusCode === 500) {
            errorResponse.message = 'Internal server error';
        }
    }

    res.status(statusCode).json(errorResponse);
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