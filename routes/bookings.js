const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const Booking = require('../models/Booking');
const User = require('../models/User');
const { generateBookingPdf } = require('../utils/pdfGenerator');

// Validation middleware
const bookingValidation = [
    body('roomType').notEmpty().withMessage('Room type is required'),
    body('checkInDate').isISO8601().withMessage('Valid check-in date is required'),
    body('checkOutDate').isISO8601().withMessage('Valid check-out date is required'),
    body('numberOfGuests').isInt({ min: 1 }).withMessage('Number of guests must be at least 1'),
    body('numberOfRooms').isInt({ min: 1 }).withMessage('Number of rooms must be at least 1')
];

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

        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const user = await User.findById(decoded.userId);
        if (!user || !user.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin privileges required.' 
            });
        }

        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
};

router.post('/create', bookingValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed',
                errors: errors.array() 
            });
        }

        const {
            userId,
            userName,
            userEmail,
            userPhone,
            roomType,
            checkInDate,
            checkOutDate,
            numberOfGuests,
            numberOfRooms,
            pricePerNight,
            specialRequests
        } = req.body;

        // Calculate total nights and price
        const checkIn = new Date(checkInDate);
        const checkOut = new Date(checkOutDate);
        const totalNights = Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24));
        const totalPrice = totalNights * pricePerNight * numberOfRooms;

        // Create booking
        const booking = new Booking({
            userId,
            userName,
            userEmail,
            userPhone,
            roomType,
            checkInDate: checkIn,
            checkOutDate: checkOut,
            numberOfGuests,
            numberOfRooms,
            pricePerNight,
            totalNights,
            totalPrice,
            specialRequests: specialRequests || '',
            status: 'Pending'
        });

        await booking.save();

        res.status(201).json({
            success: true,
            message: 'Booking created successfully',
            booking
        });

    } catch (error) {
        console.error('Booking error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during booking',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get all bookings (Admin only)
router.get('/all', verifyAdminToken, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .sort({ createdAt: -1 })
            .populate('userId', 'username email firstName lastName');

        res.status(200).json({
            success: true,
            count: bookings.length,
            bookings
        });
    } catch (error) {
        console.error('Error fetching bookings:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error fetching bookings' 
        });
    }
});

// Get user's bookings
router.get('/user/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Validate userId
        if (!userId || userId === 'undefined' || userId === 'null') {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID. Please login again.'
            });
        }
        
        const bookings = await Booking.find({ userId: userId })
            .sort({ createdAt: -1 });

        res.status(200).json({
            success: true,
            count: bookings.length,
            bookings
        });
    } catch (error) {
        console.error('Error fetching user bookings:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error fetching bookings' 
        });
    }
});

// Update booking status (Admin only)
router.put('/:id/status', verifyAdminToken, async (req, res) => {
    try {
        const { status } = req.body;

        if (!['Pending', 'Confirmed', 'Cancelled', 'Completed'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status'
            });
        }

        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status, updatedAt: Date.now() },
            { new: true }
        );

        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'Booking not found'
            });
        }

        // If booking confirmed, generate PDF (if not already generated)
        if (status === 'Confirmed' && booking) {
            try {
                if (!booking.pdfUrl) {
                    const pdfUrl = await generateBookingPdf(booking);
                    booking.pdfUrl = pdfUrl;
                    await booking.save();
                }
            } catch (pdfErr) {
                console.error('PDF generation error:', pdfErr);
                // Don't fail the status update if PDF generation fails
            }
        }

        res.status(200).json({
            success: true,
            message: 'Booking status updated',
            booking
        });
    } catch (error) {
        console.error('Error updating booking:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error updating booking' 
        });
    }
});

// Delete booking (Admin only)
router.delete('/:id', verifyAdminToken, async (req, res) => {
    try {
        const booking = await Booking.findByIdAndDelete(req.params.id);

        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'Booking not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Booking deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting booking:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error deleting booking' 
        });
    }
});

module.exports = router;
