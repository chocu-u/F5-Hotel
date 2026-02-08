// Admin Bookings Page Functionality

// Load admin data
function loadAdminData() {
    const adminData = localStorage.getItem('adminData');
    if (adminData) {
        try {
            const admin = JSON.parse(adminData);
            const fullName = admin.firstName + ' ' + admin.lastName;
            const initials = (admin.firstName[0] + admin.lastName[0]).toUpperCase();
            
            const adminNameHeaderElement = document.getElementById('adminNameHeader');
            const adminAvatarElement = document.getElementById('adminAvatar');
            
            if (adminNameHeaderElement) {
                adminNameHeaderElement.innerHTML = '<i class="fas fa-user" style="margin-right: 8px;"></i>' + fullName;
            }
            if (adminAvatarElement) {
                adminAvatarElement.textContent = initials;
            }
        } catch (e) {
            console.error('Error loading admin data:', e);
        }
    }
}

// Format date
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric'
    });
}

// Fetch bookings
async function loadBookings() {
    const token = getAdminAuthToken();
    const container = document.getElementById('bookingsTableContainer');

    if (!container) return;

    container.innerHTML = '<div class="loading"><i class="fa fa-spinner fa-spin"></i> Loading reservations...</div>';

    try {
        const response = await fetch('/api/bookings/all', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            displayBookings(data.bookings);
        } else {
            container.innerHTML = '<div class="no-data">No reservations found. Error: ' + (data.message || 'Unknown error') + '</div>';
        }
    } catch (error) {
        console.error('Error fetching bookings:', error);
        container.innerHTML = '<div class="no-data">Error loading reservations. Make sure the server is running.</div>';
    }
}

// Display bookings in table
function displayBookings(bookings) {
    const container = document.getElementById('bookingsTableContainer');
    
    if (!bookings || bookings.length === 0) {
        container.innerHTML = '<div class="no-data">No reservations found</div>';
        const bookingCountElement = document.getElementById('bookingCount');
        if (bookingCountElement) {
            bookingCountElement.textContent = '(0 reservations)';
        }
        return;
    }

    const bookingCountElement = document.getElementById('bookingCount');
    if (bookingCountElement) {
        bookingCountElement.textContent = '(' + bookings.length + ' reservations)';
    }

    let tableHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Guest Name</th>
                    <th>Email</th>
                    <th>Room Type</th>
                    <th>Check-In</th>
                    <th>Check-Out</th>
                    <th>Guests</th>
                    <th>Rooms</th>
                    <th>Total</th>
                    <th>Status</th>
                    <th>Reserved Date</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;

    bookings.forEach(function(booking, index) {
        const status = (booking.status || '').toLowerCase();
        let statusTag = '';
        if (status === 'confirmed') {
            statusTag = '<span class="status-confirmed">CONFIRMED</span>';
        } else if (status === 'pending') {
            statusTag = '<span class="status-pending">PENDING</span>';
        } else if (status === 'completed') {
            statusTag = '<span class="status-completed">COMPLETED</span>';
        } else if (status === 'cancelled') {
            statusTag = '<span class="status-cancelled">CANCELLED</span>';
        } else {
            statusTag = '<span class="status-pending">PENDING</span>';
        }

        const guestName = sanitizeInput(booking.userName || booking.guestName || '');
        const totalPrice = booking.totalPrice || booking.total || 0;
        
        tableHTML += `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${guestName}</strong></td>
                <td>${sanitizeInput(booking.userEmail || booking.email || '')}</td>
                <td>${sanitizeInput(booking.roomType || '')}</td>
                <td>${formatDate(booking.checkInDate || booking.checkIn)}</td>
                <td>${formatDate(booking.checkOutDate || booking.checkOut)}</td>
                <td>${booking.numberOfGuests || booking.guests || 0}</td>
                <td><strong>${booking.numberOfRooms || 1}</strong></td>
                <td>₱${totalPrice.toLocaleString()}</td>
                <td>${statusTag}</td>
                <td>${formatDate(booking.createdAt || booking.bookingDate)}</td>
                <td>
                    ${status === 'pending' ? `
                    <button class="action-btn edit-btn" data-booking-id="${booking._id || booking.id}" data-guest-name="${guestName}" data-action="confirm">
                        <i class="fa fa-check"></i> Confirm
                    </button>
                    ` : ''}
                    <button class="action-btn delete-btn" data-booking-id="${booking._id || booking.id}" data-guest-name="${guestName}" data-action="delete">
                        <i class="fa fa-trash"></i> Delete
                    </button>
                </td>
            </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    container.innerHTML = tableHTML;

    // Attach event listeners
    attachBookingActionListeners();
}

// Attach event listeners to action buttons
function attachBookingActionListeners() {
    const confirmButtons = document.querySelectorAll('[data-action="confirm"]');
    const deleteButtons = document.querySelectorAll('[data-action="delete"]');

    confirmButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const bookingId = this.getAttribute('data-booking-id');
            const guestName = this.getAttribute('data-guest-name');
            confirmBooking(bookingId, guestName);
        });
    });

    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const bookingId = this.getAttribute('data-booking-id');
            const guestName = this.getAttribute('data-guest-name');
            deleteBooking(bookingId, guestName);
        });
    });
}

// Confirm booking
async function confirmBooking(id, guestName) {
    if (!confirm('Confirm reservation for "' + guestName + '"?')) {
        return;
    }

    const token = getAdminAuthToken();

    try {
        const response = await fetch('/api/bookings/' + id + '/status', {
            method: 'PUT',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: 'Confirmed' })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert('Reservation confirmed successfully!');
            loadBookings();
        } else {
            alert('Failed to confirm reservation: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error confirming booking:', error);
        alert('Error confirming booking. Please try again.');
    }
}

// Delete booking
async function deleteBooking(id, guestName) {
    if (!confirm('Are you sure you want to delete reservation for "' + guestName + '"? This action cannot be undone.')) {
        return;
    }

    const token = getAdminAuthToken();

    try {
        const response = await fetch('/api/bookings/' + id, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert('Reservation deleted successfully!');
            loadBookings();
        } else {
            alert('Failed to delete reservation: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting booking:', error);
        alert('Error deleting booking. Please try again.');
    }
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    if (checkAdminAuth()) {
        loadAdminData();
        loadBookings();
        initializeAdminLogout();
    }
});
