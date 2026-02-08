// Booking Page Functionality

// Room types and prices
const roomTypes = {
    'standard': { name: 'Standard Room', price: 3500 },
    'deluxe': { name: 'Deluxe Room', price: 5500 },
    'junior': { name: 'Junior Suite', price: 8000 },
    'executive': { name: 'Executive Suite', price: 12000 }
};

// Initialize booking page
window.addEventListener('load', function() {
    if (!checkUserAuth()) {
        return;
    }

    // Auto-fill user information
    autoFillUserInfo();
    
    // Setup room details from URL parameter
    setupRoomDetails();
    
    // Setup event listeners
    setupBookingEventListeners();
    
    // Display user name
    displayUserName();
    
    // Initialize logout button
    initializeUserLogout();
});

// Auto-fill user information from storage
function autoFillUserInfo() {
    let userData = {};
    try {
        userData = JSON.parse(localStorage.getItem('userData') || localStorage.getItem('currentUser') || '{}');
    } catch (err) {
        userData = {};
    }

    // Full name
    let fullNameVal = userData.fullName || '';
    if (!fullNameVal && userData.firstName && userData.lastName) {
        fullNameVal = userData.firstName + (userData.middleName ? ' ' + userData.middleName : '') + ' ' + userData.lastName;
    }
    
    const fullNameElement = document.getElementById('fullName');
    if (fullNameElement && fullNameVal) {
        fullNameElement.value = fullNameVal;
    }

    // Email
    const emailElement = document.getElementById('email');
    if (emailElement && userData.email) {
        emailElement.value = userData.email;
    }

    // Contact number
    const phoneElement = document.getElementById('phone');
    if (phoneElement) {
        if (userData.contactNumber) {
            phoneElement.value = userData.contactNumber;
        } else if (userData.phone) {
            phoneElement.value = userData.phone;
        }
    }
}

// Setup room details from URL
function setupRoomDetails() {
    const urlParams = new URLSearchParams(window.location.search);
    const roomType = urlParams.get('room') || 'standard';
    const room = roomTypes[roomType];

    const roomTypeNameElement = document.getElementById('roomTypeName');
    const summaryRoomTypeElement = document.getElementById('summaryRoomType');
    const pricePerNightElement = document.getElementById('pricePerNight');
    
    if (roomTypeNameElement) roomTypeNameElement.textContent = room.name;
    if (summaryRoomTypeElement) summaryRoomTypeElement.textContent = room.name;
    if (pricePerNightElement) pricePerNightElement.textContent = '₱' + room.price.toLocaleString();

    // Set minimum date to today
    const today = new Date().toISOString().split('T')[0];
    const checkInElement = document.getElementById('checkInDate');
    const checkOutElement = document.getElementById('checkOutDate');
    
    if (checkInElement) checkInElement.setAttribute('min', today);
    if (checkOutElement) checkOutElement.setAttribute('min', today);
}

// Calculate total price
function calculateTotal() {
    const urlParams = new URLSearchParams(window.location.search);
    const roomType = urlParams.get('room') || 'standard';
    const room = roomTypes[roomType];

    const checkInElement = document.getElementById('checkInDate');
    const checkOutElement = document.getElementById('checkOutDate');
    const numRoomsElement = document.getElementById('numRooms');
    
    if (!checkInElement || !checkOutElement || !numRoomsElement) return;

    const checkIn = new Date(checkInElement.value);
    const checkOut = new Date(checkOutElement.value);
    const numRooms = parseInt(numRoomsElement.value) || 1;

    if (checkIn && checkOut && checkOut > checkIn) {
        const nights = Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24));
        const total = room.price * nights * numRooms;

        const numNightsElement = document.getElementById('numNights');
        const summaryNumRoomsElement = document.getElementById('summaryNumRooms');
        const totalAmountElement = document.getElementById('totalAmount');
        
        if (numNightsElement) numNightsElement.textContent = nights;
        if (summaryNumRoomsElement) summaryNumRoomsElement.textContent = numRooms;
        if (totalAmountElement) totalAmountElement.textContent = '₱' + total.toLocaleString();
    }
}

// Setup event listeners
function setupBookingEventListeners() {
    const checkInElement = document.getElementById('checkInDate');
    const checkOutElement = document.getElementById('checkOutDate');
    const numRoomsElement = document.getElementById('numRooms');
    const bookingFormElement = document.getElementById('bookingForm');

    if (checkInElement) {
        checkInElement.addEventListener('change', function() {
            const checkInDate = this.value;
            const checkOutEl = document.getElementById('checkOutDate');
            if (checkOutEl) {
                checkOutEl.setAttribute('min', checkInDate);
            }
            calculateTotal();
        });
    }

    if (checkOutElement) {
        checkOutElement.addEventListener('change', calculateTotal);
    }

    if (numRoomsElement) {
        numRoomsElement.addEventListener('change', calculateTotal);
    }

    if (bookingFormElement) {
        bookingFormElement.addEventListener('submit', handleBookingSubmit);
    }
}

// Handle booking form submission
async function handleBookingSubmit(e) {
    e.preventDefault();

    const checkInElement = document.getElementById('checkInDate');
    const checkOutElement = document.getElementById('checkOutDate');
    
    if (!checkInElement || !checkOutElement) return;

    const checkIn = new Date(checkInElement.value);
    const checkOut = new Date(checkOutElement.value);

    if (checkOut <= checkIn) {
        alert('Check-out date must be after check-in date!');
        return;
    }

    // Get user data
    const userData = JSON.parse(localStorage.getItem('userData') || '{}');
    const userId = userData.id || userData._id;

    if (!userId) {
        alert('Please login to make a booking');
        window.location.href = 'login.html';
        return;
    }

    // Get room details
    const urlParams = new URLSearchParams(window.location.search);
    const roomType = urlParams.get('room') || 'standard';
    const room = roomTypes[roomType];

    // Calculate nights and total
    const nights = Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24));
    const numRooms = parseInt(document.getElementById('numRooms').value) || 1;
    const totalPrice = room.price * nights * numRooms;

    // Prepare booking data
    const bookingData = {
        userId: userId,
        userName: document.getElementById('fullName').value,
        userEmail: document.getElementById('email').value,
        userPhone: document.getElementById('phone').value,
        roomType: room.name,
        checkInDate: document.getElementById('checkInDate').value,
        checkOutDate: document.getElementById('checkOutDate').value,
        numberOfGuests: parseInt(document.getElementById('numGuests').value),
        numberOfRooms: numRooms,
        pricePerNight: room.price,
        specialRequests: document.getElementById('specialRequests').value
    };

    // Sanitize booking data
    const sanitizedData = sanitizeFormData(bookingData);

    try {
        const response = await fetch('/api/bookings/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(sanitizedData)
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert('Booking confirmed successfully! Total: ₱' + totalPrice.toLocaleString());
            window.location.href = 'home.html';
        } else {
            alert('Booking failed: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Booking error:', error);
        alert('Error making booking. Please ensure the server is running.');
    }
}
