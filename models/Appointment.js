const mongoose = require('mongoose');

// Define your rates here so they are easy to update in one place
const ROOM_RATES = {
  'Aircon Room': 3500,
  'Fan Room': 2500,
  'Seaside Cottage': 1200
};
const COTTAGE_ADDON_PRICE = 1200;

const appointmentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  room: {
    type: String,
    required: true,
    enum: ['Aircon Room', 'Fan Room', 'Seaside Cottage'] 
  },
  cottageAddon: {
    type: Boolean,
    default: false
  },
  totalPrice: {
    type: Number,
    default: 0
  },
  checkin: {
    type: Date,
    required: true
  },
  checkout: {
    type: Date,
    required: true
  },
  guests: {
    type: Number,
    required: true,
    default: 1
  },
  contact: {
    type: String,
    required: true
  },
  specialRequests: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'declined'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * VIRTUAL PROPERTY: roomDisplayName
 * Creates a "pretty" name for the UI.
 */
appointmentSchema.virtual('roomDisplayName').get(function() {
  const names = {
    'Aircon Room': 'Aircon Suite',
    'Fan Room': 'Cozy Fan Room',
    'Seaside Cottage': 'Seaside Cottage'
  };
  
  let displayName = names[this.room] || this.room;
  
  if (this.cottageAddon && this.room !== 'Seaside Cottage') {
    displayName += ' + Cottage';
  }
  
  return displayName;
});

/**
 * PRE-SAVE HOOK: Price Calculation
 * This runs every time .save() is called.
 */
appointmentSchema.pre('save', async function() {
  try {
    // 1. Validate dates
    if (this.checkin >= this.checkout) {
      throw new Error('Check-out date must be after check-in date.');
    }

    // 2. Calculate Number of Nights
    // Convert the difference in milliseconds to days
    const diffTime = Math.abs(this.checkout - this.checkin);
    const diffNights = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    
    // Ensure at least 1 night is charged if dates are valid
    const nights = diffNights === 0 ? 1 : diffNights;

    // 3. Calculate Base Room Price
    let pricePerNight = ROOM_RATES[this.room] || 0;
    
    // 4. Add Cottage Addon if applicable
    // (Only adds if room isn't already the Seaside Cottage)
    if (this.cottageAddon && this.room !== 'Seaside Cottage') {
      pricePerNight += COTTAGE_ADDON_PRICE;
    }

    // 5. Set the final totalPrice
    this.totalPrice = pricePerNight * nights;

    console.log(`Booking logic: ${nights} night(s) at ₱${pricePerNight}/night. Total: ₱${this.totalPrice}`);
    
  } catch (err) {
    // Throwing an error here stops the save process
    throw err; 
  }
});

module.exports = mongoose.model('Appointment', appointmentSchema);