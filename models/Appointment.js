const mongoose = require("mongoose");

// ============================================================
// Puffer Isle Resort | Isle RMS
// Appointment / Booking Model
// ============================================================
//
// This model is the single source of truth for:
//
// - Booking dates
// - Guest limits
// - Room types
// - Room pricing
// - Cottage add-on pricing
// - Booking status
// - Total price calculation
// - Check-in information
// - Booking timestamps
// - Database indexes
//
// IMPORTANT:
// Never trust totalPrice sent by the browser.
// Pricing is recalculated on the server.
// ============================================================


// ============================================================
// CONSTANTS
// ============================================================

const ROOM_TYPES = [
  "Aircon Room",
  "Fan Room",
  "Seaside Cottage",
];


// ------------------------------------------------------------
// Room rates per night
// ------------------------------------------------------------

const ROOM_RATES = Object.freeze({
  "Aircon Room": 3500,
  "Fan Room": 2500,
  "Seaside Cottage": 1200,
});


// ------------------------------------------------------------
// Maximum guests per room
// ------------------------------------------------------------

const ROOM_GUEST_LIMITS = Object.freeze({
  "Aircon Room": 8,
  "Fan Room": 6,
  "Seaside Cottage": 6,
});


// ------------------------------------------------------------
// Cottage add-on
// ------------------------------------------------------------

const COTTAGE_ADDON_PRICE = 1200;


// ------------------------------------------------------------
// Booking statuses
// ------------------------------------------------------------
//
// pending:
//     Booking request submitted.
//     Currently reserves the room.
//
// accepted:
//     Admin confirmed the booking.
//     Reserves the room.
//
// declined:
//     Booking rejected.
//     Does NOT reserve the room.
//
// cancelled:
//     Booking cancelled.
//     Does NOT reserve the room.
//
// ------------------------------------------------------------

const BOOKING_STATUSES = [
  "pending",
  "accepted",
  "declined",
  "cancelled",
];


// ------------------------------------------------------------
// Statuses that occupy/reserve a room
// ------------------------------------------------------------

const RESERVING_STATUSES = [
  "pending",
  "accepted",
];


// ------------------------------------------------------------
// Date constants
// ------------------------------------------------------------

const MILLISECONDS_PER_DAY =
  1000 * 60 * 60 * 24;


// ============================================================
// SCHEMA
// ============================================================

const appointmentSchema = new mongoose.Schema(
  {
    // --------------------------------------------------------
    // USER
    // --------------------------------------------------------

    userId: {
      type: mongoose.Schema.Types.ObjectId,

      ref: "User",

      required: [true, "User is required"],

      index: true,
    },


    // --------------------------------------------------------
    // ROOM
    // --------------------------------------------------------

    room: {
      type: String,

      required: [true, "Room is required"],

      enum: {
        values: ROOM_TYPES,

        message:
          "Please select a valid accommodation.",
      },

      index: true,
    },


    // --------------------------------------------------------
    // COTTAGE ADD-ON
    // --------------------------------------------------------

    cottageAddon: {
      type: Boolean,

      default: false,
    },


    // --------------------------------------------------------
    // NUMBER OF NIGHTS
    // --------------------------------------------------------
    //
    // Stored for:
    // - invoices
    // - admin dashboard
    // - reporting
    // - easier UI rendering
    //
    // It is recalculated by the model.
    // --------------------------------------------------------

    nights: {
      type: Number,

      min: [1, "A booking must be at least one night."],

      default: 1,
    },


    // --------------------------------------------------------
    // TOTAL PRICE
    // --------------------------------------------------------
    //
    // This is calculated server-side.
    //
    // Do NOT trust a value submitted by the browser.
    // --------------------------------------------------------

    totalPrice: {
      type: Number,

      min: [
        0,
        "Total price cannot be negative.",
      ],

      default: 0,
    },


    // --------------------------------------------------------
    // CHECK-IN
    // --------------------------------------------------------

    checkin: {
      type: Date,

      required: [
        true,
        "Check-in date is required.",
      ],

      index: true,
    },


    // --------------------------------------------------------
    // CHECK-OUT
    // --------------------------------------------------------

    checkout: {
      type: Date,

      required: [
        true,
        "Check-out date is required.",
      ],

      index: true,
    },


    // --------------------------------------------------------
    // GUESTS
    // --------------------------------------------------------

    guests: {
      type: Number,

      required: [
        true,
        "Number of guests is required.",
      ],

      min: [
        1,
        "At least one guest is required.",
      ],

      validate: {
        validator: Number.isInteger,

        message:
          "Number of guests must be a whole number.",
      },

      default: 1,
    },


    // --------------------------------------------------------
    // CONTACT
    // --------------------------------------------------------

    contact: {
      type: String,

      required: [
        true,
        "Contact information is required.",
      ],

      trim: true,

      minlength: [
        3,
        "Contact information is too short.",
      ],

      maxlength: [
        100,
        "Contact information is too long.",
      ],
    },


    // --------------------------------------------------------
    // SPECIAL REQUESTS
    // --------------------------------------------------------

    specialRequests: {
      type: String,

      trim: true,

      maxlength: [
        1000,
        "Special requests cannot exceed 1000 characters.",
      ],

      default: "",
    },


    // --------------------------------------------------------
    // BOOKING STATUS
    // --------------------------------------------------------

    status: {
      type: String,

      enum: {
        values: BOOKING_STATUSES,

        message:
          "Invalid booking status.",
      },

      default: "pending",

      index: true,
    },


    // --------------------------------------------------------
    // CHECK-IN STATUS
    // --------------------------------------------------------

    checkedIn: {
      type: Boolean,

      default: false,

      index: true,
    },


    // --------------------------------------------------------
    // ACTUAL CHECK-IN TIME
    // --------------------------------------------------------

    checkInTime: {
      type: Date,

      default: null,
    },
  },

  {
    // --------------------------------------------------------
    // AUTOMATIC TIMESTAMPS
    // --------------------------------------------------------
    //
    // Creates:
    //
    // createdAt
    // updatedAt
    //
    // This fixes the notification code in server.js which
    // already expects updatedAt to exist.
    // --------------------------------------------------------

    timestamps: true,


    // --------------------------------------------------------
    // VIRTUALS
    // --------------------------------------------------------

    toJSON: {
      virtuals: true,
    },

    toObject: {
      virtuals: true,
    },

    
  }
);


// ============================================================
// VIRTUAL: ROOM DISPLAY NAME
// ============================================================

appointmentSchema.virtual("roomDisplayName").get(
  function () {
    const names = {
      "Aircon Room": "Aircon Suite",

      "Fan Room": "Cozy Fan Room",

      "Seaside Cottage": "Seaside Cottage",
    };

    let displayName =
      names[this.room] || this.room;


    if (
      this.cottageAddon &&
      this.room !== "Seaside Cottage"
    ) {
      displayName += " + Cottage";
    }


    return displayName;
  }
);


// ============================================================
// VIRTUAL: PRICE PER NIGHT
// ============================================================

appointmentSchema.virtual("pricePerNight").get(
  function () {
    const baseRate =
      ROOM_RATES[this.room] || 0;


    if (
      this.cottageAddon &&
      this.room !== "Seaside Cottage"
    ) {
      return (
        baseRate +
        COTTAGE_ADDON_PRICE
      );
    }


    return baseRate;
  }
);


// ============================================================
// STATIC: GET ROOM RATES
// ============================================================

appointmentSchema.statics.getRoomRates =
  function () {
    return {
      ...ROOM_RATES,
    };
  };


// ============================================================
// STATIC: GET ROOM GUEST LIMITS
// ============================================================

appointmentSchema.statics.getRoomGuestLimits =
  function () {
    return {
      ...ROOM_GUEST_LIMITS,
    };
  };


// ============================================================
// STATIC: GET ROOM CAPACITY
// ============================================================

appointmentSchema.statics.getRoomCapacity =
  function (room) {
    return ROOM_GUEST_LIMITS[room] || null;
  };


// ============================================================
// STATIC: GET ROOM RATE
// ============================================================

appointmentSchema.statics.getRoomRate =
  function (room) {
    return ROOM_RATES[room] || null;
  };


// ============================================================
// STATIC: VALIDATE DATES
// ============================================================
//
// Centralized date validation.
//
// Returns:
//
// {
//   valid: true,
//   start,
//   end,
//   nights
// }
//
// OR:
//
// {
//   valid: false,
//   message
// }
// ============================================================

appointmentSchema.statics.validateBookingDates =
  function (checkin, checkout) {
    const start =
      checkin instanceof Date
        ? new Date(checkin)
        : new Date(checkin);


    const end =
      checkout instanceof Date
        ? new Date(checkout)
        : new Date(checkout);


    // --------------------------------------------------------
    // Invalid dates
    // --------------------------------------------------------

    if (
      Number.isNaN(start.getTime()) ||
      Number.isNaN(end.getTime())
    ) {
      return {
        valid: false,

        message:
          "Invalid booking dates.",
      };
    }


    // --------------------------------------------------------
    // Check-out must be after check-in
    // --------------------------------------------------------

    if (end <= start) {
      return {
        valid: false,

        message:
          "Check-out must be after check-in.",
      };
    }


    // --------------------------------------------------------
    // Prevent bookings in the past
    // --------------------------------------------------------

    const now = new Date();

    const todayStart =
      new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate()
      );


    if (start < todayStart) {
      return {
        valid: false,

        message:
          "Check-in date cannot be in the past.",
      };
    }


    // --------------------------------------------------------
    // Calculate nights
    // --------------------------------------------------------

    const milliseconds =
      end.getTime() -
      start.getTime();


    const nights =
      Math.ceil(
        milliseconds /
          MILLISECONDS_PER_DAY
      );


    if (nights < 1) {
      return {
        valid: false,

        message:
          "A booking must be at least one night.",
      };
    }


    return {
      valid: true,

      start,

      end,

      nights,
    };
  };


// ============================================================
// STATIC: VALIDATE GUEST COUNT
// ============================================================

appointmentSchema.statics.validateGuestCount =
  function (room, guests) {
    const guestCount =
      Number(guests);


    if (
      !Number.isInteger(
        guestCount
      )
    ) {
      return {
        valid: false,

        message:
          "Number of guests must be a whole number.",
      };
    }


    if (guestCount < 1) {
      return {
        valid: false,

        message:
          "At least one guest is required.",
      };
    }


    const maximumGuests =
      ROOM_GUEST_LIMITS[room];


    if (!maximumGuests) {
      return {
        valid: false,

        message:
          "Invalid room type.",
      };
    }


    if (
      guestCount >
      maximumGuests
    ) {
      return {
        valid: false,

        message:
          `${room} allows a maximum of ${maximumGuests} guests.`,
      };
    }


    return {
      valid: true,

      guests: guestCount,

      maximumGuests,
    };
  };


// ============================================================
// STATIC: CALCULATE PRICE
// ============================================================
//
// IMPORTANT:
//
// This is the method your current server.js expects:
//
// Appointment.calculatePrice(...)
//
// The browser's totalPrice is never used here.
// ============================================================

appointmentSchema.statics.calculatePrice =
  function ({
    room,
    cottageAddon = false,
    checkin,
    checkout,
  }) {
    // --------------------------------------------------------
    // Validate room
    // --------------------------------------------------------

    if (
      !ROOM_TYPES.includes(room)
    ) {
      throw new Error(
        "Invalid room type."
      );
    }


    // --------------------------------------------------------
    // Validate dates
    // --------------------------------------------------------

    const dateValidation =
      this.validateBookingDates(
        checkin,
        checkout
      );


    if (
      !dateValidation.valid
    ) {
      throw new Error(
        dateValidation.message
      );
    }


    const {
      nights,
    } = dateValidation;


    // --------------------------------------------------------
    // Base room rate
    // --------------------------------------------------------

    const baseRate =
      ROOM_RATES[room];


    // --------------------------------------------------------
    // Cottage add-on
    // --------------------------------------------------------
    //
    // Seaside Cottage already IS the cottage.
    // Therefore the add-on is never charged.
    // --------------------------------------------------------

    const validCottageAddon =
      room === "Seaside Cottage"
        ? false
        : Boolean(cottageAddon);


    const addonRate =
      validCottageAddon
        ? COTTAGE_ADDON_PRICE
        : 0;


    // --------------------------------------------------------
    // Final nightly rate
    // --------------------------------------------------------

    const pricePerNight =
      baseRate +
      addonRate;


    // --------------------------------------------------------
    // Final booking price
    // --------------------------------------------------------

    const totalPrice =
      pricePerNight *
      nights;


    return {
      room,

      nights,

      baseRate,

      cottageAddon:
        validCottageAddon,

      addonRate,

      pricePerNight,

      totalPrice,
    };
  };


// ============================================================
// STATIC: FIND CONFLICTING BOOKING
// ============================================================
//
// This is the reusable overlap query.
//
// A booking conflicts when:
//
// existing.checkin < requested.checkout
//
// AND
//
// existing.checkout > requested.checkin
//
// Pending and accepted bookings reserve the room.
//
// Declined and cancelled bookings do not.
// ============================================================

appointmentSchema.statics.findConflictingBooking =
  function ({
    room,
    checkin,
    checkout,
    excludeId = null,
  }) {
    const query = {
      room,

      status: {
        $in: RESERVING_STATUSES,
      },

      checkin: {
        $lt: checkout,
      },

      checkout: {
        $gt: checkin,
      },
    };


    if (
      excludeId &&
      mongoose.Types.ObjectId.isValid(
        excludeId
      )
    ) {
      query._id = {
        $ne: excludeId,
      };
    }


    return this.findOne(query)
      .sort({
        checkin: 1,
      });
  };


// ============================================================
// PRE-VALIDATE
// ============================================================
//
// Runs before Mongoose validation.
//
// This provides model-level protection even if another route
// attempts to create an Appointment without using server.js.
// ============================================================

appointmentSchema.pre(
  "validate",
  function (next) {
    try {
      // ------------------------------------------------------
      // Date validation
      // ------------------------------------------------------

      const dateValidation =
        this.constructor.validateBookingDates(
          this.checkin,
          this.checkout
        );


      if (
        !dateValidation.valid
      ) {
        return next(
          new Error(
            dateValidation.message
          )
        );
      }


      // ------------------------------------------------------
      // Guest validation
      // ------------------------------------------------------

      const guestValidation =
        this.constructor.validateGuestCount(
          this.room,
          this.guests
        );


      if (
        !guestValidation.valid
      ) {
        return next(
          new Error(
            guestValidation.message
          )
        );
      }


      // ------------------------------------------------------
      // Cottage add-on normalization
      // ------------------------------------------------------
      //
      // A Seaside Cottage cannot have a second cottage add-on.
      // ------------------------------------------------------

      if (
        this.room ===
        "Seaside Cottage"
      ) {
        this.cottageAddon =
          false;
      }


      // ------------------------------------------------------
      // Store calculated nights
      // ------------------------------------------------------

      this.nights =
        dateValidation.nights;


      next();

    } catch (error) {
      next(error);
    }
  }
);


// ============================================================
// PRE-SAVE
// ============================================================
//
// Recalculate price every time the document is saved.
//
// This means:
//
// booking.totalPrice = fake browser value
//
// is overwritten by the real server calculation.
// ============================================================

appointmentSchema.pre(
  "save",
  function (next) {
    try {
      const pricing =
        this.constructor.calculatePrice({
          room: this.room,

          cottageAddon:
            this.cottageAddon,

          checkin:
            this.checkin,

          checkout:
            this.checkout,
        });


      this.nights =
        pricing.nights;


      this.cottageAddon =
        pricing.cottageAddon;


      this.totalPrice =
        pricing.totalPrice;


      next();

    } catch (error) {
      next(error);
    }
  }
);


// ============================================================
// PRE-SAVE: CHECK-IN SAFETY
// ============================================================
//
// Keep checkInTime consistent with checkedIn.
// ============================================================

appointmentSchema.pre(
  "save",
  function (next) {
    if (!this.checkedIn) {
      this.checkInTime = null;
    }


    if (
      this.checkedIn &&
      !this.checkInTime
    ) {
      this.checkInTime = new Date();
    }


    next();
  }
);


// ============================================================
// INDEXES
// ============================================================
//
// These indexes improve:
//
// - User booking history
// - Admin booking lists
// - Room availability searches
// - Status filtering
// - Date overlap queries
//
// IMPORTANT:
// MongoDB indexes improve performance but do NOT by themselves
// guarantee that two date ranges cannot overlap.
//
// True race-condition protection will be handled in the
// booking/service layer we build next.
// ============================================================

appointmentSchema.index({
  userId: 1,

  createdAt: -1,
});


appointmentSchema.index({
  room: 1,

  status: 1,

  checkin: 1,

  checkout: 1,
});


appointmentSchema.index({
  status: 1,

  checkin: 1,

  checkout: 1,
});


appointmentSchema.index({
  checkedIn: 1,

  checkin: 1,
});


// ============================================================
// MODEL
// ============================================================

const Appointment =
  mongoose.model(
    "Appointment",
    appointmentSchema
  );


// ============================================================
// EXPORT CONSTANTS FOR SERVER-SIDE USE
// ============================================================
//
// These are exposed without changing the Mongoose model API.
//
// Usage:
//
// const {
//   ROOM_RATES,
//   ROOM_GUEST_LIMITS,
//   BOOKING_STATUSES,
//   RESERVING_STATUSES
// } = require("./models/Appointment");
// ============================================================

Appointment.ROOM_RATES =
  ROOM_RATES;

Appointment.ROOM_GUEST_LIMITS =
  ROOM_GUEST_LIMITS;

Appointment.ROOM_TYPES =
  ROOM_TYPES;

Appointment.BOOKING_STATUSES =
  BOOKING_STATUSES;

Appointment.RESERVING_STATUSES =
  RESERVING_STATUSES;

Appointment.COTTAGE_ADDON_PRICE =
  COTTAGE_ADDON_PRICE;


module.exports = Appointment;