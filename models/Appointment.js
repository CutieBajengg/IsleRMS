"use strict";

const mongoose = require("mongoose");

/*
|--------------------------------------------------------------------------
| Appointment Model
|--------------------------------------------------------------------------
| Puffer Isle Resort / IsleRMS
|
| Important design rule:
|
| Appointment stores a SNAPSHOT of the prices used when the booking
| was created.
|
| Room.js and AddOn.js contain the CURRENT catalog prices.
|
| Therefore:
|
|   Current catalog price changes
|          ↓
|   Future bookings use the new price
|
|   Existing appointment
|          ↓
|   Keeps its original stored price
|
| This protects historical booking records.
|--------------------------------------------------------------------------
*/

const BOOKING_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
  "declined",
  "rejected",
  "cancelled",
  "checked-in",
  "checked-out",
  "completed",
];

const BLOCKING_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
  "checked-in",
];

const CANCELLABLE_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
];

/*
|--------------------------------------------------------------------------
| Embedded Add-on Snapshot
|--------------------------------------------------------------------------
| We intentionally store the add-on name and price at booking time.
| This prevents future admin price changes from altering old bookings.
|--------------------------------------------------------------------------
*/

const addOnSnapshotSchema = new mongoose.Schema(
  {
    addOnId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "AddOn",
      default: null,
    },

    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    price: {
      type: Number,
      required: true,
      min: 0,
    },

    pricingType: {
      type: String,
      enum: ["perNight", "once"],
      default: "once",
    },

    quantity: {
      type: Number,
      default: 1,
      min: 1,
      validate: {
        validator: Number.isInteger,
        message: "Add-on quantity must be a whole number.",
      },
    },

    subtotal: {
      type: Number,
      required: true,
      min: 0,
    },
  },
  {
    _id: false,
  }
);

/*
|--------------------------------------------------------------------------
| Appointment Schema
|--------------------------------------------------------------------------
*/

const appointmentSchema = new mongoose.Schema(
  {
    /*
     * Owner of the booking.
     */
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    /*
     * Current catalog Room ID.
     *
     * This lets us connect the appointment to the catalog item,
     * while roomName/roomPrice below preserve historical information.
     */
    roomId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Room",
      default: null,
      index: true,
    },

    /*
     * Historical room name snapshot.
     *
     * Keep this even if an admin later renames or deactivates the room.
     */
    room: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true,
    },

    /*
     * Optional compatibility field.
     *
     * Older parts of the project may refer to roomType,
     * accommodation, or roomName. We keep these fields available
     * during the migration so existing records/views don't break.
     */
    roomType: {
      type: String,
      default: "",
      trim: true,
      maxlength: 100,
    },

    accommodation: {
      type: String,
      default: "",
      trim: true,
      maxlength: 100,
    },

    roomName: {
      type: String,
      default: "",
      trim: true,
      maxlength: 100,
    },

    /*
     * Historical room price at the time of booking.
     */
    roomPrice: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
     * Number of nights.
     *
     * This is stored because it is part of the historical
     * pricing record.
     */
    numberOfNights: {
      type: Number,
      default: 0,
      min: 0,
      validate: {
        validator: Number.isInteger,
        message: "Number of nights must be a whole number.",
      },
    },

    /*
     * Historical room subtotal.
     */
    roomSubtotal: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
     * Guest information.
     */
    guests: {
      type: Number,
      required: true,
      min: 1,
      validate: {
        validator: Number.isInteger,
        message: "Guest count must be a whole number.",
      },
    },

    /*
     * Contact number supplied for this booking.
     */
    contact: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    /*
     * Stay dates.
     */
    checkin: {
      type: Date,
      required: true,
      index: true,
    },

    checkout: {
      type: Date,
      required: true,
      index: true,
    },

    /*
     * Add-on snapshots.
     *
     * New booking code should populate this array from AddOn.js.
     */
    addOns: {
      type: [addOnSnapshotSchema],
      default: [],
    },

    /*
     * Legacy cottage compatibility.
     *
     * Old bookings may contain these fields.
     *
     * They remain historical data only; new booking logic should
     * use addOns instead.
     */
    cottageAddon: {
      type: Boolean,
      default: false,
    },

    cottagePrice: {
      type: Number,
      default: 0,
      min: 0,
    },

    cottageSubtotal: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
     * Optional pricing breakdown.
     */
    addOnSubtotal: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
     * Final server-calculated booking total.
     *
     * NEVER trust a client-provided totalPrice.
     */
    totalPrice: {
      type: Number,
      required: true,
      min: 0,
    },

    /*
     * Booking state.
     */
    status: {
      type: String,
      enum: {
        values: BOOKING_STATUSES,
        message: "Invalid appointment status.",
      },
      default: "pending",
      index: true,
    },

    /*
     * User/admin cancellation information.
     */
    cancelledAt: {
      type: Date,
      default: null,
    },

    cancelledBy: {
      type: String,
      enum: ["user", "admin", null],
      default: null,
    },

    /*
     * Check-in/check-out tracking.
     */
    checkedInAt: {
      type: Date,
      default: null,
    },

    checkedOutAt: {
      type: Date,
      default: null,
    },

    /*
     * Optional notes from the guest.
     */
    specialRequests: {
      type: String,
      default: "",
      trim: true,
      maxlength: 3000,
    },

    /*
     * Optional admin notes.
     */
    adminNotes: {
      type: String,
      default: "",
      trim: true,
      maxlength: 3000,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

/*
|--------------------------------------------------------------------------
| Indexes
|--------------------------------------------------------------------------
|
| These support the most common booking searches and availability
| checks.
|--------------------------------------------------------------------------
*/

appointmentSchema.index({
  room: 1,
  checkin: 1,
  checkout: 1,
  status: 1,
});

appointmentSchema.index({
  roomId: 1,
  checkin: 1,
  checkout: 1,
  status: 1,
});

appointmentSchema.index({
  userId: 1,
  createdAt: -1,
});

appointmentSchema.index({
  status: 1,
  checkin: 1,
});

/*
|--------------------------------------------------------------------------
| Validation
|--------------------------------------------------------------------------
| Prevent invalid date ranges.
|
| IMPORTANT:
| Mongoose 9 no longer uses the old pre-hook `next()` callback pattern.
| We therefore use a synchronous validation hook and throw on invalid
| date ranges.
|--------------------------------------------------------------------------
*/

appointmentSchema.pre("validate", function () {
  /*
   * Normalize room compatibility fields.
   */
  if (this.room) {
    this.room = String(this.room).trim();
  }

  if (!this.roomType && this.room) {
    this.roomType = this.room;
  }

  if (!this.accommodation && this.room) {
    this.accommodation = this.room;
  }

  if (!this.roomName && this.room) {
    this.roomName = this.room;
  }

  /*
   * Validate dates.
   */
  if (this.checkin && this.checkout) {
    if (this.checkout <= this.checkin) {
      throw new Error("Check-out must be after check-in.");
    }
  }
});

/*
|--------------------------------------------------------------------------
| Pricing Snapshot Helpers
|--------------------------------------------------------------------------
*/

/**
 * Calculate the number of nights between two dates.
 *
 * This function performs no database lookup and does not use
 * any hard-coded room or add-on prices.
 */
function calculateNumberOfNights(checkin, checkout) {
  const start = new Date(checkin);
  const end = new Date(checkout);

  if (
    Number.isNaN(start.getTime()) ||
    Number.isNaN(end.getTime()) ||
    end <= start
  ) {
    return 0;
  }

  const milliseconds =
    end.getTime() - start.getTime();

  return Math.ceil(
    milliseconds / (1000 * 60 * 60 * 24)
  );
}

/**
 * Calculate pricing from already-resolved catalog snapshots.
 *
 * IMPORTANT:
 * This method does not query Room.js/AddOn.js.
 *
 * The booking route/service is responsible for loading the
 * CURRENT catalog prices from MongoDB first.
 *
 * The resulting values are then frozen into the appointment.
 */
appointmentSchema.statics.calculateSnapshotPrice = function ({
  roomPrice,
  numberOfNights,
  addOns = [],
}) {
  const normalizedRoomPrice = Number(roomPrice);
  const nights = Math.floor(Number(numberOfNights));

  if (
    !Number.isFinite(normalizedRoomPrice) ||
    normalizedRoomPrice < 0
  ) {
    throw new Error("Invalid room price.");
  }

  if (!Number.isInteger(nights) || nights < 1) {
    throw new Error("Invalid number of nights.");
  }

  const roomSubtotal =
    normalizedRoomPrice * nights;

  let addOnSubtotal = 0;

  const snapshots = addOns.map((addOn) => {
    const price = Number(addOn.price);

    const quantity = Math.max(
      1,
      Math.floor(Number(addOn.quantity || 1))
    );

    if (!Number.isFinite(price) || price < 0) {
      throw new Error(
        `Invalid price for add-on "${addOn.name || "Unknown"}".`
      );
    }

    const pricingType =
      addOn.pricingType === "perNight"
        ? "perNight"
        : "once";

    const subtotal =
      pricingType === "perNight"
        ? price * nights * quantity
        : price * quantity;

    addOnSubtotal += subtotal;

    return {
      addOnId:
        addOn.addOnId || addOn._id || null,

      name: String(addOn.name || "").trim(),

      price,

      pricingType,

      quantity,

      subtotal,
    };
  });

  return {
    numberOfNights: nights,

    roomPrice: normalizedRoomPrice,

    roomSubtotal,

    addOns: snapshots,

    addOnSubtotal,

    totalPrice:
      roomSubtotal + addOnSubtotal,
  };
};

/*
|--------------------------------------------------------------------------
| Instance Pricing Helpers
|--------------------------------------------------------------------------
*/

/**
 * Return a plain historical pricing snapshot from an appointment.
 */
appointmentSchema.methods.getPricingSnapshot =
  function () {
    return {
      roomPrice: this.roomPrice,

      roomSubtotal: this.roomSubtotal,

      numberOfNights:
        this.numberOfNights,

      addOns: this.addOns.map(
        (addOn) => ({
          addOnId: addOn.addOnId,
          name: addOn.name,
          price: addOn.price,
          pricingType:
            addOn.pricingType,
          quantity: addOn.quantity,
          subtotal: addOn.subtotal,
        })
      ),

      addOnSubtotal:
        this.addOnSubtotal,

      /*
       * Legacy cottage data is preserved.
       */
      cottageAddon:
        this.cottageAddon,

      cottagePrice:
        this.cottagePrice,

      cottageSubtotal:
        this.cottageSubtotal,

      totalPrice:
        this.totalPrice,
    };
  };

/**
 * Convenience status checker.
 */
appointmentSchema.methods.isBlocking =
  function () {
    return BLOCKING_STATUSES.includes(
      String(this.status).toLowerCase()
    );
  };

appointmentSchema.methods.isCancellable =
  function () {
    return CANCELLABLE_STATUSES.includes(
      String(this.status).toLowerCase()
    );
  };

/*
|--------------------------------------------------------------------------
| Static Helpers
|--------------------------------------------------------------------------
*/

appointmentSchema.statics.getBlockingStatuses =
  function () {
    return [...BLOCKING_STATUSES];
  };

appointmentSchema.statics.getCancellableStatuses =
  function () {
    return [...CANCELLABLE_STATUSES];
  };

appointmentSchema.statics.getAllStatuses =
  function () {
    return [...BOOKING_STATUSES];
  };

/**
 * Find an appointment overlapping the supplied dates.
 *
 * Hotel-style overlap rule:
 *
 * existing.checkin < requested.checkout
 * AND
 * existing.checkout > requested.checkin
 */
appointmentSchema.statics.findConflictingBooking =
  async function ({
    roomId = null,
    room = null,
    checkin,
    checkout,
    excludeAppointmentId = null,
  }) {
    const start = new Date(checkin);
    const end = new Date(checkout);

    if (
      Number.isNaN(start.getTime()) ||
      Number.isNaN(end.getTime()) ||
      end <= start
    ) {
      return null;
    }

    const roomConditions = [];

    /*
     * Prefer roomId for modern bookings.
     */
    if (
      roomId &&
      mongoose.Types.ObjectId.isValid(roomId)
    ) {
      roomConditions.push({
        roomId,
      });
    }

    /*
     * Keep room-name matching for legacy appointments.
     */
    if (room) {
      const escapedRoom = String(room)
  .trim()
  .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      roomConditions.push({
        $or: [
          {
            room: new RegExp(
              `^${escapedRoom}$`,
              "i"
            ),
          },

          {
            roomType: new RegExp(
              `^${escapedRoom}$`,
              "i"
            ),
          },

          {
            accommodation: new RegExp(
              `^${escapedRoom}$`,
              "i"
            ),
          },

          {
            roomName: new RegExp(
              `^${escapedRoom}$`,
              "i"
            ),
          },
        ],
      });
    }

    if (roomConditions.length === 0) {
      return null;
    }

    const query = {
      status: {
        $in: BLOCKING_STATUSES,
      },

      checkin: {
        $lt: end,
      },

      checkout: {
        $gt: start,
      },

      $or: roomConditions,
    };

    if (
      excludeAppointmentId &&
      mongoose.Types.ObjectId.isValid(
        excludeAppointmentId
      )
    ) {
      query._id = {
        $ne: excludeAppointmentId,
      };
    }

    return this.findOne(query)
      .sort({
        checkin: 1,
      })
      .lean();
  };

/*
|--------------------------------------------------------------------------
| Query Helpers
|--------------------------------------------------------------------------
*/

appointmentSchema.query.blocking =
  function () {
    return this.where({
      status: {
        $in: BLOCKING_STATUSES,
      },
    });
  };

appointmentSchema.query.active =
  function () {
    return this.where({
      status: {
        $nin: [
          "declined",
          "rejected",
          "cancelled",
          "completed",
        ],
      },
    });
  };

/*
|--------------------------------------------------------------------------
| Export
|--------------------------------------------------------------------------
*/

module.exports =
  mongoose.models.Appointment ||
  mongoose.model(
    "Appointment",
    appointmentSchema
  );