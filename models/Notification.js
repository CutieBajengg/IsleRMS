// models/Notification.js
/**
 * Puffer Isle Resort | Notification Model
 * Handles in-app user notifications for appointments, system updates, alerts,
 * security events, and future notification-channel expansion.
 */

const mongoose = require("mongoose");

const NOTIFICATION_TYPES = ["appointment", "system", "alert"];

const NOTIFICATION_EVENTS = [
  "general",
  "created",
  "accepted",
  "confirmed",
  "declined",
  "rejected",
  "cancelled",
  "checked-in",
  "checked-out",
  "completed",
  "reminder",
  "payment",
  "security",
];

const NOTIFICATION_PRIORITIES = ["low", "normal", "high", "urgent"];

// Backwards compatibility for older route/admin code that used the status
// itself as the notification type, or used "booking" as the type.
const LEGACY_TYPE_TO_EVENT = {
  booking: "created",
  accepted: "accepted",
  confirmed: "confirmed",
  declined: "declined",
  rejected: "rejected",
  cancelled: "cancelled",
  "checked-in": "checked-in",
  "checked-out": "checked-out",
  completed: "completed",
};

const DEFAULT_TITLES = {
  created: "Reservation Received",
  accepted: "Reservation Accepted",
  confirmed: "Reservation Confirmed",
  declined: "Reservation Declined",
  rejected: "Reservation Rejected",
  cancelled: "Reservation Cancelled",
  "checked-in": "Check-in Completed",
  "checked-out": "Check-out Completed",
  completed: "Reservation Completed",
  reminder: "Reservation Reminder",
  payment: "Payment Update",
  security: "Security Notice",
  general: "Update",
};

const notificationSchema = new mongoose.Schema(
  {
    // Recipient
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Notification must be associated with a user."],
      index: true,
    },

    // Presentation
    title: {
      type: String,
      trim: true,
      maxlength: [120, "Notification title cannot exceed 120 characters."],
    },

    message: {
      type: String,
      required: [true, "Notification message cannot be empty."],
      trim: true,
      maxlength: [2000, "Notification message cannot exceed 2000 characters."],
    },

    // High-level category retained for compatibility with the current UI.
    type: {
      type: String,
      enum: NOTIFICATION_TYPES,
      default: "system",
      index: true,
    },

    // Business event gives the notification a precise meaning without
    // overloading the high-level "type" field.
    event: {
      type: String,
      enum: NOTIFICATION_EVENTS,
      default: "general",
      index: true,
    },

    priority: {
      type: String,
      enum: NOTIFICATION_PRIORITIES,
      default: "normal",
      index: true,
    },

    // Optional relationship to a reservation/appointment.
    appointmentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Appointment",
      default: null,
      index: true,
    },

    // Kept as a real path for compatibility with older admin helpers/code.
    // It is synchronized with appointmentId in the validation hook.
    bookingId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Appointment",
      default: null,
      index: true,
    },

    // Optional UI action.
    // Example: /appointments?booking=...
    actionLabel: {
      type: String,
      trim: true,
      maxlength: [
        50,
        "Notification action label cannot exceed 50 characters.",
      ],
      default: null,
    },

    actionUrl: {
      type: String,
      trim: true,
      maxlength: [
        500,
        "Notification action URL cannot exceed 500 characters.",
      ],
      default: null,
    },

    // Flexible structured context for the notification center/API.
    // Examples:
    // roomName, checkin, checkout, amount, status, referenceNumber, etc.
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: undefined,
    },

    // Read state
    read: {
      type: Boolean,
      default: false,
      index: true,
    },

    readAt: {
      type: Date,
      default: null,
    },

    // Archive state lets users hide old notifications without
    // destroying the historical record.
    archived: {
      type: Boolean,
      default: false,
      index: true,
    },

    archivedAt: {
      type: Date,
      default: null,
    },

    // Optional expiry point for temporary reminders.
    // This is intentionally NOT a TTL index yet, so historical records
    // are not silently deleted by MongoDB.
    expiresAt: {
      type: Date,
      default: null,
      index: true,
    },
  },
  {
    timestamps: true,
    strict: true,
    toJSON: {
      virtuals: true,
    },
    toObject: {
      virtuals: true,
    },
  }
);

// ----------------------------
// Indexes
// ----------------------------

notificationSchema.index({
  userId: 1,
  createdAt: -1,
});

notificationSchema.index({
  userId: 1,
  archived: 1,
  read: 1,
  createdAt: -1,
});

notificationSchema.index({
  userId: 1,
  type: 1,
  createdAt: -1,
});

notificationSchema.index({
  appointmentId: 1,
  createdAt: -1,
});

notificationSchema.index({
  bookingId: 1,
  createdAt: -1,
});

// ----------------------------
// Virtuals
// ----------------------------

notificationSchema.virtual("status").get(function () {
  return this.read ? "Read" : "Unread";
});

notificationSchema.virtual("isUnread").get(function () {
  return !this.read;
});

// ----------------------------
// Validation / compatibility
// normalization
// ----------------------------

notificationSchema.pre("validate", function () {
  // Normalize legacy notification types such as "booking" or "accepted"
  // into the current type/event model instead of rejecting old writes.
  const legacyEvent = LEGACY_TYPE_TO_EVENT[this.type];

  if (legacyEvent) {
    this.event = legacyEvent;
    this.type = "appointment";
  }

  // Appointment and booking references stay synchronized.
  if (this.appointmentId && !this.bookingId) {
    this.bookingId = this.appointmentId;
  } else if (this.bookingId && !this.appointmentId) {
    this.appointmentId = this.bookingId;
  }

  // Appointment notifications should have an appointment event.
  if (this.type === "appointment" && this.event === "general") {
    this.event = "created";
  }

  // Provide a professional default title when callers only supply a message.
  if (!this.title) {
    this.title =
      DEFAULT_TITLES[this.event] ||
      (this.type === "alert"
        ? "Important Alert"
        : this.type === "system"
        ? "System Update"
        : "Appointment Update");
  }

  // Keep timestamp fields consistent with their boolean state.
  if (this.read) {
    if (!this.readAt) {
      this.readAt = new Date();
    }
  } else {
    this.readAt = null;
  }

  if (this.archived) {
    if (!this.archivedAt) {
      this.archivedAt = new Date();
    }
  } else {
    this.archivedAt = null;
  }
});

// ----------------------------
// Instance methods
// ----------------------------

notificationSchema.methods.markAsRead = async function () {
  if (!this.read) {
    this.read = true;
    this.readAt = new Date();
    await this.save();
  }

  return this;
};

notificationSchema.methods.markAsUnread = async function () {
  if (this.read) {
    this.read = false;
    this.readAt = null;
    await this.save();
  }

  return this;
};

notificationSchema.methods.archive = async function () {
  if (!this.archived) {
    this.archived = true;
    this.archivedAt = new Date();
    await this.save();
  }

  return this;
};

notificationSchema.methods.unarchive = async function () {
  if (this.archived) {
    this.archived = false;
    this.archivedAt = null;
    await this.save();
  }

  return this;
};

// ----------------------------
// Static helpers
// ----------------------------

notificationSchema.statics.getUnreadCount = function (userId) {
  return this.countDocuments({
    userId,
    read: false,
    archived: false,
  });
};

notificationSchema.statics.markAllAsReadForUser = function (userId) {
  return this.updateMany(
    {
      userId,
      read: false,
      archived: false,
    },
    {
      $set: {
        read: true,
        readAt: new Date(),
      },
    }
  );
};

notificationSchema.statics.createAppointmentNotification =
  function ({
    userId,
    appointmentId,
    event,
    message,
    title,
    priority = "normal",
    actionLabel,
    actionUrl,
    metadata,
    expiresAt,
  }) {
    return this.create({
      userId,
      appointmentId,
      bookingId: appointmentId,
      type: "appointment",
      event,
      title,
      message,
      priority,
      actionLabel,
      actionUrl,
      metadata,
      expiresAt,
    });
  };

notificationSchema.statics.listForUser = function (
  userId,
  {
    includeArchived = false,
    unreadOnly = false,
    page = 1,
    limit = 20,
  } = {}
) {
  const safePage = Math.max(1, Number(page) || 1);
  const safeLimit = Math.min(100, Math.max(1, Number(limit) || 20));

  const filter = {
    userId,
    ...(includeArchived ? {} : { archived: false }),
    ...(unreadOnly ? { read: false } : {}),
  };

  return this.find(filter)
    .sort({
      createdAt: -1,
    })
    .skip((safePage - 1) * safeLimit)
    .limit(safeLimit)
    .lean();
};

// ----------------------------
// Export
// ----------------------------

const Notification = mongoose.model(
  "Notification",
  notificationSchema
);

Notification.TYPES = NOTIFICATION_TYPES;
Notification.EVENTS = NOTIFICATION_EVENTS;
Notification.PRIORITIES = NOTIFICATION_PRIORITIES;

module.exports = Notification;