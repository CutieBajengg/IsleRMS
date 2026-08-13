// models/Notification.js
/**
 * Puffer Isle Resort | Notification Model
 * Handles user notifications for appointments, system updates, and alerts
 * Author: Puffer Isle Resort Dev Team
 */

const mongoose = require("mongoose");

// ----------------------------
// Notification Schema
// ----------------------------
const notificationSchema = new mongoose.Schema(
  {
    // 🧍 User reference (recipient of the notification)
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Notification must be associated with a user."],
    },

    // 📝 Notification content
    message: {
      type: String,
      required: [true, "Notification message cannot be empty."],
      trim: true,
    },

    // 🏷️ Notification type (appointment, system, alert)
    type: {
      type: String,
      enum: ["appointment", "system", "alert"],
      default: "system",
    },

    // ✅ Read/unread status
    read: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true, // Automatically adds createdAt & updatedAt
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ----------------------------
// Virtual: human-readable status
// ----------------------------
notificationSchema.virtual("status").get(function () {
  return this.read ? "Read" : "Unread";
});

// ----------------------------
// Method: Mark notification as read
// ----------------------------
notificationSchema.methods.markAsRead = async function () {
  if (!this.read) {
    this.read = true;
    await this.save();
  }
  return this;
};

// ----------------------------
// Export Notification Model
// ----------------------------
module.exports = mongoose.model("Notification", notificationSchema);