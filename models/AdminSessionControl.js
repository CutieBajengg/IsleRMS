
"use strict";

const mongoose = require("mongoose");

const adminSessionControlSchema = new mongoose.Schema(
  {
    // One global record controls all administrator sessions.
    _id: {
      type: String,
      default: "global",
    },

    // Store only the hash of the active session token.
    activeSessionTokenHash: {
      type: String,
      default: null,
      select: false,
    },

    // The administrator account associated with the session.
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },

    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "admin_session_controls",
    versionKey: false,
  }
);

module.exports =
  mongoose.models.AdminSessionControl ||
  mongoose.model(
    "AdminSessionControl",
    adminSessionControlSchema
  );