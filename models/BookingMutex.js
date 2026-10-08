"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * models/BookingMutex.js
 *
 * MongoDB-backed distributed lock used to serialize
 * booking/inventory mutations for the same room.
 *
 * This prevents two Node.js requests or server instances
 * from simultaneously changing the same room inventory.
 *
 * IMPORTANT:
 * - This collection contains temporary lock records only.
 * - It is not part of the resort's business data.
 * - Expired locks are automatically cleaned by MongoDB.
 * ============================================================
 */

const mongoose = require("mongoose");

const bookingMutexSchema = new mongoose.Schema(
  {
    /*
     * Unique resource being locked.
     *
     * Example:
     *   room:68f1...
     *
     * Only one active mutex document can exist for a
     * particular resourceKey at a time.
     */
    resourceKey: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      index: true,
      maxlength: 200,
    },

    /*
     * Random token identifying the process/request that
     * currently owns the lock.
     */
    ownerToken: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },

    /*
     * Lease expiration time.
     *
     * When the application crashes or a request is abandoned,
     * the lock eventually becomes replaceable.
     */
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

/*
 * MongoDB TTL index.
 *
 * MongoDB automatically removes expired lock documents.
 *
 * NOTE:
 * TTL cleanup itself is not what makes the lock safe.
 * The booking service also checks expiresAt when acquiring
 * and releasing the lock.
 */
bookingMutexSchema.index(
  {
    expiresAt: 1,
  },
  {
    expireAfterSeconds: 0,
  }
);

/*
 * Reuse an already-registered model during development,
 * hot reloads, tests, or environments where this file may
 * be required more than once.
 */
module.exports =
  mongoose.models.BookingMutex ||
  mongoose.model(
    "BookingMutex",
    bookingMutexSchema
  );