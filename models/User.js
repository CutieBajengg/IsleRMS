"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * models/User.js
 *
 * Customer / Guest account model.
 *
 * Responsibilities:
 * - Store customer identity information
 * - Securely hash passwords
 * - Compare login passwords
 * - Track account status
 * - Support login lockout
 * - Prepare for email verification
 * - Prepare for password reset
 * - Prevent sensitive fields from being exposed
 *
 * IMPORTANT:
 * Authentication flow itself belongs in the auth/service layer.
 * This model only handles user/account-level behavior.
 * ============================================================
 */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

/* ============================================================
   CONSTANTS
   ============================================================ */

const PASSWORD_MIN_LENGTH = 10;

const MAX_LOGIN_ATTEMPTS = 5;

const LOGIN_LOCK_DURATION_MS =
  15 * 60 * 1000;

/* ============================================================
   HELPERS
   ============================================================ */

/**
 * Normalize email addresses consistently.
 */
function normalizeEmail(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

/**
 * Normalize usernames consistently.
 */
function normalizeUsername(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "");
}

/**
 * Normalize phone numbers.
 *
 * Supported formats:
 * 09XXXXXXXXX
 * +639XXXXXXXXX
 *
 * Internally we store:
 * 09XXXXXXXXX
 */
function normalizePhone(value) {
  const phone = String(value ?? "")
    .trim()
    .replace(/[\s()-]/g, "");

  if (!phone) {
    return undefined;
  }

  if (/^\+639\d{9}$/.test(phone)) {
    return `0${phone.slice(3)}`;
  }

  if (/^639\d{9}$/.test(phone)) {
    return `0${phone.slice(2)}`;
  }

  return phone;
}

/* ============================================================
   USER SCHEMA
   ============================================================ */

const userSchema = new mongoose.Schema(
  {
    /* ----------------------------------------------------------
       IDENTITY
    ---------------------------------------------------------- */

    fullname: {
      type: String,

      required: [
        true,
        "Full name is required",
      ],

      trim: true,

      maxlength: [
        100,
        "Full name cannot exceed 100 characters.",
      ],
    },

    username: {
      type: String,

      trim: true,

      lowercase: true,

      unique: true,

      sparse: true,

      maxlength: [
        50,
        "Username cannot exceed 50 characters.",
      ],

      set: normalizeUsername,

      validate: {
        validator(value) {
          /*
           * Username is optional.
           * When provided, allow letters, numbers,
           * dots, underscores and hyphens.
           */
          if (!value) {
            return true;
          }

          return /^[a-z0-9._-]+$/i.test(value);
        },

        message:
          "Username may only contain letters, numbers, dots, underscores, and hyphens.",
      },
    },

    email: {
      type: String,

      required: [
        true,
        "Email is required",
      ],

      unique: true,

      lowercase: true,

      trim: true,

      set: normalizeEmail,

      maxlength: [
        254,
        "Email address is too long.",
      ],

      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address.",
      ],
    },

    phone: {
      type: String,

      trim: true,

      set: normalizePhone,

      maxlength: [
        20,
        "Phone number is too long.",
      ],

      validate: {
        validator(value) {
          if (!value) {
            return true;
          }

          /*
           * Accept Philippine mobile format:
           * 09XXXXXXXXX
           */
          return /^09\d{9}$/.test(value);
        },

        message:
          "Please provide a valid Philippine mobile number.",
      },
    },

    /* ----------------------------------------------------------
       AUTHENTICATION
    ---------------------------------------------------------- */

    password: {
      type: String,

      required: [
        true,
        "Password is required",
      ],

      /*
       * Password is hidden from normal MongoDB queries.
       *
       * Login must explicitly request it:
       * .select("+password")
       */
      select: false,
    },

    /* ----------------------------------------------------------
       ACCOUNT STATUS
    ---------------------------------------------------------- */

    status: {
      type: String,

      enum: {
        values: [
          "active",
          "suspended",
          "disabled",
        ],

        message:
          "Invalid account status.",
      },

      default: "active",

      index: true,
    },

    /* ----------------------------------------------------------
       EMAIL VERIFICATION
    ---------------------------------------------------------- */

    emailVerified: {
      type: Boolean,

      default: false,

      index: true,
    },

    emailVerificationTokenHash: {
      type: String,

      select: false,

      default: null,
    },

    emailVerificationExpiresAt: {
      type: Date,

      select: false,

      default: null,
    },

    /* ----------------------------------------------------------
       PASSWORD RESET
    ---------------------------------------------------------- */

    passwordResetTokenHash: {
      type: String,

      select: false,

      default: null,
    },

    passwordResetExpiresAt: {
      type: Date,

      select: false,

      default: null,
    },

    /* ----------------------------------------------------------
       LOGIN SECURITY
    ---------------------------------------------------------- */

    failedLoginAttempts: {
      type: Number,

      default: 0,

      min: [
        0,
        "Failed login attempts cannot be negative.",
      ],
    },

    lockedUntil: {
      type: Date,

      default: null,
    },

    lastLoginAt: {
      type: Date,

      default: null,
    },

    passwordChangedAt: {
      type: Date,

      default: null,
    },
  },

  {
    timestamps: true,

    /*
     * Don't automatically expose hidden security
     * properties through JSON serialization.
     */
    toJSON: {
      virtuals: true,

      transform: function (doc, ret) {
        delete ret.password;

        delete ret.emailVerificationTokenHash;

        delete ret.emailVerificationExpiresAt;

        delete ret.passwordResetTokenHash;

        delete ret.passwordResetExpiresAt;

        delete ret.failedLoginAttempts;

        delete ret.lockedUntil;

        return ret;
      },
    },

    toObject: {
      virtuals: true,
    },
  }
);

/* ============================================================
   INDEXES
   ============================================================ */

/*
 * Email and username already create their required indexes
 * through `unique: true`.
 *
 * Status already creates its lookup index through
 * `index: true` on the schema field.
 *
 * Do not declare the same indexes again with
 * userSchema.index(), or Mongoose will emit duplicate-index
 * warnings during startup.
 */

/* ============================================================
   VIRTUALS
   ============================================================ */

/**
 * Check whether the account is currently locked.
 */
userSchema.virtual("isLocked").get(function () {
  return Boolean(
    this.lockedUntil &&
      this.lockedUntil.getTime() >
        Date.now()
  );
});

/**
 * Safe display name for UI.
 */
userSchema.virtual("displayName").get(function () {
  return (
    this.fullname ||
    this.username ||
    this.email ||
    "Guest"
  );
});

/* ============================================================
   PRE-SAVE
   ============================================================ */

/**
 * Secure password hashing.
 *
 * Passwords are only hashed when they are modified.
 *
 * This also means:
 * - creating a user hashes the password
 * - changing a password hashes the new password
 * - updating a profile without touching password
 *   does NOT hash the existing password again
 */
userSchema.pre(
  "save",
  async function () {
    if (!this.isModified("password")) {
      return;
    }

    /*
     * The password at this stage should still be
     * the plain-text password supplied by the application.
     *
     * We validate it BEFORE hashing.
     */
    if (
      typeof this.password !== "string" ||
      this.password.length <
        PASSWORD_MIN_LENGTH
    ) {
      throw new Error(
        `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
      );
    }

    const salt =
      await bcrypt.genSalt(10);

    this.password =
      await bcrypt.hash(
        this.password,
        salt
      );

    this.passwordChangedAt =
      new Date();
  }
);

/* ============================================================
   PASSWORD METHODS
   ============================================================ */

/**
 * Set a new password.
 *
 * This method is useful for:
 * - signup
 * - password change
 * - password reset
 */
userSchema.methods.setPassword =
  async function (newPassword) {
    const password =
      String(newPassword ?? "");

    if (
      password.length <
      PASSWORD_MIN_LENGTH
    ) {
      throw new Error(
        `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
      );
    }

    /*
     * Assign plain text here.
     * The pre-save hook hashes it.
     */
    this.password = password;

    return this;
  };

/**
 * Compare a supplied password against
 * the stored bcrypt hash.
 *
 * IMPORTANT:
 * The password field must be explicitly selected
 * for this method to work after using `select: false`.
 */
userSchema.methods.comparePassword =
  async function (candidatePassword) {
    if (
      !this.password ||
      typeof this.password !== "string"
    ) {
      return false;
    }

    return bcrypt.compare(
      String(candidatePassword ?? ""),
      this.password
    );
  };

/* ============================================================
   LOGIN SECURITY METHODS
   ============================================================ */

/**
 * Record a failed login attempt.
 *
 * After MAX_LOGIN_ATTEMPTS, the account is temporarily
 * locked.
 */
userSchema.methods.recordFailedLogin =
  async function () {
    this.failedLoginAttempts =
      Math.max(
        0,
        Number(
          this.failedLoginAttempts || 0
        )
      ) + 1;

    if (
      this.failedLoginAttempts >=
      MAX_LOGIN_ATTEMPTS
    ) {
      this.lockedUntil =
        new Date(
          Date.now() +
            LOGIN_LOCK_DURATION_MS
        );

      /*
       * Reset counter after lock is established.
       * The lock itself is the source of truth.
       */
      this.failedLoginAttempts = 0;
    }

    await this.save();

    return this;
  };

/**
 * Clear failed-login state after
 * a successful authentication.
 */
userSchema.methods.resetLoginSecurity =
  async function () {
    this.failedLoginAttempts = 0;

    this.lockedUntil = null;

    this.lastLoginAt =
      new Date();

    await this.save();

    return this;
  };

/**
 * Check whether the user is currently
 * prevented from logging in.
 */
userSchema.methods.isCurrentlyLocked =
  function () {
    return Boolean(
      this.lockedUntil &&
        this.lockedUntil.getTime() >
          Date.now()
    );
  };

/**
 * Automatically clear an expired lock.
 */
userSchema.methods.clearExpiredLock =
  async function () {
    if (
      this.lockedUntil &&
      this.lockedUntil.getTime() <=
        Date.now()
    ) {
      this.lockedUntil = null;

      this.failedLoginAttempts = 0;

      await this.save();
    }

    return this;
  };

/* ============================================================
   ACCOUNT SECURITY METHODS
   ============================================================ */

/**
 * Check whether the account is allowed
 * to authenticate.
 */
userSchema.methods.canAuthenticate =
  function () {
    return (
      this.status === "active" &&
      !this.isCurrentlyLocked()
    );
  };

/* ============================================================
   STATIC HELPERS
   ============================================================ */

/**
 * Find a customer by email.
 */
userSchema.statics.findByEmail =
  function (email) {
    return this.findOne({
      email:
        normalizeEmail(email),
    });
  };

/**
 * Find a customer by email or username.
 */
userSchema.statics.findByIdentifier =
  function (identifier) {
    const value =
      String(identifier ?? "")
        .trim()
        .toLowerCase();

    return this.findOne({
      $or: [
        {
          email: value,
        },
        {
          username: value,
        },
      ],
    });
  };

/* ============================================================
   MODEL
   ============================================================ */

const User =
  mongoose.model(
    "User",
    userSchema
  );

module.exports = User;