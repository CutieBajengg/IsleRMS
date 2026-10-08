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
 * - Support local and Google authentication
 * - Track account status
 * - Support login lockout
 * - Support email verification / OTP
 * - Support password reset
 * - Prevent sensitive fields from being exposed
 *
 * IMPORTANT:
 * Authentication flow belongs in the auth/service layer.
 * This model handles user/account-level behavior only.
 * ============================================================
 */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

/* ============================================================
   CONSTANTS
============================================================ */

const PASSWORD_MIN_LENGTH = 10;

const MAX_LOGIN_ATTEMPTS = 5;

const LOGIN_LOCK_DURATION_MS =
  15 * 60 * 1000;

const EMAIL_OTP_LENGTH = 6;

const EMAIL_OTP_EXPIRATION_MS =
  10 * 60 * 1000;

const EMAIL_OTP_MAX_ATTEMPTS = 5;

const EMAIL_OTP_RESEND_COOLDOWN_MS =
  60 * 1000;

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
 *
 * Empty usernames return undefined rather than "",
 * so MongoDB sparse unique indexes behave correctly.
 */
function normalizeUsername(value) {
  const username =
    String(value ?? "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "");

  return username || undefined;
}

/**
 * Normalize Philippine phone numbers.
 *
 * Supported:
 *
 * 09XXXXXXXXX
 * +639XXXXXXXXX
 * 639XXXXXXXXX
 *
 * Internally:
 *
 * 09XXXXXXXXX
 */
function normalizePhone(value) {
  const phone =
    String(value ?? "")
      .trim()
      .replace(/[\s()-]/g, "");

  if (!phone) {
    return undefined;
  }

  if (
    /^\+639\d{9}$/.test(phone)
  ) {
    return `0${phone.slice(3)}`;
  }

  if (
    /^639\d{9}$/.test(phone)
  ) {
    return `0${phone.slice(2)}`;
  }

  return phone;
}

/**
 * Hash an OTP for secure database storage.
 *
 * The plain OTP is never stored in MongoDB.
 */
async function hashVerificationCode(code) {
  return bcrypt.hash(
    String(code ?? ""),
    10
  );
}

/**
 * Generate a random six-digit OTP.
 *
 * crypto.randomInt is used instead of Math.random().
 */
function generateVerificationCode() {
  const minimum = 100000;
  const maximum = 1000000;

  return String(
    crypto.randomInt(
      minimum,
      maximum
    )
  );
}

/* ============================================================
   USER SCHEMA
============================================================ */

const userSchema =
  new mongoose.Schema(
    {
      /* --------------------------------------------------------
         IDENTITY
      -------------------------------------------------------- */

      fullname: {
        type: String,

        required: [
          true,
          "Full name is required",
        ],

        trim: true,

        minlength: [
          2,
          "Full name must contain at least 2 characters.",
        ],

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

        set:
          normalizeUsername,

        validate: {
          validator(value) {
            if (!value) {
              return true;
            }

            return /^[a-z0-9._-]+$/i.test(
              value
            );
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

        set:
          normalizeEmail,

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

        set:
          normalizePhone,

        maxlength: [
          20,
          "Phone number is too long.",
        ],

        validate: {
          validator(value) {
            if (!value) {
              return true;
            }

            return /^09\d{9}$/.test(
              value
            );
          },

          message:
            "Please provide a valid Philippine mobile number.",
        },
      },

      /* --------------------------------------------------------
         AUTHENTICATION PROVIDER
      -------------------------------------------------------- */

      authProvider: {
        type: String,

        enum: {
          values: [
            "local",
            "google",
            "hybrid",
          ],

          message:
            "Invalid authentication provider.",
        },

        default: "local",

        index: true,
      },

      /**
       * Google account identifier.
       *
       * sparse + unique allows local accounts
       * to have no Google ID.
       */
      googleId: {
        type: String,

        unique: true,

        sparse: true,

        select: false,

        default: undefined,

        trim: true,
      },

      /**
       * Optional Google profile image.
       */
      avatarUrl: {
        type: String,

        trim: true,

        maxlength: [
          1000,
          "Avatar URL is too long.",
        ],

        default: null,
      },

      /* --------------------------------------------------------
         PASSWORD
      -------------------------------------------------------- */

      password: {
        type: String,

        /**
         * Local/hybrid accounts require passwords.
         * Google-only accounts do not.
         */
        required: function () {
          return (
            this.authProvider === "local" ||
            this.authProvider === "hybrid"
          );
        },

        select: false,
      },

      /**
       * Timestamp used to invalidate older
       * credentials/sessions in future auth hardening.
       */
      passwordChangedAt: {
        type: Date,

        default: null,
      },

      /* --------------------------------------------------------
         ACCOUNT STATUS
      -------------------------------------------------------- */

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

      /* --------------------------------------------------------
         EMAIL VERIFICATION
      -------------------------------------------------------- */

      emailVerified: {
        type: Boolean,

        default: false,

        index: true,
      },

      emailVerifiedAt: {
        type: Date,

        default: null,
      },

      /**
       * Legacy verification token support.
       *
       * Retained so older IsleRMS records remain compatible.
       */
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

      /**
       * Hashed six-digit email OTP.
       */
      emailVerificationCodeHash: {
        type: String,

        select: false,

        default: null,
      },

      /**
       * Current OTP expiration timestamp.
       */
      emailVerificationCodeExpiresAt: {
        type: Date,

        select: false,

        default: null,
      },

      /**
       * Failed OTP attempts.
       */
      emailVerificationAttempts: {
        type: Number,

        default: 0,

        min: 0,

        max:
          EMAIL_OTP_MAX_ATTEMPTS,

        select: false,
      },

      /**
       * Prevent repeated OTP requests.
       */
      emailVerificationResendAt: {
        type: Date,

        select: false,

        default: null,
      },

      /* --------------------------------------------------------
         PASSWORD RESET
      -------------------------------------------------------- */

      /**
       * SHA-256 hash of the one-time reset token.
       *
       * The raw token is only sent through the reset URL.
       */
      passwordResetTokenHash: {
        type: String,

        select: false,

        default: null,
      },

      /**
       * Expiration timestamp for the reset token.
       *
       * This is the canonical field name used by
       * the upgraded authentication flow.
       */
      passwordResetExpiresAt: {
        type: Date,

        select: false,

        default: null,
      },

      /* --------------------------------------------------------
         LOGIN SECURITY
      -------------------------------------------------------- */

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
    },

    {
      timestamps: true,

      /* --------------------------------------------------------
         JSON SECURITY
      -------------------------------------------------------- */

      toJSON: {
        virtuals: true,

        transform: function (
          doc,
          ret
        ) {
          delete ret.password;
          delete ret.googleId;

          delete ret.emailVerificationTokenHash;
          delete ret.emailVerificationExpiresAt;

          delete ret.emailVerificationCodeHash;
          delete ret.emailVerificationCodeExpiresAt;
          delete ret.emailVerificationAttempts;
          delete ret.emailVerificationResendAt;

          delete ret.passwordResetTokenHash;
          delete ret.passwordResetExpiresAt;

          delete ret.failedLoginAttempts;
          delete ret.lockedUntil;

          return ret;
        },
      },

      toObject: {
        virtuals: true,

        transform: function (
          doc,
          ret
        ) {
          delete ret.password;
          delete ret.googleId;

          delete ret.emailVerificationTokenHash;
          delete ret.emailVerificationExpiresAt;

          delete ret.emailVerificationCodeHash;
          delete ret.emailVerificationCodeExpiresAt;
          delete ret.emailVerificationAttempts;
          delete ret.emailVerificationResendAt;

          delete ret.passwordResetTokenHash;
          delete ret.passwordResetExpiresAt;

          delete ret.failedLoginAttempts;
          delete ret.lockedUntil;

          return ret;
        },
      },
    }
  );

/* ============================================================
   VIRTUALS
============================================================ */

/**
 * Whether login is currently locked.
 */
userSchema.virtual(
  "isLocked"
).get(function () {
  return Boolean(
    this.lockedUntil &&
    this.lockedUntil.getTime() >
      Date.now()
  );
});

/**
 * Safe display name for UI.
 */
userSchema.virtual(
  "displayName"
).get(function () {
  return (
    this.fullname ||
    this.username ||
    this.email ||
    "Guest"
  );
});

/**
 * Whether the current OTP has expired.
 */
userSchema.virtual(
  "isEmailVerificationExpired"
).get(function () {
  if (
    !this.emailVerificationCodeExpiresAt
  ) {
    return true;
  }

  return (
    this.emailVerificationCodeExpiresAt.getTime() <=
    Date.now()
  );
});

/* ============================================================
   PRE-SAVE
============================================================ */

userSchema.pre(
  "save",
  async function () {
    if (
      !this.isModified(
        "password"
      )
    ) {
      return;
    }

    /*
     * Google-only accounts should never receive a password hash
     * merely because an unrelated save happened.
     *
     * setPassword() changes Google accounts to hybrid first.
     */
    if (
      this.authProvider ===
      "google"
    ) {
      return;
    }

    if (
      typeof this.password !==
        "string" ||
      this.password.length <
        PASSWORD_MIN_LENGTH
    ) {
      throw new Error(
        `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
      );
    }

    /*
     * Avoid double hashing.
     *
     * setPassword() deliberately assigns the plain password and
     * this pre-save hook hashes it exactly once.
     */
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
 * Set a new local password.
 *
 * The password is hashed by the pre-save hook.
 */
userSchema.methods.setPassword =
  async function (
    newPassword
  ) {
    const password =
      String(
        newPassword ?? ""
      );

    if (
      password.length <
      PASSWORD_MIN_LENGTH
    ) {
      throw new Error(
        `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`
      );
    }

    if (
      password.length >
      128
    ) {
      throw new Error(
        "Password cannot exceed 128 characters."
      );
    }

    this.password =
      password;

    /*
     * Google accounts become hybrid accounts
     * once they establish a local password.
     */
    if (
      this.authProvider ===
      "google"
    ) {
      this.authProvider =
        "hybrid";
    }

    return this;
  };

/**
 * Compare supplied password to stored bcrypt hash.
 */
userSchema.methods.comparePassword =
  async function (
    candidatePassword
  ) {
    if (
      !this.password ||
      typeof this.password !==
        "string"
    ) {
      return false;
    }

    return bcrypt.compare(
      String(
        candidatePassword ?? ""
      ),
      this.password
    );
  };

/* ============================================================
   EMAIL VERIFICATION
============================================================ */

/**
 * Generate and store a new email verification code.
 *
 * Returns the plain OTP so the mailer can send it.
 *
 * The plain OTP is NEVER stored in MongoDB.
 */
userSchema.methods.createEmailVerificationCode =
  async function () {
    const now =
      Date.now();

    if (
      this.emailVerificationResendAt &&
      this.emailVerificationResendAt.getTime() >
        now
    ) {
      const remainingMs =
        this.emailVerificationResendAt.getTime() -
        now;

      const remainingSeconds =
        Math.ceil(
          remainingMs /
            1000
        );

      const error =
        new Error(
          `Please wait ${remainingSeconds} seconds before requesting another verification code.`
        );

      error.code =
        "OTP_RESEND_COOLDOWN";

      error.retryAfter =
        remainingSeconds;

      throw error;
    }

    const code =
      generateVerificationCode();

    this.emailVerificationCodeHash =
      await hashVerificationCode(
        code
      );

    this.emailVerificationCodeExpiresAt =
      new Date(
        now +
          EMAIL_OTP_EXPIRATION_MS
      );

    this.emailVerificationAttempts =
      0;

    this.emailVerificationResendAt =
      new Date(
        now +
          EMAIL_OTP_RESEND_COOLDOWN_MS
      );

    return code;
  };

/**
 * Verify an entered email OTP.
 *
 * This method intentionally does not call save() itself.
 * The auth route controls when the state is persisted.
 */
userSchema.methods.verifyEmailVerificationCode =
  async function (
    code
  ) {
    const suppliedCode =
      String(
        code ?? ""
      ).trim();

    if (
      !/^\d{6}$/.test(
        suppliedCode
      )
    ) {
      return {
        success: false,
        reason: "invalid",
      };
    }

    if (
      !this.emailVerificationCodeHash
    ) {
      return {
        success: false,
        reason: "missing",
      };
    }

    if (
      !this.emailVerificationCodeExpiresAt ||
      this.emailVerificationCodeExpiresAt.getTime() <=
        Date.now()
    ) {
      return {
        success: false,
        reason: "expired",
      };
    }

    if (
      Number(
        this.emailVerificationAttempts ||
          0
      ) >=
      EMAIL_OTP_MAX_ATTEMPTS
    ) {
      return {
        success: false,
        reason: "attempts",
      };
    }

    const matched =
      await bcrypt.compare(
        suppliedCode,
        this.emailVerificationCodeHash
      );

    if (!matched) {
      this.emailVerificationAttempts =
        Number(
          this.emailVerificationAttempts ||
            0
        ) + 1;

      return {
        success: false,
        reason: "invalid",
      };
    }

    this.emailVerified =
      true;

    this.emailVerifiedAt =
      new Date();

    this.emailVerificationCodeHash =
      null;

    this.emailVerificationCodeExpiresAt =
      null;

    this.emailVerificationAttempts =
      0;

    this.emailVerificationResendAt =
      null;

    /*
     * Verification is now complete.
     * Clear legacy token state as well.
     */
    this.emailVerificationTokenHash =
      null;

    this.emailVerificationExpiresAt =
      null;

    return {
      success: true,
      reason: "verified",
    };
  };

/**
 * Clear email verification state.
 */
userSchema.methods.clearEmailVerification =
  function () {
    this.emailVerificationCodeHash =
      null;

    this.emailVerificationCodeExpiresAt =
      null;

    this.emailVerificationAttempts =
      0;

    this.emailVerificationResendAt =
      null;

    this.emailVerificationTokenHash =
      null;

    this.emailVerificationExpiresAt =
      null;

    return this;
  };

/**
 * Determine whether another email OTP can be requested.
 */
userSchema.methods.canRequestEmailVerification =
  function () {
    if (
      !this.emailVerificationResendAt
    ) {
      return true;
    }

    return (
      this.emailVerificationResendAt.getTime() <=
      Date.now()
    );
  };

/**
 * Return remaining resend cooldown in seconds.
 */
userSchema.methods.getEmailVerificationResendRemaining =
  function () {
    if (
      !this.emailVerificationResendAt
    ) {
      return 0;
    }

    const remaining =
      this.emailVerificationResendAt.getTime() -
      Date.now();

    return Math.max(
      0,
      Math.ceil(
        remaining /
          1000
      )
    );
  };

/**
 * Return OTP expiration remaining in seconds.
 */
userSchema.methods.getEmailVerificationRemaining =
  function () {
    if (
      !this.emailVerificationCodeExpiresAt
    ) {
      return 0;
    }

    const remaining =
      this.emailVerificationCodeExpiresAt.getTime() -
      Date.now();

    return Math.max(
      0,
      Math.ceil(
        remaining /
          1000
      )
    );
  };

/* ============================================================
   PASSWORD RESET
============================================================ */

/**
 * Clear any active password reset token.
 *
 * The actual reset token generation/hash belongs in the
 * authentication service/server layer.
 */
userSchema.methods.clearPasswordReset =
  function () {
    this.passwordResetTokenHash =
      null;

    this.passwordResetExpiresAt =
      null;

    return this;
  };

/**
 * Determine whether a stored reset token is still active.
 */
userSchema.methods.hasActivePasswordReset =
  function () {
    return Boolean(
      this.passwordResetTokenHash &&
      this.passwordResetExpiresAt &&
      this.passwordResetExpiresAt.getTime() >
        Date.now()
    );
  };

/* ============================================================
   LOGIN SECURITY
============================================================ */

/**
 * Record a failed login attempt.
 */
userSchema.methods.recordFailedLogin =
  async function () {
    this.failedLoginAttempts =
      Math.max(
        0,
        Number(
          this.failedLoginAttempts ||
            0
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
       * Reset the visible counter after the account
       * enters a timed lock.
       */
      this.failedLoginAttempts =
        0;
    }

    await this.save();

    return this;
  };

/**
 * Reset login security after successful login.
 */
userSchema.methods.resetLoginSecurity =
  async function () {
    this.failedLoginAttempts =
      0;

    this.lockedUntil =
      null;

    this.lastLoginAt =
      new Date();

    await this.save();

    return this;
  };

/**
 * Determine whether account is currently locked.
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
 * Automatically clear expired lock.
 */
userSchema.methods.clearExpiredLock =
  async function () {
    if (
      this.lockedUntil &&
      this.lockedUntil.getTime() <=
        Date.now()
    ) {
      this.lockedUntil =
        null;

      this.failedLoginAttempts =
        0;

      await this.save();
    }

    return this;
  };

/* ============================================================
   ACCOUNT SECURITY
============================================================ */

/**
 * Check whether account is allowed to authenticate.
 */
userSchema.methods.canAuthenticate =
  function () {
    return (
      this.status ===
        "active" &&
      !this.isCurrentlyLocked()
    );
  };

/* ============================================================
   STATIC HELPERS
============================================================ */

/**
 * Find customer by normalized email.
 */
userSchema.statics.findByEmail =
  function (
    email
  ) {
    return this.findOne({
      email:
        normalizeEmail(
          email
        ),
    });
  };

/**
 * Find customer by email or username.
 */
userSchema.statics.findByIdentifier =
  function (
    identifier
  ) {
    const value =
      String(
        identifier ?? ""
      )
        .trim()
        .toLowerCase();

    return this.findOne({
      $or: [
        {
          email:
            value,
        },

        {
          username:
            value,
        },
      ],
    });
  };

/**
 * Find customer by Google account ID.
 */
userSchema.statics.findByGoogleId =
  function (
    googleId
  ) {
    const normalized =
      String(
        googleId ?? ""
      ).trim();

    if (!normalized) {
      return Promise.resolve(null);
    }

    return this.findOne({
      googleId:
        normalized,
    }).select(
      "+googleId"
    );
  };

/* ============================================================
   MODEL
============================================================ */

const User =
  mongoose.model(
    "User",
    userSchema
  );

module.exports =
  User;

/* ============================================================
   EXPORTED CONFIGURATION
============================================================ */

module.exports.PASSWORD_MIN_LENGTH =
  PASSWORD_MIN_LENGTH;

module.exports.EMAIL_OTP_LENGTH =
  EMAIL_OTP_LENGTH;

module.exports.EMAIL_OTP_EXPIRATION_MS =
  EMAIL_OTP_EXPIRATION_MS;

module.exports.EMAIL_OTP_MAX_ATTEMPTS =
  EMAIL_OTP_MAX_ATTEMPTS;

module.exports.EMAIL_OTP_RESEND_COOLDOWN_MS =
  EMAIL_OTP_RESEND_COOLDOWN_MS;