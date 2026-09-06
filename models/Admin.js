// ============================================================
// Puffer Isle Resort | IsleRMS
// Admin Model
// ============================================================

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

const parsedRounds = parseInt(
  process.env.BCRYPT_ROUNDS || "12",
  10
);

const BCRYPT_ROUNDS = Number.isFinite(parsedRounds)
  ? Math.max(10, Math.min(parsedRounds, 15))
  : 12;

// ============================================================
// ADMIN SCHEMA
// ============================================================

const adminSchema = new mongoose.Schema(
  {
    // --------------------------------------------------------
    // Username
    // --------------------------------------------------------

    username: {
      type: String,
      required: [true, "Username is required"],
      trim: true,
      lowercase: true,
      minlength: [3, "Username must be at least 3 characters long"],
      maxlength: [50, "Username cannot exceed 50 characters"],
      unique: true,
      match: [
        /^[a-z0-9._-]+$/,
        "Username may only contain letters, numbers, dots, underscores, and hyphens",
      ],
    },

    // --------------------------------------------------------
    // Password
    // --------------------------------------------------------

    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters long"],
      select: false,
    },

    // --------------------------------------------------------
    // Role
    // --------------------------------------------------------

    role: {
      type: String,
      enum: ["admin", "root"],
      default: "admin",
    },

    // --------------------------------------------------------
    // Account Status
    // --------------------------------------------------------

    active: {
      type: Boolean,
      default: true,
    },

    // --------------------------------------------------------
    // Login Tracking
    // --------------------------------------------------------

    lastLogin: {
      type: Date,
      default: null,
    },

    loginAttempts: {
      type: Number,
      default: 0,
      min: 0,
    },

    lockedUntil: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,

    // Prevent password from accidentally appearing
    // in JSON responses.
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// ============================================================
// INDEXES
// ============================================================
//
// IMPORTANT:
// Do NOT add another username index here.
// `unique: true` above already creates the unique index.
//
// This avoids:
// mongoose duplicate schema index warning
//
// ============================================================

// ============================================================
// NORMALIZE USERNAME
// ============================================================

adminSchema.pre("validate", function () {
  if (typeof this.username === "string") {
    this.username = this.username
      .trim()
      .toLowerCase();
  }
});

// ============================================================
// HASH PASSWORD BEFORE SAVE
// ============================================================

adminSchema.pre("save", async function () {
  // Password hasn't changed.
  // No need to hash it again.
  if (!this.isModified("password")) {
    return;
  }

  // Make sure a password exists.
  if (
    typeof this.password !== "string" ||
    this.password.length === 0
  ) {
    throw new Error("Password cannot be empty.");
  }

  // IMPORTANT:
  // If the password is already a bcrypt hash,
  // don't hash it a second time.
  //
  // This protects against accidentally double-hashing
  // an existing password.
  if (
    this.password.startsWith("$2a$") ||
    this.password.startsWith("$2b$") ||
    this.password.startsWith("$2y$")
  ) {
    return;
  }

  this.password = await bcrypt.hash(
    this.password,
    BCRYPT_ROUNDS
  );
});

// ============================================================
// COMPARE PASSWORD
// ============================================================

adminSchema.methods.comparePassword = async function (
  candidatePassword
) {
  if (
    typeof candidatePassword !== "string" ||
    candidatePassword.length === 0
  ) {
    return false;
  }

  if (
    typeof this.password !== "string" ||
    this.password.length === 0
  ) {
    return false;
  }

  try {
    return await bcrypt.compare(
      candidatePassword,
      this.password
    );
  } catch (error) {
    console.error(
      "Admin password comparison error:",
      error.message
    );

    return false;
  }
};

// ============================================================
// SET PASSWORD
// ============================================================

adminSchema.methods.setPassword = async function (
  newPassword
) {
  if (
    typeof newPassword !== "string" ||
    newPassword.length < 6
  ) {
    throw new Error(
      "Password must be at least 6 characters long."
    );
  }

  this.password = newPassword;

  return this;
};

// ============================================================
// CHECK ACCOUNT STATUS
// ============================================================

adminSchema.methods.isAccountLocked = function () {
  if (!this.lockedUntil) {
    return false;
  }

  return this.lockedUntil.getTime() > Date.now();
};

// ============================================================
// RECORD SUCCESSFUL LOGIN
// ============================================================

adminSchema.methods.recordSuccessfulLogin = async function () {
  this.lastLogin = new Date();
  this.loginAttempts = 0;
  this.lockedUntil = null;

  await this.save();
};

// ============================================================
// RECORD FAILED LOGIN
// ============================================================

adminSchema.methods.recordFailedLogin = async function () {
  this.loginAttempts += 1;

  // Lock account after 5 failed attempts.
  if (this.loginAttempts >= 5) {
    const lockTime = new Date();

    // 15-minute lockout
    lockTime.setMinutes(
      lockTime.getMinutes() + 15
    );

    this.lockedUntil = lockTime;
  }

  await this.save();
};

// ============================================================
// SAFE OBJECT
// ============================================================

adminSchema.methods.toSafeObject = function () {
  const obj = this.toObject();

  delete obj.password;
  delete obj.__v;

  return obj;
};

// ============================================================
// FIND BY USERNAME
// ============================================================

adminSchema.statics.findOneByUsername = function (
  username
) {
  if (typeof username !== "string") {
    return null;
  }

  return this.findOne({
    username: username
      .trim()
      .toLowerCase(),
  }).select("+password");
};

// ============================================================
// AUTHENTICATE ADMIN
// ============================================================

adminSchema.statics.authenticate = async function (
  username,
  candidatePassword
) {
  if (
    typeof username !== "string" ||
    typeof candidatePassword !== "string"
  ) {
    return null;
  }

  const normalizedUsername = username
    .trim()
    .toLowerCase();

  const admin = await this.findOne({
    username: normalizedUsername,
  }).select("+password");

  // Admin doesn't exist.
  if (!admin) {
    return null;
  }

  // Account disabled.
  if (!admin.active) {
    return null;
  }

  // Account temporarily locked.
  if (admin.isAccountLocked()) {
    return null;
  }

  const validPassword =
    await admin.comparePassword(
      candidatePassword
    );

  if (!validPassword) {
    try {
      await admin.recordFailedLogin();
    } catch (error) {
      console.error(
        "Failed-login tracking error:",
        error.message
      );
    }

    return null;
  }

  try {
    await admin.recordSuccessfulLogin();
  } catch (error) {
    console.error(
      "Successful-login tracking error:",
      error.message
    );
  }

  return admin;
};

// ============================================================
// CREATE ADMIN
// ============================================================

adminSchema.statics.createAdmin = async function (
  username,
  password,
  role = "admin"
) {
  if (
    typeof username !== "string" ||
    username.trim().length < 3
  ) {
    throw new Error("A valid username is required.");
  }

  if (
    typeof password !== "string" ||
    password.length < 6
  ) {
    throw new Error(
      "Password must be at least 6 characters long."
    );
  }

  const normalizedUsername = username
    .trim()
    .toLowerCase();

  const existingAdmin = await this.findOne({
    username: normalizedUsername,
  });

  if (existingAdmin) {
    throw new Error(
      `Admin "${normalizedUsername}" already exists.`
    );
  }

  const admin = new this({
    username: normalizedUsername,
    password,
    role:
      role === "root"
        ? "root"
        : "admin",
    active: true,
  });

  await admin.save();

  return admin;
};

// ============================================================
// EXPORT MODEL
// ============================================================

module.exports =
  mongoose.models.Admin ||
  mongoose.model("Admin", adminSchema);