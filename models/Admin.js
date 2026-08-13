// -------------------------------
// Puffer Isle Resort | Admin Model
// -------------------------------

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const adminSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: 6,
    },
    // Note: Manual 'createdAt' is removed because 'timestamps: true' handles this below
  },
  {
    timestamps: true, // automatically adds createdAt & updatedAt fields
  }
);

// -------------------------------
// 🔒 Pre-save: Hash password
// -------------------------------
// FIXED: Removed (next) and next() calls. 
// Async hooks in Mongoose 5.x+ resolve via the returned Promise.
adminSchema.pre("save", async function () {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified("password")) return;

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  } catch (err) {
    // If an error occurs, Mongoose will catch the thrown error
    throw new Error(err);
  }
});

// -------------------------------
// ✅ Method: Compare password
// -------------------------------
adminSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (err) {
    return false;
  }
};

// -------------------------------
// Export Admin model
// -------------------------------
module.exports = mongoose.model("Admin", adminSchema);