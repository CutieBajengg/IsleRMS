// -------------------------------
// Puffer Isle Resort | User Model (FIXED)
// -------------------------------

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    fullname: {
      type: String,
      required: [true, "Full name is required"],
      trim: true,
      maxlength: 50,
    },
    username: {
      type: String,
      trim: true,
      unique: true,
      sparse: true, // optional but unique if provided
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: 6,
    },
    phone: {
      type: String,
      trim: true,
    },
  },
  {
    timestamps: true, // automatically adds createdAt & updatedAt
  }
);

// -------------------------------
// 🔒 Pre-save: Hash password (FIXED)
// -------------------------------
userSchema.pre("save", async function () {
  // Only hash if password was modified
  if (!this.isModified("password")) return;

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// -------------------------------
// ✅ Method: Compare password
// -------------------------------
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// -------------------------------
// Export User model
// -------------------------------
module.exports = mongoose.model("User", userSchema);