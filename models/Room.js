const mongoose = require("mongoose");

function normalizeName(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function makeSlug(value) {
  return normalizeName(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

const roomSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Room name is required."],
      trim: true,
      minlength: [2, "Room name must be at least 2 characters."],
      maxlength: [100, "Room name cannot exceed 100 characters."],
      unique: true,
      index: true,
    },

    slug: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    price: {
      type: Number,
      required: [true, "Room price is required."],
      min: [0, "Room price cannot be negative."],
      validate: {
        validator: Number.isFinite,
        message: "Room price must be a valid number.",
      },
    },

    maxGuests: {
      type: Number,
      required: [true, "Maximum guest capacity is required."],
      min: [1, "Maximum guest capacity must be at least 1."],
      max: [100, "Maximum guest capacity cannot exceed 100."],
      validate: {
        validator: Number.isInteger,
        message: "Maximum guest capacity must be a whole number.",
      },
    },

    quantity: {
      type: Number,
      default: 1,
      min: [1, "Room quantity must be at least 1."],
      validate: {
        validator: Number.isInteger,
        message: "Room quantity must be a whole number.",
      },
    },

    image: {
      type: String,
      default: "",
      trim: true,
      maxlength: [500, "Image path cannot exceed 500 characters."],
    },

    description: {
      type: String,
      default: "",
      trim: true,
      maxlength: [2000, "Room description cannot exceed 2000 characters."],
    },

    active: {
      type: Boolean,
      default: true,
      index: true,
    },

    sortOrder: {
      type: Number,
      default: 0,
      min: [0, "Sort order cannot be negative."],
      validate: {
        validator: Number.isInteger,
        message: "Sort order must be a whole number.",
      },
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

/*
 * Normalize room names before validation.
 */
roomSchema.pre("validate", function () {
  if (this.name) {
    this.name = normalizeName(this.name);
    this.slug = makeSlug(this.name);
  }
});

/*
 * Useful indexes for the customer booking page
 * and admin catalog management.
 */
roomSchema.index({ active: 1, sortOrder: 1, name: 1 });

module.exports =
  mongoose.models.Room || mongoose.model("Room", roomSchema);