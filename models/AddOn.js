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

const addOnSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Add-on name is required."],
      trim: true,
      minlength: [2, "Add-on name must be at least 2 characters."],
      maxlength: [100, "Add-on name cannot exceed 100 characters."],
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
      required: [true, "Add-on price is required."],
      min: [0, "Add-on price cannot be negative."],
      validate: {
        validator: Number.isFinite,
        message: "Add-on price must be a valid number.",
      },
    },

    pricingType: {
      type: String,
      enum: {
        values: ["perNight", "once"],
        message: "Pricing type must be either 'perNight' or 'once'.",
      },
      default: "once",
      required: true,
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
      maxlength: [2000, "Add-on description cannot exceed 2000 characters."],
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
 * Normalize add-on names and automatically generate
 * a stable URL-friendly slug.
 */
addOnSchema.pre("validate", function () {
  if (this.name) {
    this.name = normalizeName(this.name);
    this.slug = makeSlug(this.name);
  }
});

/*
 * Useful indexes for customer-facing catalog queries
 * and admin ordering.
 */
addOnSchema.index({ active: 1, sortOrder: 1, name: 1 });

module.exports =
  mongoose.models.AddOn || mongoose.model("AddOn", addOnSchema);