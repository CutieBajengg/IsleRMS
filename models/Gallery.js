"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * models/Gallery.js
 *
 * Dedicated gallery model for the public 360° resort
 * experience and the future admin gallery editor.
 *
 * Stores:
 * - 360° panorama image
 * - location title
 * - display order
 * - Street View-style navigation
 *
 * IMPORTANT:
 * - One default gallery document is used for now.
 * - No SiteSettings dependency.
 * - No pre-save middleware.
 * - No versionKey.
 * - Compatible with modern Mongoose versions.
 * ============================================================
 */

const mongoose = require("mongoose");


/* ============================================================
   DEFAULT GALLERY DATA
============================================================ */

const DEFAULT_GALLERY_IMAGES = [
  {
    title: "Resort View",
    image: "/images/pano.jpg",
    order: 1,

    // Zero-based scene indexes
    left: null,
    right: 1,
    forward: null,
    backward: null,
  },

  {
    title: "Coastal Sunset",
    image: "/images/pano2.jpg",
    order: 2,

    // Zero-based scene indexes
    left: 0,
    right: 2,
    forward: null,
    backward: null,
  },

  {
    title: "Island Path",
    image: "/images/pano3.jpg",
    order: 3,

    // Zero-based scene indexes
    left: 1,
    right: 3,
    forward: null,
    backward: null,
  },

  {
    title: "Beach Horizon",
    image: "/images/pano4.jpg",
    order: 4,

    // Zero-based scene indexes
    left: 2,
    right: null,
    forward: null,
    backward: null,
  },
];


/* ============================================================
   HELPERS
============================================================ */

/**
 * Safely clone the default gallery images.
 *
 * This prevents accidental modification of the original
 * DEFAULT_GALLERY_IMAGES array.
 */
function cloneDefaultGalleryImages() {
  return DEFAULT_GALLERY_IMAGES.map((image) => ({
    title: image.title,
    image: image.image,
    order: image.order,
    left: image.left,
    right: image.right,
    forward: image.forward,
    backward: image.backward,
  }));
}


/**
 * Convert a gallery image subdocument into a normal object.
 *
 * Useful when sending gallery data to EJS templates or APIs.
 */
function normalizeGalleryImage(image) {
  if (!image) {
    return null;
  }

  if (typeof image.toObject === "function") {
    return image.toObject();
  }

  return {
    ...image,
  };
}


/**
 * Return gallery images sorted by display order.
 */
function sortGalleryImages(images) {
  if (!Array.isArray(images)) {
    return [];
  }

  return [...images]
    .map(normalizeGalleryImage)
    .filter(Boolean)
    .sort(
      (a, b) =>
        Number(a.order || 0) -
        Number(b.order || 0)
    );
}


/* ============================================================
   GALLERY IMAGE SCHEMA
============================================================ */

const galleryImageSchema =
  new mongoose.Schema(
    {
      title: {
        type: String,
        trim: true,
        minlength: 2,
        maxlength: 150,
        default: "Resort Photo",
      },

      image: {
        type: String,
        required: true,
        trim: true,
        maxlength: 1000,
      },

      /**
       * Display order.
       *
       * This is one-based:
       * 1, 2, 3, 4...
       */
      order: {
        type: Number,
        min: 1,
        default: 1,
      },

      /**
       * Navigation values are zero-based scene indexes.
       *
       * Example:
       * Scene 0 -> right: 1
       * Scene 1 -> left: 0
       */
      left: {
        type: Number,
        min: 0,
        default: null,
      },

      right: {
        type: Number,
        min: 0,
        default: null,
      },

      forward: {
        type: Number,
        min: 0,
        default: null,
      },

      backward: {
        type: Number,
        min: 0,
        default: null,
      },
    },
    {
      _id: true,
    }
  );


/* ============================================================
   GALLERY DOCUMENT SCHEMA
============================================================ */

const gallerySchema =
  new mongoose.Schema(
    {
      /**
       * Gallery identifier.
       *
       * We currently use one gallery:
       * "default"
       */
      key: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        default: "default",
      },

      /**
       * All panorama scenes.
       */
      images: {
        type: [galleryImageSchema],
        default: [],
      },
    },
    {
      timestamps: true,

      /**
       * We do not need __v for this gallery document.
       */
      versionKey: false,
    }
  );


/* ============================================================
   STATIC: GET DEFAULT DATA
============================================================ */

/**
 * Returns a completely fresh default gallery object.
 *
 * This is used only when the default gallery does not yet
 * exist in MongoDB.
 */
gallerySchema.statics.getDefaultData =
  function () {
    return {
      key: "default",

      images:
        cloneDefaultGalleryImages(),
    };
  };


/* ============================================================
   STATIC: GET OR CREATE DEFAULT GALLERY
============================================================ */

/**
 * Get the single default gallery.
 *
 * If it does not exist, create it using the default
 * panorama configuration above.
 */
gallerySchema.statics.getOrCreateDefault =
  async function () {
    let gallery =
      await this.findOne({
        key: "default",
      });

    if (!gallery) {
      gallery =
        await this.create(
          this.getDefaultData()
        );
    }

    return gallery;
  };


/* ============================================================
   STATIC: GET DEFAULT GALLERY IMAGES
============================================================ */

/**
 * Convenience method for the public gallery page.
 *
 * Returns a normal sorted array instead of raw Mongoose
 * subdocuments.
 */
gallerySchema.statics.getDefaultImages =
  async function () {
    const gallery =
      await this.getOrCreateDefault();

    return sortGalleryImages(
      gallery.images
    );
  };


/* ============================================================
   INSTANCE: GET SORTED IMAGES
============================================================ */

/**
 * Convenience method for an already-loaded gallery document.
 */
gallerySchema.methods.getSortedImages =
  function () {
    return sortGalleryImages(
      this.images
    );
  };


/* ============================================================
   EXPORT
============================================================ */

module.exports =
  mongoose.models.Gallery ||
  mongoose.model(
    "Gallery",
    gallerySchema
  );