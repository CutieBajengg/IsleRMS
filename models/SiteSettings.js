"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * models/SiteSettings.js
 *
 * Mongoose 9 compatible.
 *
 * IMPORTANT:
 * - pre("validate") middleware is synchronous.
 * - DO NOT use function(next)
 * - DO NOT call next()
 * ============================================================
 */

const mongoose = require("mongoose");

/* ============================================================
   GALLERY ITEM NORMALIZATION
   ============================================================ */

function normalizeString(
  value,
  maxLength = 1000
) {
  if (
    value === undefined ||
    value === null
  ) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, maxLength);
}

function normalizeBoolean(
  value,
  defaultValue = true
) {
  if (
    value === undefined ||
    value === null
  ) {
    return defaultValue;
  }

  if (
    value === true ||
    value === "true" ||
    value === "1" ||
    value === 1 ||
    value === "on" ||
    value === "yes"
  ) {
    return true;
  }

  if (
    value === false ||
    value === "false" ||
    value === "0" ||
    value === 0 ||
    value === "off" ||
    value === "no"
  ) {
    return false;
  }

  return defaultValue;
}

function normalizeOrder(
  value,
  fallback = 0
) {
  const parsed =
    Number(value);

  if (
    !Number.isFinite(parsed)
  ) {
    return fallback;
  }

  return Math.max(
    0,
    Math.floor(parsed)
  );
}

/**
 * Normalize one gallery entry.
 *
 * Supports both object-based gallery records and
 * simple string image paths.
 */
function normalizeGalleryItem(
  item,
  fallbackOrder = 1
) {
  if (
    item === undefined ||
    item === null
  ) {
    return null;
  }

  /* ----------------------------------------------------------
     STRING IMAGE
     ---------------------------------------------------------- */

  if (
    typeof item === "string"
  ) {
    const url =
      normalizeString(
        item,
        1000
      );

    if (!url) {
      return null;
    }

    return {
      url,
      src: url,
      image: url,

      title: "",
      caption: "",
      alt: "",

      description: "",

      order:
        normalizeOrder(
          fallbackOrder,
          fallbackOrder
        ),

      active: true,
    };
  }

  /* ----------------------------------------------------------
     OBJECT IMAGE
     ---------------------------------------------------------- */

  if (
    typeof item !== "object"
  ) {
    return null;
  }

  const source = {
    ...item,
  };

  const url =
    normalizeString(
      source.url ||
        source.src ||
        source.image ||
        source.imageUrl ||
        source.photo ||
        source.photoUrl ||
        "",
      1000
    );

  if (!url) {
    return null;
  }

  const title =
    normalizeString(
      source.title ||
        source.name ||
        "",
      200
    );

  const caption =
    normalizeString(
      source.caption ||
        source.description ||
        "",
      1000
    );

  const alt =
    normalizeString(
      source.alt ||
        title ||
        caption ||
        "Puffer Isle Resort gallery image",
      500
    );

  const description =
    normalizeString(
      source.description ||
        caption ||
        "",
      2000
    );

  const order =
    normalizeOrder(
      source.order ??
        source.sortOrder ??
        source.displayOrder ??
        fallbackOrder,
      fallbackOrder
    );

  const active =
    normalizeBoolean(
      source.active ??
        source.isActive ??
        source.enabled ??
        true,
      true
    );

  return {
    ...source,

    url,

    src:
      normalizeString(
        source.src || url,
        1000
      ),

    image:
      normalizeString(
        source.image || url,
        1000
      ),

    title,

    caption,

    alt,

    description,

    order,

    active,
  };
}

/* ============================================================
   GALLERY SUB-SCHEMA
   ============================================================ */

const galleryImageSchema =
  new mongoose.Schema(
    {
      url: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      src: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      image: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      title: {
        type: String,
        default: "",
        trim: true,
        maxlength: 200,
      },

      caption: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      alt: {
        type: String,
        default: "",
        trim: true,
        maxlength: 500,
      },

      description: {
        type: String,
        default: "",
        trim: true,
        maxlength: 2000,
      },

      order: {
        type: Number,
        default: 1,
        min: 0,
      },

      active: {
        type: Boolean,
        default: true,
      },
    },

    {
      _id: true,

      /*
       * Preserve compatibility with older gallery objects
       * that may contain additional properties.
       */
      strict: false,
    }
  );

/* ============================================================
   SITE SETTINGS SCHEMA
   ============================================================ */

const siteSettingsSchema =
  new mongoose.Schema(
    {
      /* --------------------------------------------------------
         BASIC SITE INFORMATION
         -------------------------------------------------------- */

      siteName: {
        type: String,
        default:
          "Puffer Isle Resort",
        trim: true,
        maxlength: 200,
      },

      siteTitle: {
        type: String,
        default:
          "Puffer Isle Resort",
        trim: true,
        maxlength: 200,
      },

      tagline: {
        type: String,
        default:
          "",
        trim: true,
        maxlength: 500,
      },

      description: {
        type: String,
        default:
          "",
        trim: true,
        maxlength: 5000,
      },

      /* --------------------------------------------------------
         BRANDING
         -------------------------------------------------------- */

      logo: {
        type: String,
        default:
          "/images/islelogo.png",
        trim: true,
        maxlength: 1000,
      },

      logoUrl: {
        type: String,
        default:
          "/images/islelogo.png",
        trim: true,
        maxlength: 1000,
      },

      favicon: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      /* --------------------------------------------------------
         HERO / HOMEPAGE
         -------------------------------------------------------- */

      heroTitle: {
        type: String,
        default:
          "Welcome to Puffer Isle Resort",
        trim: true,
        maxlength: 300,
      },

      heroSubtitle: {
        type: String,
        default:
          "",
        trim: true,
        maxlength: 1000,
      },

      heroDescription: {
        type: String,
        default:
          "",
        trim: true,
        maxlength: 3000,
      },

      heroImage: {
        type: String,
        default:
          "",
        trim: true,
        maxlength: 1000,
      },

      /* --------------------------------------------------------
         CONTACT INFORMATION
         -------------------------------------------------------- */

      phone: {
        type: String,
        default: "",
        trim: true,
        maxlength: 50,
      },

      contactPhone: {
        type: String,
        default: "",
        trim: true,
        maxlength: 50,
      },

      email: {
        type: String,
        default: "",
        trim: true,
        maxlength: 320,
      },

      contactEmail: {
        type: String,
        default: "",
        trim: true,
        maxlength: 320,
      },

      address: {
        type: String,
        default:
          "Dingalan, Aurora, Philippines",
        trim: true,
        maxlength: 500,
      },

      /* --------------------------------------------------------
         SOCIAL MEDIA
         -------------------------------------------------------- */

      facebook: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      facebookUrl: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      instagram: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      instagramUrl: {
        type: String,
        default: "",
        trim: true,
        maxlength: 1000,
      },

      /* --------------------------------------------------------
         MAP / LOCATION
         -------------------------------------------------------- */

      mapUrl: {
        type: String,
        default: "",
        trim: true,
        maxlength: 2000,
      },

      mapEmbedUrl: {
        type: String,
        default: "",
        trim: true,
        maxlength: 2000,
      },

      latitude: {
        type: Number,
        default: null,
      },

      longitude: {
        type: Number,
        default: null,
      },

      /* --------------------------------------------------------
         GALLERY
         -------------------------------------------------------- */

      galleryImages: {
        type: [galleryImageSchema],
        default: [],
      },

      /* --------------------------------------------------------
         GENERAL SETTINGS
         -------------------------------------------------------- */

      active: {
        type: Boolean,
        default: true,
      },

      enabled: {
        type: Boolean,
        default: true,
      },

      /* --------------------------------------------------------
         EXTENSIBILITY
         -------------------------------------------------------- */

      /*
       * This allows older/newer SiteSettings fields already
       * stored in MongoDB to remain compatible.
       */
    },

    {
      timestamps: true,

      /*
       * Keep compatibility with existing SiteSettings data
       * that may already contain additional fields.
       */
      strict: false,
    }
  );

/* ============================================================
   MONGOOSE 9 PRE-VALIDATE MIDDLEWARE
   ============================================================ */

/**
 * IMPORTANT:
 *
 * Mongoose 9 compatible middleware.
 *
 * There is NO:
 *
 *     function (next)
 *
 * and NO:
 *
 *     next();
 *
 * because this middleware is synchronous.
 */
siteSettingsSchema.pre(
  "validate",
  function () {
    /* ----------------------------------------------------------
       ENSURE GALLERY ARRAY
       ---------------------------------------------------------- */

    if (
      !Array.isArray(
        this.galleryImages
      )
    ) {
      this.galleryImages = [];
    }

    /* ----------------------------------------------------------
       NORMALIZE GALLERY ITEMS
       ---------------------------------------------------------- */

    const normalized =
      this.galleryImages
        .map(
          (item, index) =>
            normalizeGalleryItem(
              item,
              index + 1
            )
        )
        .filter(Boolean);

    /* ----------------------------------------------------------
       REBUILD ORDER
       ---------------------------------------------------------- */

    normalized.forEach(
      (item, index) => {
        item.order =
          index + 1;
      }
    );

    /* ----------------------------------------------------------
       SAVE NORMALIZED GALLERY
       ---------------------------------------------------------- */

    this.galleryImages =
      normalized;
  }
);

/* ============================================================
   SINGLETON HELPERS
   ============================================================ */

/**
 * Get the global SiteSettings document.
 *
 * Uses the first record as the singleton settings document.
 */
siteSettingsSchema.statics.getSettings =
  async function () {
    let settings =
      await this.findOne({})
        .sort({
          createdAt: 1,
        });

    if (!settings) {
      settings =
        await this.create({});
    }

    return settings;
  };

/**
 * Update global SiteSettings.
 */
siteSettingsSchema.statics.updateSettings =
  async function (updates) {
    if (
      !updates ||
      typeof updates !== "object"
    ) {
      throw new TypeError(
        "Site settings updates must be an object."
      );
    }

    let settings =
      await this.findOne({})
        .sort({
          createdAt: 1,
        });

    if (!settings) {
      settings =
        new this({});
    }

    Object.entries(
      updates
    ).forEach(
      ([key, value]) => {
        if (
          key ===
          "_id"
        ) {
          return;
        }

        if (
          key ===
          "__v"
        ) {
          return;
        }

        settings.set(
          key,
          value
        );
      }
    );

    await settings.save();

    return settings;
  };

/* ============================================================
   MODEL EXPORT
   ============================================================ */

module.exports =
  mongoose.models.SiteSettings ||
  mongoose.model(
    "SiteSettings",
    siteSettingsSchema
  );