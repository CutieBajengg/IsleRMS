"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * routes/adminRoutes.js
 *
 * Administrator routing / operations.
 *
 * Responsibilities:
 * - Administrator authentication
 * - Dashboard / analytics
 * - Booking management
 * - Front Desk check-in / check-out
 * - User management
 * - Room management
 * - Add-on management
 * - Admin APIs
 * - Booking notifications
 * - Production hardening
 *
 * Mounted by server.js at:
 *   /admin
 *
 * Therefore:
 *   /login
 *   /dashboard
 *   /checkin-manager
 *   /update-checkin
 *   ...
 *
 * are intentionally NOT prefixed with /admin here.
 *
 * ============================================================
 * BOOKING INTEGRITY
 * ============================================================
 *
 * Booking and inventory operations use:
 *
 *   services/bookingAvailability.js
 *
 * and:
 *
 *   models/BookingMutex.js
 *
 * This makes the availability engine shared between:
 *
 *   Customer booking
 *   Admin acceptance / confirmation
 *   Customer cancellation
 *   Room inventory changes
 *
 * The room mutex prevents two concurrent requests from both
 * passing the final availability check and creating/activating
 * conflicting reservations.
 * ============================================================
 */

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Admin = require("../models/Admin");
const Notification = require("../models/Notification");
const Room = require("../models/Room");
const AddOn = require("../models/AddOn");
const Gallery = require("../models/Gallery");
const AdminSessionControl =
  require("../models/AdminSessionControl");

const csrf = require("../middleware/csrf");

const {
  withRoomLock,
  findAvailabilityConflict,
  getPeakOccupancy,
} = require("../services/bookingAvailability");

const verifyCsrfToken =
  csrf.verifyCsrfToken ||
  csrf.verifyCsrf;

const router =
  express.Router();

if (
  typeof verifyCsrfToken !==
  "function"
) {
  throw new Error(
    "CSRF middleware is missing a compatible verification function."
  );
}

/* ============================================================
   CACHE CONTROL
============================================================ */

router.use(
  (
    req,
    res,
    next
  ) => {
    res.setHeader(
      "Cache-Control",
      "no-store"
    );

    res.setHeader(
      "Pragma",
      "no-cache"
    );

    next();
  }
);

/* ============================================================
   CONSTANTS
============================================================ */

const BLOCKING_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
  "checked-in",
];

const ALL_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
  "declined",
  "rejected",
  "cancelled",
  "checked-in",
  "checked-out",
  "completed",
];

const STATUS_TRANSITIONS = {
  pending: [
    "accepted",
    "confirmed",
    "declined",
    "rejected",
    "cancelled",
  ],

  accepted: [
    "confirmed",
    "checked-in",
    "cancelled",
  ],

  confirmed: [
    "checked-in",
    "cancelled",
  ],

  "checked-in": [
    "checked-out",
  ],

  "checked-out": [
    "completed",
  ],

  declined: [],
  rejected: [],
  cancelled: [],
  completed: [],
};

/*
 * Admin CSRF remains configurable for compatibility with the
 * current legacy admin templates.
 *
 * After every admin form/fetch sends `_csrf` or
 * `X-CSRF-Token`, set:
 *
 *   ADMIN_CSRF_REQUIRED=true
 *
 * in production.
 */
const ADMIN_CSRF_REQUIRED =
  String(
    process.env.ADMIN_CSRF_REQUIRED ||
      "false"
  )
    .trim()
    .toLowerCase() ===
  "true";

/*
 * Shared lock configuration.
 *
 * This should be short compared with real request duration.
 */
const BOOKING_LOCK_OPTIONS = {
  leaseMs:
    5 * 60 * 1000,

  waitMs:
    15 * 1000,
};

/* ============================================================
   IMAGE UPLOAD CONFIGURATION
============================================================ */

const ROOM_IMAGE_MAX_BYTES =
  8 *
  1024 *
  1024;

const ROOM_IMAGE_UPLOAD_DIR =
  path.join(
    __dirname,
    "..",
    "public",
    "uploads",
    "rooms"
  );

const ROOM_IMAGE_PUBLIC_PREFIX =
  "/uploads/rooms/";

const ROOM_IMAGE_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
];

try {
  fs.mkdirSync(
    ROOM_IMAGE_UPLOAD_DIR,
    {
      recursive: true,
    }
  );
} catch (error) {
  console.error(
    "Room image upload directory initialization failed:",
    error.stack ||
      error.message ||
      error
  );
}

const parseRoomImageBody =
  express.raw({
    type:
      ROOM_IMAGE_CONTENT_TYPES,
    limit:
      ROOM_IMAGE_MAX_BYTES,
  });

const ADDON_IMAGE_MAX_BYTES =
  8 *
  1024 *
  1024;

const ADDON_IMAGE_UPLOAD_DIR =
  path.join(
    __dirname,
    "..",
    "public",
    "uploads",
    "addons"
  );

const ADDON_IMAGE_PUBLIC_PREFIX =
  "/uploads/addons/";

const ADDON_IMAGE_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
];

try {
  fs.mkdirSync(
    ADDON_IMAGE_UPLOAD_DIR,
    {
      recursive: true,
    }
  );
} catch (error) {
  console.error(
    "Add-on image upload directory initialization failed:",
    error.stack ||
      error.message ||
      error
  );
}

const parseAddOnImageBody =
  express.raw({
    type:
      ADDON_IMAGE_CONTENT_TYPES,
    limit:
      ADDON_IMAGE_MAX_BYTES,
  });

/* ============================================================
   GALLERY IMAGE UPLOAD
============================================================ */

const GALLERY_IMAGE_MAX_BYTES =
  25 *
  1024 *
  1024;

const GALLERY_IMAGE_UPLOAD_DIR =
  path.join(
    __dirname,
    "..",
    "public",
    "uploads",
    "gallery"
  );

const GALLERY_IMAGE_PUBLIC_PREFIX =
  "/uploads/gallery/";

const GALLERY_IMAGE_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
];

try {
  fs.mkdirSync(
    GALLERY_IMAGE_UPLOAD_DIR,
    {
      recursive: true,
    }
  );
} catch (error) {
  console.error(
    "Gallery upload directory initialization failed:",
    error.stack ||
      error.message ||
      error
  );
}

const galleryUpload =
  multer({
    storage:
      multer.memoryStorage(),

    limits: {
      fileSize:
        GALLERY_IMAGE_MAX_BYTES,

      files: 1,

      fields: 20,
    },

    fileFilter: (
      req,
      file,
      callback
    ) => {
      const contentType =
        String(
          file?.mimetype ||
            ""
        )
          .trim()
          .toLowerCase();

      if (
        GALLERY_IMAGE_CONTENT_TYPES.includes(
          contentType
        )
      ) {
        return callback(
          null,
          true
        );
      }

      return callback(
        new Error(
          "Unsupported gallery image type."
        )
      );
    },
  });

/* ============================================================
   LEGACY CATALOG FALLBACKS
============================================================ */

const LEGACY_ROOMS = [
  {
    key:
      "Aircon Room",

    name:
      "Aircon Room",

    displayName:
      "Aircon Room",

    price:
      3500,

    maxGuests:
      8,

    quantity:
      1,

    image:
      "/images/room1.jpg",

    type:
      "room",

    active:
      true,
  },

  {
    key:
      "Fan Room",

    name:
      "Fan Room",

    displayName:
      "Fan Room",

    price:
      2500,

    maxGuests:
      6,

    quantity:
      1,

    image:
      "/images/room2.jpg",

    type:
      "room",

    active:
      true,
  },
];

const LEGACY_COTTAGE = {
  key:
    "Seaside Cottage",

  name:
    "Seaside Cottage",

  displayName:
    "Seaside Cottage",

  price:
    1200,

  maxGuests:
    6,

  quantity:
    1,

  image:
    "/images/cottage.jpg",

  type:
    "cottage",

  active:
    true,
};

/* ============================================================
   GENERIC HELPERS
============================================================ */

function normalizeString(
  value,
  maxLength = 500
) {
  if (
    value ===
      undefined ||
    value ===
      null
  ) {
    return "";
  }

  return String(value)
    .trim()
    .slice(
      0,
      maxLength
    );
}

function normalizeUsername(
  value
) {
  return normalizeString(
    value,
    120
  ).toLowerCase();
}

function normalizeEmail(
  value
) {
  return normalizeString(
    value,
    320
  ).toLowerCase();
}

function isValidObjectId(
  id
) {
  return (
    Boolean(id) &&
    mongoose.Types.ObjectId.isValid(
      id
    )
  );
}

function parseNumber(
  value,
  fallback = 0
) {
  const parsed =
    Number(value);

  return Number.isFinite(
    parsed
  )
    ? parsed
    : fallback;
}

function parseInteger(
  value,
  fallback = 0
) {
  const parsed =
    Number(value);

  return Number.isInteger(
    parsed
  )
    ? parsed
    : fallback;
}

function asBoolean(
  value
) {
  return (
    value === true ||
    value === "true" ||
    value === "1" ||
    value === "on" ||
    value === "yes"
  );
}

function startOfToday() {
  const now =
    new Date();

  return new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate()
  );
}

function endOfToday() {
  const start =
    startOfToday();

  return new Date(
    start.getFullYear(),
    start.getMonth(),
    start.getDate() +
      1
  );
}

function parseBookingDate(
  value
) {
  if (!value) {
    return null;
  }

  const stringValue =
    String(value).trim();

  if (
    /^\d{4}-\d{2}-\d{2}$/.test(
      stringValue
    )
  ) {
    const [
      year,
      month,
      day,
    ] =
      stringValue
        .split("-")
        .map(Number);

    const date =
      new Date(
        year,
        month - 1,
        day
      );

    if (
      date.getFullYear() !==
        year ||
      date.getMonth() !==
        month - 1 ||
      date.getDate() !==
        day
    ) {
      return null;
    }

    return date;
  }

  const date =
    new Date(value);

  return Number.isNaN(
    date.getTime()
  )
    ? null
    : date;
}

function calculateNights(
  checkin,
  checkout
) {
  const start =
    parseBookingDate(
      checkin
    );

  const end =
    parseBookingDate(
      checkout
    );

  if (
    !start ||
    !end ||
    end <= start
  ) {
    return 0;
  }

  const startUtc =
    Date.UTC(
      start.getFullYear(),
      start.getMonth(),
      start.getDate()
    );

  const endUtc =
    Date.UTC(
      end.getFullYear(),
      end.getMonth(),
      end.getDate()
    );

  return Math.round(
    (
      endUtc -
      startUtc
    ) /
      86400000
  );
}

function validateBookingDates(
  checkin,
  checkout
) {
  const start =
    parseBookingDate(
      checkin
    );

  const end =
    parseBookingDate(
      checkout
    );

  if (
    !start ||
    !end
  ) {
    return {
      valid:
        false,

      message:
        "Invalid booking dates.",
    };
  }

  if (
    end <= start
  ) {
    return {
      valid:
        false,

      message:
        "Check-out must be after check-in.",
    };
  }

  return {
    valid:
      true,

    start,

    end,
  };
}

function pickFirst(
  record,
  fields,
  fallback =
    undefined
) {
  for (
    const field of fields
  ) {
    if (
      record &&
      record[field] !==
        undefined &&
      record[field] !==
        null &&
      record[field] !==
        ""
    ) {
      return record[field];
    }
  }

  return fallback;
}

function modelHasPath(
  model,
  field
) {
  return Boolean(
    model &&
      model.schema &&
      typeof model.schema.path ===
        "function" &&
      model.schema.path(
        field
      )
  );
}

function setModelValue(
  document,
  fieldNames,
  value
) {
  if (
    !document ||
    !Array.isArray(
      fieldNames
    )
  ) {
    return false;
  }

  for (
    const field of
      fieldNames
  ) {
    if (
      document.schema &&
      document.schema.path(
        field
      )
    ) {
      document.set(
        field,
        value
      );

      return true;
    }
  }

  return false;
}

function hasOwn(
  body,
  ...names
) {
  return names.some(
    (
      name
    ) =>
      Object.prototype.hasOwnProperty.call(
        body || {},
        name
      )
  );
}

function firstPresent(
  body,
  names
) {
  for (
    const name of
      names
  ) {
    if (
      hasOwn(
        body,
        name
      )
    ) {
      return body[name];
    }
  }

  return undefined;
}

function wantsJson(
  req
) {
  const accepted =
    String(
      req.headers?.accept ||
        ""
    ).toLowerCase();

  return Boolean(
    req.xhr ||
      accepted.includes(
        "application/json"
      ) ||
      req.path.startsWith(
        "/api/"
      ) ||
      req.path.startsWith(
        "/booking/"
      ) ||
      req.path.startsWith(
        "/update-"
      )
  );
}

function getAdminSession(
  req
) {
  return (
    req.session?.admin ||
    null
  );
}

function getAdminId(
  req
) {
  const id =
    req.session?.admin?.id ||
    req.session?.admin?._id;

  return isValidObjectId(id)
    ? String(id)
    : null;
}

function getRequestId(
  req
) {
  return (
    String(
      req.requestId ||
        ""
    ).trim() ||
    null
  );
}

function sendApiError(
  res,
  statusCode,
  message,
  code =
    "REQUEST_FAILED",
  requestId =
    null
) {
  return res
    .status(statusCode)
    .json({
      success:
        false,

      code,

      message,

      ...(requestId
        ? {
            requestId,
          }
        : {}),
    });
}

function getBookingIdFromRequest(
  req
) {
  return normalizeString(
    req.body?.bookingId ||
      req.body?.appointmentId ||
      req.body?.id
  );
}

function getResourceIdFromRequest(
  req
) {
  return normalizeString(
    req.params?.id ||
      req.body?.id ||
      req.body?._id
  );
}

function renderAdminError(
  res,
  statusCode,
  title,
  message
) {
  return res
    .status(statusCode)
    .render(
      "error",
      {
        title,

        statusCode,

        error:
          message,

        message,
      }
    );
}

function redirectWithMessage(
  res,
  route,
  key,
  value
) {
  const separator =
    route.includes("?")
      ? "&"
      : "?";

  return res.redirect(
    `${route}${separator}${key}=${encodeURIComponent(
      value
    )}`
  );
}

/* ============================================================
   IMAGE HELPERS
============================================================ */

function detectRoomImageType(
  buffer
) {
  if (
    !Buffer.isBuffer(
      buffer
    ) ||
    buffer.length <
      12
  ) {
    return null;
  }

  if (
    buffer[0] ===
      0xff &&
    buffer[1] ===
      0xd8 &&
    buffer[2] ===
      0xff
  ) {
    return {
      extension:
        "jpg",

      contentType:
        "image/jpeg",
    };
  }

  const pngSignature =
    Buffer.from([
      0x89,
      0x50,
      0x4e,
      0x47,
      0x0d,
      0x0a,
      0x1a,
      0x0a,
    ]);

  if (
    buffer.length >=
      pngSignature.length &&
    buffer
      .subarray(
        0,
        pngSignature.length
      )
      .equals(
        pngSignature
      )
  ) {
    return {
      extension:
        "png",

      contentType:
        "image/png",
    };
  }

  if (
    buffer.toString(
      "ascii",
      0,
      4
    ) === "RIFF" &&
    buffer.toString(
      "ascii",
      8,
      12
    ) === "WEBP"
  ) {
    return {
      extension:
        "webp",

      contentType:
        "image/webp",
    };
  }

  return null;
}

function isManagedRoomImageUrl(
  value
) {
  const normalized =
    normalizeString(
      value,
      500
    );

  if (
    !normalized ||
    !normalized.startsWith(
      ROOM_IMAGE_PUBLIC_PREFIX
    )
  ) {
    return false;
  }

  const filename =
    normalized.slice(
      ROOM_IMAGE_PUBLIC_PREFIX.length
    );

  if (
    !filename ||
    filename.includes(
      "/"
    ) ||
    filename.includes(
      "\\"
    )
  ) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}

function roomImageAbsolutePathFromUrl(
  value
) {
  if (
    !isManagedRoomImageUrl(
      value
    )
  ) {
    return null;
  }

  const filename =
    value.slice(
      ROOM_IMAGE_PUBLIC_PREFIX.length
    );

  const uploadRoot =
    path.resolve(
      ROOM_IMAGE_UPLOAD_DIR
    );

  const absolutePath =
    path.resolve(
      ROOM_IMAGE_UPLOAD_DIR,
      filename
    );

  if (
    absolutePath !==
      uploadRoot &&
    !absolutePath.startsWith(
      `${uploadRoot}${path.sep}`
    )
  ) {
    return null;
  }

  return absolutePath;
}

async function removeManagedRoomImage(
  value
) {
  const filePath =
    roomImageAbsolutePathFromUrl(
      value
    );

  if (!filePath) {
    return;
  }

  try {
    await fs.promises.unlink(
      filePath
    );
  } catch (error) {
    if (
      error?.code !==
      "ENOENT"
    ) {
      console.warn(
        "Unable to remove previous room image:",
        error.message ||
          error
      );
    }
  }
}

function createRoomImageFilename(
  extension
) {
  return (
    `room-${Date.now()}-${crypto
      .randomBytes(16)
      .toString(
        "hex"
      )}.${extension}`
  );
}

async function saveRoomImageBuffer(
  buffer,
  imageType
) {
  await fs.promises.mkdir(
    ROOM_IMAGE_UPLOAD_DIR,
    {
      recursive:
        true,
    }
  );

  const filename =
    createRoomImageFilename(
      imageType.extension
    );

  const finalPath =
    path.join(
      ROOM_IMAGE_UPLOAD_DIR,
      filename
    );

  const tempPath =
    `${finalPath}.${crypto
      .randomBytes(6)
      .toString(
        "hex"
      )}.tmp`;

  await fs.promises.writeFile(
    tempPath,
    buffer,
    {
      flag:
        "wx",
    }
  );

  try {
    await fs.promises.rename(
      tempPath,
      finalPath
    );
  } catch (error) {
    try {
      await fs.promises.unlink(
        tempPath
      );
    } catch (_) {}

    throw error;
  }

  return {
    filename,

    path:
      finalPath,

    url:
      `${ROOM_IMAGE_PUBLIC_PREFIX}${filename}`,
  };
}

function detectAddOnImageType(
  buffer
) {
  return detectRoomImageType(
    buffer
  );
}

function isManagedAddOnImageUrl(
  value
) {
  const normalized =
    normalizeString(
      value,
      500
    );

  if (
    !normalized ||
    !normalized.startsWith(
      ADDON_IMAGE_PUBLIC_PREFIX
    )
  ) {
    return false;
  }

  const filename =
    normalized.slice(
      ADDON_IMAGE_PUBLIC_PREFIX.length
    );

  if (
    !filename ||
    filename.includes(
      "/"
    ) ||
    filename.includes(
      "\\"
    )
  ) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}

function addOnImageAbsolutePathFromUrl(
  value
) {
  if (
    !isManagedAddOnImageUrl(
      value
    )
  ) {
    return null;
  }

  const filename =
    value.slice(
      ADDON_IMAGE_PUBLIC_PREFIX.length
    );

  const uploadRoot =
    path.resolve(
      ADDON_IMAGE_UPLOAD_DIR
    );

  const absolutePath =
    path.resolve(
      ADDON_IMAGE_UPLOAD_DIR,
      filename
    );

  if (
    absolutePath !==
      uploadRoot &&
    !absolutePath.startsWith(
      `${uploadRoot}${path.sep}`
    )
  ) {
    return null;
  }

  return absolutePath;
}

async function removeManagedAddOnImage(
  value
) {
  const filePath =
    addOnImageAbsolutePathFromUrl(
      value
    );

  if (!filePath) {
    return;
  }

  try {
    await fs.promises.unlink(
      filePath
    );
  } catch (error) {
    if (
      error?.code !==
      "ENOENT"
    ) {
      console.warn(
        "Unable to remove previous add-on image:",
        error.message ||
          error
      );
    }
  }
}

function createAddOnImageFilename(
  extension
) {
  return (
    `addon-${Date.now()}-${crypto
      .randomBytes(16)
      .toString(
        "hex"
      )}.${extension}`
  );
}

async function saveAddOnImageBuffer(
  buffer,
  imageType
) {
  await fs.promises.mkdir(
    ADDON_IMAGE_UPLOAD_DIR,
    {
      recursive:
        true,
    }
  );

  const filename =
    createAddOnImageFilename(
      imageType.extension
    );

  const finalPath =
    path.join(
      ADDON_IMAGE_UPLOAD_DIR,
      filename
    );

  const tempPath =
    `${finalPath}.${crypto
      .randomBytes(6)
      .toString(
        "hex"
      )}.tmp`;

  await fs.promises.writeFile(
    tempPath,
    buffer,
    {
      flag:
        "wx",
    }
  );

  try {
    await fs.promises.rename(
      tempPath,
      finalPath
    );
  } catch (error) {
    try {
      await fs.promises.unlink(
        tempPath
      );
    } catch (_) {}

    throw error;
  }

  return {
    filename,

    path:
      finalPath,

    url:
      `${ADDON_IMAGE_PUBLIC_PREFIX}${filename}`,
  };
}

function detectGalleryImageType(
  buffer
) {
  return detectRoomImageType(
    buffer
  );
}

function isManagedGalleryImageUrl(
  value
) {
  const normalized =
    normalizeString(
      value,
      1000
    );

  if (
    !normalized ||
    !normalized.startsWith(
      GALLERY_IMAGE_PUBLIC_PREFIX
    )
  ) {
    return false;
  }

  const filename =
    normalized.slice(
      GALLERY_IMAGE_PUBLIC_PREFIX.length
    );

  if (
    !filename ||
    filename.includes(
      "/"
    ) ||
    filename.includes(
      "\\"
    )
  ) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}

function galleryImageAbsolutePathFromUrl(
  value
) {
  if (
    !isManagedGalleryImageUrl(
      value
    )
  ) {
    return null;
  }

  const filename =
    value.slice(
      GALLERY_IMAGE_PUBLIC_PREFIX.length
    );

  const uploadRoot =
    path.resolve(
      GALLERY_IMAGE_UPLOAD_DIR
    );

  const absolutePath =
    path.resolve(
      GALLERY_IMAGE_UPLOAD_DIR,
      filename
    );

  if (
    absolutePath !==
      uploadRoot &&
    !absolutePath.startsWith(
      `${uploadRoot}${path.sep}`
    )
  ) {
    return null;
  }

  return absolutePath;
}

async function removeManagedGalleryImage(
  value
) {
  const filePath =
    galleryImageAbsolutePathFromUrl(
      value
    );

  if (!filePath) {
    return;
  }

  try {
    await fs.promises.unlink(
      filePath
    );
  } catch (error) {
    if (
      error?.code !==
      "ENOENT"
    ) {
      console.warn(
        "Unable to remove gallery image:",
        error.message ||
          error
      );
    }
  }
}

function createGalleryImageFilename(
  extension
) {
  return (
    `pano-${Date.now()}-${crypto
      .randomBytes(16)
      .toString(
        "hex"
      )}.${extension}`
  );
}

async function saveGalleryImageBuffer(
  buffer,
  imageType
) {
  await fs.promises.mkdir(
    GALLERY_IMAGE_UPLOAD_DIR,
    {
      recursive:
        true,
    }
  );

  const filename =
    createGalleryImageFilename(
      imageType.extension
    );

  const finalPath =
    path.join(
      GALLERY_IMAGE_UPLOAD_DIR,
      filename
    );

  const tempPath =
    `${finalPath}.${crypto
      .randomBytes(6)
      .toString(
        "hex"
      )}.tmp`;

  await fs.promises.writeFile(
    tempPath,
    buffer,
    {
      flag:
        "wx",
    }
  );

  try {
    await fs.promises.rename(
      tempPath,
      finalPath
    );
  } catch (error) {
    try {
      await fs.promises.unlink(
        tempPath
      );
    } catch (_) {}

    throw error;
  }

  return {
    filename,

    path:
      finalPath,

    url:
      `${GALLERY_IMAGE_PUBLIC_PREFIX}${filename}`,
  };
}

/* ============================================================
   GALLERY HELPERS
============================================================ */

function normalizeGalleryImages(
  images
) {
  if (
    !Array.isArray(
      images
    )
  ) {
    return [];
  }

  const sceneCount =
    images.length;

  return images.map(
    (
      item,
      index
    ) => {
      const plain =
        typeof item?.toObject ===
        "function"
          ? item.toObject()
          : {
              ...item,
            };

      const normalizeNavigation =
        (value) => {
          const parsed =
            Number(value);

          if (
            !Number.isInteger(
              parsed
            ) ||
            parsed < 0 ||
            parsed >=
              sceneCount ||
            parsed ===
              index
          ) {
            return null;
          }

          return parsed;
        };

      return {
        _id:
          plain._id,

        title:
          normalizeString(
            plain.title ||
              `Resort View ${
                index + 1
              }`,
            150
          ) ||
          `Resort View ${
            index + 1
          }`,

        image:
          normalizeString(
            plain.image ||
              "",
            1000
          ),

        order:
          index + 1,

        left:
          normalizeNavigation(
            plain.left
          ),

        right:
          normalizeNavigation(
            plain.right
          ),

        forward:
          normalizeNavigation(
            plain.forward
          ),

        backward:
          normalizeNavigation(
            plain.backward
          ),
      };
    }
  );
}

async function getAdminGallery() {
  const gallery =
    await Gallery.getOrCreateDefault();

  return {
    gallery,

    images:
      normalizeGalleryImages(
        gallery.images
      ),
  };
}

function remapGalleryNavigationAfterDelete(
  images,
  deletedIndex
) {
  return images.map(
    (
      image
    ) => {
      const remap =
        (
          value
        ) => {
          if (
            !Number.isInteger(
              value
            )
          ) {
            return null;
          }

          if (
            value ===
            deletedIndex
          ) {
            return null;
          }

          if (
            value >
            deletedIndex
          ) {
            return (
              value - 1
            );
          }

          return value;
        };

      return {
        ...image,

        left:
          remap(
            image.left
          ),

        right:
          remap(
            image.right
          ),

        forward:
          remap(
            image.forward
          ),

        backward:
          remap(
            image.backward
          ),
      };
    }
  );
}

/* ============================================================
   SESSION / AUTHENTICATION
============================================================ */

/**
 * Revalidates the admin account against MongoDB.
 *
 * The session is NOT treated as permanent authorization.
 *
 * If an administrator is disabled after logging in, the live
 * database state wins.
 */
async function getAuthenticatedAdmin(
  req
) {
  const sessionAdmin =
    req.session?.admin;

  const adminId =
    sessionAdmin?.id ||
    sessionAdmin?._id;

  if (
    !isValidObjectId(
      adminId
    )
  ) {
    return null;
  }

  const admin =
    await Admin.findById(
      adminId
    ).select(
      "username role status active email failedLoginAttempts lockedUntil lastLoginAt"
    );

  if (
    !admin
  ) {
    return null;
  }

  if (
    modelHasPath(
      Admin,
      "status"
    ) &&
    admin.status &&
    String(
      admin.status
    )
      .trim()
      .toLowerCase() !==
      "active"
  ) {
    return null;
  }

  if (
    modelHasPath(
      Admin,
      "active"
    ) &&
    admin.active ===
      false
  ) {
    return null;
  }

  const role =
    normalizeString(
      admin.role ||
        sessionAdmin.role ||
        "admin",
      80
    ).toLowerCase();

  /*
   * Keep the session synchronized with the live account.
   */
  req.session.admin =
    {
      ...sessionAdmin,

      id:
        admin._id.toString(),

      _id:
        admin._id.toString(),

      username:
        normalizeUsername(
          admin.username
        ),

      role,
    };

  return admin;
}

function requireAdmin(
  req,
  res,
  next
) {
  getAuthenticatedAdmin(
    req
  )
    .then(
      async (
        admin
      ) => {
        if (
          !admin
        ) {
          /*
           * Clear the invalid admin session.
           */
          if (
            req.session
          ) {
            await new Promise(
              (
                resolve
              ) =>
                req.session.destroy(
                  () =>
                    resolve()
                )
            );
          }

          if (
            wantsJson(
              req
            )
          ) {
            return sendApiError(
              res,
              401,
              "Administrator authentication required.",
              "AUTHENTICATION_REQUIRED",
              getRequestId(
                req
              )
            );
          }

          return res.redirect(
            "/admin/login?error=" +
              encodeURIComponent(
                "Your administrator session is no longer valid."
              )
          );
        }

        res.locals.admin =
          admin;

        next();
      }
    )
    .catch(
      (
        error
      ) => {
        console.error(
          "Admin authentication validation error:",
          error
        );

        return sendApiError(
          res,
          500,
          "Unable to validate administrator access.",
          "ADMIN_AUTH_VALIDATION_FAILED",
          getRequestId(
            req
          )
        );
      }
    );
}

async function requireAdminApiHandler(
  req,
  res,
  next
) {
  try {
    const admin =
      await getAuthenticatedAdmin(
        req
      );

    if (
      !admin
    ) {
      if (
        req.session
      ) {
        await new Promise(
          (
            resolve
          ) =>
            req.session.destroy(
              () =>
                resolve()
            )
        );
      }

      return sendApiError(
        res,
        401,
        "Administrator authentication required.",
        "AUTHENTICATION_REQUIRED",
        getRequestId(
          req
        )
      );
    }

    res.locals.admin =
      admin;

    next();
  } catch (error) {
    console.error(
      "Admin API authentication validation error:",
      error
    );

    return sendApiError(
      res,
      500,
      "Unable to validate administrator access.",
      "ADMIN_AUTH_VALIDATION_FAILED",
      getRequestId(
        req
      )
    );
  }
}

const requireAdminApi =
  requireAdminApiHandler;

function verifyAdminMutationCsrf(
  req,
  res,
  next
) {
  /*
   * Compatibility switch.
   *
   * Once the current admin templates all send the token,
   * set ADMIN_CSRF_REQUIRED=true.
   */
  if (
    !ADMIN_CSRF_REQUIRED
  ) {
    return next();
  }

  return verifyCsrfToken(
    req,
    res,
    next
  );
}

function requireAdminMutation(
  req,
  res,
  next
) {
  return requireAdminApi(
    req,
    res,
    () =>
      verifyAdminMutationCsrf(
        req,
        res,
        next
      )
  );
}

function regenerateSession(
  req
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
      if (
        !req.session
      ) {
        return reject(
          new Error(
            "Session middleware is unavailable."
          )
        );
      }

      req.session.regenerate(
        (
          error
        ) => {
          if (
            error
          ) {
            return reject(
              error
            );
          }

          resolve();
        }
      );
    }
  );
}

function saveSession(
  req
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
      if (
        !req.session
      ) {
        return reject(
          new Error(
            "Session middleware is unavailable."
          )
        );
      }

      req.session.save(
        (
          error
        ) => {
          if (
            error
          ) {
            return reject(
              error
            );
          }

          resolve();
        }
      );
    }
  );
}

/* ============================================================
   ADMIN LOGIN SECURITY
============================================================ */

async function recordAdminLoginFailure(
  admin
) {
  if (
    !admin
  ) {
    return;
  }

  try {
    if (
      modelHasPath(
        Admin,
        "failedLoginAttempts"
      )
    ) {
      admin.failedLoginAttempts =
        Math.max(
          0,
          Number(
            admin.failedLoginAttempts ||
              0
          )
        ) + 1;
    }

    if (
      modelHasPath(
        Admin,
        "lockedUntil"
      ) &&
      modelHasPath(
        Admin,
        "failedLoginAttempts"
      )
    ) {
      const attempts =
        Number(
          admin.failedLoginAttempts ||
            0
        );

      /*
       * Five failed attempts:
       * temporarily lock the account.
       */
      if (
        attempts >=
        5
      ) {
        admin.lockedUntil =
          new Date(
            Date.now() +
              15 *
                60 *
                1000
          );

        if (
          modelHasPath(
            Admin,
            "failedLoginAttempts"
          )
        ) {
          admin.failedLoginAttempts =
            0;
        }
      }
    }

    await admin.save();
  } catch (error) {
    console.error(
      "Admin failed-login tracking error:",
      error
    );
  }
}

async function recordAdminLoginSuccess(
  admin
) {
  try {
    let changed =
      false;

    if (
      modelHasPath(
        Admin,
        "failedLoginAttempts"
      )
    ) {
      admin.failedLoginAttempts =
        0;

      changed =
        true;
    }

    if (
      modelHasPath(
        Admin,
        "lockedUntil"
      )
    ) {
      admin.lockedUntil =
        null;

      changed =
        true;
    }

    if (
      modelHasPath(
        Admin,
        "lastLoginAt"
      )
    ) {
      admin.lastLoginAt =
        new Date();

      changed =
        true;
    }

    if (
      changed
    ) {
      await admin.save();
    }
  } catch (error) {
    console.error(
      "Admin successful-login tracking error:",
      error
    );
  }
}

function renderAdminLogin(
  req,
  res,
  {
    statusCode =
      200,

    error =
      null,

    username =
      "",
  } = {}
) {
  const csrfToken =
    res.locals?.csrfToken ||
    res.locals?._csrf ||
    "";

  return res
    .status(
      statusCode
    )
    .render(
      "admin/adminlogin",
      {
        title:
          "Admin Portal",

        error:
          error ||
          null,

        username:
          String(
            username ||
              ""
          )
            .trim()
            .slice(
              0,
              120
            ),

        csrfToken:
          String(
            csrfToken ||
              ""
          ),
      }
    );
}

router.get(
  "/login",
  async (
    req,
    res
  ) => {
    const admin =
      req.session?.admin;

    if (
      admin?.id &&
      isValidObjectId(
        admin.id
      )
    ) {
      /*
       * A session-shaped identity is not enough.
       * Verify the live admin before redirecting.
       */
      const authenticatedAdmin =
        await getAuthenticatedAdmin(
          req
        ).catch(
          () => null
        );

      if (
        authenticatedAdmin
      ) {
        return res.redirect(
          "/admin/dashboard"
        );
      }

      await new Promise(
        (
          resolve
        ) => {
          if (
            !req.session
          ) {
            return resolve();
          }

          req.session.destroy(
            () =>
              resolve()
          );
        }
      );
    }

    const queryError =
      normalizeString(
        req.query?.error,
        500
      );

    return renderAdminLogin(
      req,
      res,
      {
        error:
          queryError ||
          null,
      }
    );
  }
);


/* ============================================================
   ADMIN LOGIN
============================================================ */

router.post(
  "/login",
  verifyAdminMutationCsrf,
  async (
    req,
    res
  ) => {
    const rawUsername =
      String(
        req.body?.username ||
          req.body?.email ||
          ""
      ).trim();

    const displayUsername =
      rawUsername.slice(
        0,
        120
      );

    const password =
      String(
        req.body?.password ||
          ""
      );

    try {
      if (
        !rawUsername ||
        !password
      ) {
        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 400,
            username: displayUsername,
            error:
              "Username and password are required.",
          }
        );
      }

      if (
        rawUsername.length > 120
      ) {
        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 400,
            username: displayUsername,
            error:
              "Administrator username is invalid.",
          }
        );
      }

      const submittedUsername =
        normalizeUsername(
          rawUsername
        );

      if (!submittedUsername) {
        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 400,
            username: displayUsername,
            error:
              "Administrator username is invalid.",
          }
        );
      }

      /*
       * Username is the canonical administrator identifier.
       * Email lookup remains supported if the model has email.
       */
      const loginQuery =
        modelHasPath(
          Admin,
          "email"
        ) &&
        submittedUsername.includes("@")
          ? {
              $or: [
                {
                  username:
                    submittedUsername,
                },
                {
                  email:
                    normalizeEmail(
                      submittedUsername
                    ),
                },
              ],
            }
          : {
              username:
                submittedUsername,
            };

      const admin =
        await Admin.findOne(
          loginQuery
        ).select(
          "+password"
        );

      /*
       * ACCOUNT LOCKOUT
       */
      if (
        admin &&
        modelHasPath(
          Admin,
          "lockedUntil"
        ) &&
        admin.lockedUntil &&
        new Date(
          admin.lockedUntil
        ) > new Date()
      ) {
        logAdminAction(
          req,
          "login-blocked",
          {
            username:
              submittedUsername,
          }
        );

        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 429,
            username: displayUsername,
            error:
              "Administrator account temporarily locked. Please try again later.",
          }
        );
      }

      /*
       * VERIFY PASSWORD
       */
      let validPassword = false;

      if (admin) {
        if (
          typeof admin.comparePassword ===
          "function"
        ) {
          validPassword =
            await admin.comparePassword(
              password
            );
        } else if (admin.password) {
          validPassword =
            await bcrypt.compare(
              password,
              admin.password
            );
        }
      }

      /*
       * VALIDATE ACCOUNT STATUS
       */
      const adminStatus =
        admin
          ? String(
              admin.status || "active"
            )
              .trim()
              .toLowerCase()
          : null;

      const inactive =
        admin &&
        (
          (
            modelHasPath(
              Admin,
              "status"
            ) &&
            admin.status &&
            adminStatus !== "active"
          ) ||
          (
            modelHasPath(
              Admin,
              "active"
            ) &&
            admin.active === false
          )
        );

      if (inactive) {
        validPassword = false;
      }

      /*
       * REJECT INVALID CREDENTIALS
       */
      if (
        !admin ||
        !validPassword
      ) {
        if (
          admin &&
          !inactive
        ) {
          await recordAdminLoginFailure(
            admin
          );
        }

        logAdminAction(
          req,
          "login-failed",
          {
            username:
              submittedUsername,
          }
        );

        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 401,
            username: displayUsername,
            error:
              "Access denied. Invalid credentials.",
          }
        );
      }

      /*
       * RECORD SUCCESSFUL LOGIN
       */
      await recordAdminLoginSuccess(
        admin
      );

      /*
       * SESSION FIXATION PROTECTION
       *
       * Replace the pre-authentication session ID.
       */
      await regenerateSession(
        req
      );

      /*
       * CREATE UNIQUE ADMIN SESSION TOKEN
       *
       * The raw token is stored in the server-side session.
       * Only its SHA-256 hash is stored in MongoDB.
       */
      const adminSessionToken =
        crypto.randomBytes(32).toString("hex");

      const adminSessionTokenHash =
        crypto
          .createHash("sha256")
          .update(adminSessionToken)
          .digest("hex");

      /*
       * SET THE AUTHENTICATED ADMIN IDENTITY
       */
      req.session.admin = {
        id:
          admin._id.toString(),

        _id:
          admin._id.toString(),

        username:
          normalizeUsername(
            admin.username
          ),

        role:
          normalizeString(
            admin.role || "admin",
            80
          ).toLowerCase(),
      };

      req.session.adminSessionToken =
        adminSessionToken;

      /*
       * Keep customer identity separate from the admin session.
       */
      delete req.session.user;

      /*
       * SAVE THE NEW SESSION FIRST
       */
      await saveSession(
        req
      );

      /*
       * ACTIVATE THIS ADMIN SESSION GLOBALLY
       *
       * Replacing this hash invalidates older administrator
       * sessions on their next protected /admin request.
       */
      const controlUpdate = {
        activeSessionTokenHash:
          adminSessionTokenHash,

        adminId:
          admin._id,

        updatedAt:
          new Date(),
      };

      try {
        await AdminSessionControl.findOneAndUpdate(
          {
            _id: "global",
          },
          {
            $set: controlUpdate,
          },
          {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true,
          }
        );
      } catch (controlError) {
        /*
         * Handle a duplicate-key race if simultaneous first
         * logins try to create the singleton record.
         */
        if (
          controlError?.code !== 11000
        ) {
          throw controlError;
        }

        await AdminSessionControl.updateOne(
          {
            _id: "global",
          },
          {
            $set: controlUpdate,
          }
        );
      }

      /*
       * PRESERVE EXISTING ACTIVITY LOGGING
       */
      logAdminAction(
        req,
        "login",
        {
          adminId:
            admin._id,
        }
      );

      return res.redirect(
        303,
        "/admin/dashboard"
      );

    } catch (error) {
      console.error(
        `[ADMIN LOGIN ERROR] requestId=${
          getRequestId(req) || "none"
        }`,
        error.stack ||
          error.message ||
          error
      );

      return renderAdminLogin(
        req,
        res,
        {
          statusCode: 500,
          username: displayUsername,
          error:
            "We were unable to process the administrator login. Please try again.",
        }
      );
    }
  }
);

/* ============================================================
   ROOM / CATALOG HELPERS
============================================================ */

function normalizeRoomRecord(
  record
) {
  if (!record) {
    return null;
  }

  const plain =
    typeof record.toObject ===
    "function"
      ? record.toObject()
      : record;

  const name =
    normalizeString(
      pickFirst(
        plain,
        [
          "displayName",
          "name",
          "roomName",
          "title",
          "type",
        ],
        ""
      ),
      150
    );

  if (
    !name
  ) {
    return null;
  }

  const price =
    Math.max(
      0,
      parseNumber(
        pickFirst(
          plain,
          [
            "price",
            "nightlyPrice",
            "pricePerNight",
            "rate",
          ],
          0
        ),
        0
      )
    );

  const maxGuests =
    Math.max(
      1,
      parseInteger(
        pickFirst(
          plain,
          [
            "maxGuests",
            "capacity",
            "guestLimit",
            "maxOccupancy",
          ],
          1
        ),
        1
      )
    );

  const quantity =
    Math.max(
      1,
      parseInteger(
        pickFirst(
          plain,
          [
            "quantity",
            "units",
            "inventory",
          ],
          1
        ),
        1
      )
    );

  const image =
    normalizeString(
      pickFirst(
        plain,
        [
          "image",
          "imageUrl",
          "photo",
          "photoUrl",
        ],
        "/images/room1.jpg"
      ),
      500
    );

  const typeValue =
    normalizeString(
      pickFirst(
        plain,
        [
          "type",
          "category",
          "roomType",
        ],
        "room"
      ),
      80
    ).toLowerCase();

  const isCottage =
    typeValue.includes(
      "cottage"
    ) ||
    name
      .toLowerCase()
      .includes(
        "cottage"
      );

  const activeValue =
    pickFirst(
      plain,
      [
        "active",
        "isActive",
        "available",
        "enabled",
      ],
      true
    );

  return {
    id:
      plain._id
        ? plain._id.toString()
        : null,

    key:
      name,

    name,

    displayName:
      name,

    price,

    maxGuests,

    quantity,

    image,

    description:
      normalizeString(
        pickFirst(
          plain,
          [
            "description",
            "details",
          ],
          ""
        ),
        2000
      ),

    sortOrder:
      Math.max(
        0,
        parseInteger(
          pickFirst(
            plain,
            [
              "sortOrder",
              "displayOrder",
              "order",
            ],
            0
          ),
          0
        )
      ),

    type:
      isCottage
        ? "cottage"
        : "room",

    active:
      activeValue !==
      false,
  };
}

async function getDynamicRooms() {
  try {
    const records =
      await Room.find({})
        .sort({
          sortOrder:
            1,

          name:
            1,

          createdAt:
            1,
        })
        .lean();

    return records
      .map(
        normalizeRoomRecord
      )
      .filter(
        Boolean
      );
  } catch (error) {
    console.error(
      "Room model read error:",
      error
    );

    return [];
  }
}

async function getConfiguredRooms() {
  const dynamicRooms =
    await getDynamicRooms();

  if (
    dynamicRooms.length >
    0
  ) {
    return dynamicRooms.filter(
      (
        room
      ) =>
        room.active
    );
  }

  return LEGACY_ROOMS.map(
    (
      room
    ) => ({
      ...room,
    })
  );
}

async function getConfiguredCottage() {
  const dynamicRooms =
    await getDynamicRooms();

  const dynamicCottage =
    dynamicRooms.find(
      (
        room
      ) =>
        room.type ===
        "cottage"
    );

  return dynamicCottage
    ? {
        ...dynamicCottage,
      }
    : {
        ...LEGACY_COTTAGE,
      };
}

async function getConfiguredAccommodation(
  roomName
) {
  const requested =
    normalizeString(
      roomName,
      150
    );

  const rooms =
    await getConfiguredRooms();

  const cottage =
    await getConfiguredCottage();

  return (
    [
      ...rooms,
      cottage,
    ].find(
      (
        room
      ) =>
        room.name ===
          requested ||
        room.displayName ===
          requested ||
        room.key ===
          requested
    ) ||
    null
  );
}

async function getRoomDocumentById(
  id
) {
  if (
    !isValidObjectId(
      id
    )
  ) {
    return null;
  }

  return Room.findById(
    id
  );
}

/**
 * Loads the authoritative current Room document for an
 * appointment.
 *
 * roomId is preferred.
 *
 * Legacy name matching remains available for older bookings.
 */
async function getRoomForAppointment(
  appointment
) {
  if (
    appointment?.roomId &&
    isValidObjectId(
      appointment.roomId
    )
  ) {
    const room =
      await Room.findById(
        appointment.roomId
      ).lean();

    if (
      room
    ) {
      return room;
    }
  }

  return {
    _id:
      null,

    name:
      normalizeString(
        appointment?.room ||
          appointment?.roomName ||
          appointment?.roomType ||
          appointment?.accommodation ||
          "",
        150
      ),

    quantity:
      1,

    active:
      true,
  };
}

/* ============================================================
   ROOM PAYLOADS
============================================================ */

function buildRoomCreatePayload(
  body
) {
  const rawName =
    firstPresent(
      body,
      [
        "name",
        "displayName",
        "roomName",
        "title",
      ]
    );

  const rawPrice =
    firstPresent(
      body,
      [
        "price",
        "nightlyPrice",
        "pricePerNight",
        "rate",
      ]
    );

  const rawMaxGuests =
    firstPresent(
      body,
      [
        "maxGuests",
        "capacity",
        "guestLimit",
        "maxOccupancy",
      ]
    );

  const rawImage =
    firstPresent(
      body,
      [
        "image",
        "imageUrl",
        "photo",
        "photoUrl",
      ]
    );

  const rawType =
    firstPresent(
      body,
      [
        "type",
        "category",
        "roomType",
      ]
    );

  const rawDescription =
    firstPresent(
      body,
      [
        "description",
        "details",
      ]
    );

  const rawQuantity =
    firstPresent(
      body,
      [
        "quantity",
        "units",
        "inventory",
      ]
    );

  const rawSortOrder =
    firstPresent(
      body,
      [
        "sortOrder",
        "displayOrder",
        "order",
      ]
    );

  const rawActive =
    firstPresent(
      body,
      [
        "active",
        "isActive",
        "available",
        "enabled",
      ]
    );

  return {
    name:
      normalizeString(
        rawName,
        150
      ),

    price:
      Math.max(
        0,
        parseNumber(
          rawPrice,
          0
        )
      ),

    maxGuests:
      Math.max(
        1,
        parseInteger(
          rawMaxGuests,
          1
        )
      ),

    image:
      normalizeString(
        rawImage ||
          "/images/room1.jpg",
        500
      ),

    type:
      normalizeString(
        rawType ||
          "room",
        80
      ),

    description:
      normalizeString(
        rawDescription,
        2000
      ),

    quantity:
      Math.max(
        1,
        parseInteger(
          rawQuantity,
          1
        )
      ),

    sortOrder:
      Math.max(
        0,
        parseInteger(
          rawSortOrder,
          0
        )
      ),

    active:
      rawActive ===
      undefined
        ? true
        : asBoolean(
            rawActive
          ),
  };
}

function buildRoomUpdatePayload(
  body
) {
  const payload =
    {};

  if (
    hasOwn(
      body,
      "name",
      "displayName",
      "roomName",
      "title"
    )
  ) {
    const value =
      firstPresent(
        body,
        [
          "name",
          "displayName",
          "roomName",
          "title",
        ]
      );

    payload.name =
      normalizeString(
        value,
        150
      );
  }

  if (
    hasOwn(
      body,
      "price",
      "nightlyPrice",
      "pricePerNight",
      "rate"
    )
  ) {
    payload.price =
      Math.max(
        0,
        parseNumber(
          firstPresent(
            body,
            [
              "price",
              "nightlyPrice",
              "pricePerNight",
              "rate",
            ]
          ),
          0
        )
      );
  }

  if (
    hasOwn(
      body,
      "maxGuests",
      "capacity",
      "guestLimit",
      "maxOccupancy"
    )
  ) {
    payload.maxGuests =
      Math.max(
        1,
        parseInteger(
          firstPresent(
            body,
            [
              "maxGuests",
              "capacity",
              "guestLimit",
              "maxOccupancy",
            ]
          ),
          1
        )
      );
  }

  if (
    hasOwn(
      body,
      "image",
      "imageUrl",
      "photo",
      "photoUrl"
    )
  ) {
    payload.image =
      normalizeString(
        firstPresent(
          body,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ]
        ),
        500
      );
  }

  if (
    hasOwn(
      body,
      "type",
      "category",
      "roomType"
    )
  ) {
    payload.type =
      normalizeString(
        firstPresent(
          body,
          [
            "type",
            "category",
            "roomType",
          ]
        ),
        80
      );
  }

  if (
    hasOwn(
      body,
      "description",
      "details"
    )
  ) {
    payload.description =
      normalizeString(
        firstPresent(
          body,
          [
            "description",
            "details",
          ]
        ),
        2000
      );
  }

  if (
    hasOwn(
      body,
      "quantity",
      "units",
      "inventory"
    )
  ) {
    payload.quantity =
      Math.max(
        1,
        parseInteger(
          firstPresent(
            body,
            [
              "quantity",
              "units",
              "inventory",
            ]
          ),
          1
        )
      );
  }

  if (
    hasOwn(
      body,
      "sortOrder",
      "displayOrder",
      "order"
    )
  ) {
    payload.sortOrder =
      Math.max(
        0,
        parseInteger(
          firstPresent(
            body,
            [
              "sortOrder",
              "displayOrder",
              "order",
            ]
          ),
          0
        )
      );
  }

  if (
    hasOwn(
      body,
      "active",
      "isActive",
      "available",
      "enabled"
    )
  ) {
    payload.active =
      asBoolean(
        firstPresent(
          body,
          [
            "active",
            "isActive",
            "available",
            "enabled",
          ]
        )
      );
  }

  return payload;
}

/* ============================================================
   ADD-ON HELPERS
============================================================ */

function normalizeAddOnPricingType(
  value
) {
  const normalized =
    normalizeString(
      value,
      50
    )
      .toLowerCase()
      .replace(
        /[\s_-]+/g,
        ""
      );

  if (
    normalized ===
      "pernight" ||
    normalized ===
      "nightly" ||
    normalized ===
      "night"
  ) {
    return "perNight";
  }

  return "once";
}

function buildAddOnCreatePayload(
  body
) {
  const name =
    normalizeString(
      firstPresent(
        body,
        [
          "name",
          "displayName",
          "title",
        ]
      ),
      150
    );

  const price =
    Math.max(
      0,
      parseNumber(
        firstPresent(
          body,
          [
            "price",
            "amount",
            "rate",
          ]
        ),
        0
      )
    );

  return {
    name,

    price,

    pricingType:
      normalizeAddOnPricingType(
        firstPresent(
          body,
          [
            "pricingType",
            "priceType",
            "billingType",
          ]
        )
      ),

    sortOrder:
      Math.max(
        0,
        parseInteger(
          firstPresent(
            body,
            [
              "sortOrder",
              "displayOrder",
              "order",
            ]
          ),
          0
        )
      ),

    image:
      normalizeString(
        firstPresent(
          body,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ]
        ),
        500
      ),

    description:
      normalizeString(
        firstPresent(
          body,
          [
            "description",
            "details",
          ]
        ),
        2000
      ),

    active:
      firstPresent(
        body,
        [
          "active",
          "isActive",
          "available",
          "enabled",
        ]
      ) ===
        undefined
        ? true
        : asBoolean(
            firstPresent(
              body,
              [
                "active",
                "isActive",
                "available",
                "enabled",
              ]
            )
          ),
  };
}

function buildAddOnUpdatePayload(
  body
) {
  const payload =
    {};

  if (
    hasOwn(
      body,
      "name",
      "displayName",
      "title"
    )
  ) {
    payload.name =
      normalizeString(
        firstPresent(
          body,
          [
            "name",
            "displayName",
            "title",
          ]
        ),
        150
      );
  }

  if (
    hasOwn(
      body,
      "price",
      "amount",
      "rate"
    )
  ) {
    payload.price =
      Math.max(
        0,
        parseNumber(
          firstPresent(
            body,
            [
              "price",
              "amount",
              "rate",
            ]
          ),
          0
        )
      );
  }

  if (
    hasOwn(
      body,
      "pricingType",
      "priceType",
      "billingType"
    )
  ) {
    payload.pricingType =
      normalizeAddOnPricingType(
        firstPresent(
          body,
          [
            "pricingType",
            "priceType",
            "billingType",
          ]
        )
      );
  }

  if (
    hasOwn(
      body,
      "sortOrder",
      "displayOrder",
      "order"
    )
  ) {
    payload.sortOrder =
      Math.max(
        0,
        parseInteger(
          firstPresent(
            body,
            [
              "sortOrder",
              "displayOrder",
              "order",
            ]
          ),
          0
        )
      );
  }

  if (
    hasOwn(
      body,
      "image",
      "imageUrl",
      "photo",
      "photoUrl"
    )
  ) {
    payload.image =
      normalizeString(
        firstPresent(
          body,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ]
        ),
        500
      );
  }

  if (
    hasOwn(
      body,
      "description",
      "details"
    )
  ) {
    payload.description =
      normalizeString(
        firstPresent(
          body,
          [
            "description",
            "details",
          ]
        ),
        2000
      );
  }

  if (
    hasOwn(
      body,
      "active",
      "isActive",
      "available",
      "enabled"
    )
  ) {
    payload.active =
      asBoolean(
        firstPresent(
          body,
          [
            "active",
            "isActive",
            "available",
            "enabled",
          ]
        )
      );
  }

  return payload;
}

function normalizeAddOnRecord(
  record
) {
  if (!record) {
    return null;
  }

  const plain =
    typeof record.toObject ===
    "function"
      ? record.toObject()
      : record;

  const name =
    normalizeString(
      pickFirst(
        plain,
        [
          "name",
          "displayName",
          "title",
        ],
        ""
      ),
      150
    );

  if (!name) {
    return null;
  }

  const price =
    Math.max(
      0,
      parseNumber(
        pickFirst(
          plain,
          [
            "price",
            "amount",
            "rate",
          ],
          0
        ),
        0
      )
    );

  return {
    ...plain,

    id:
      plain._id
        ? plain._id.toString()
        : null,

    name,

    displayName:
      name,

    price,

    amount:
      price,

    pricingType:
      normalizeAddOnPricingType(
        pickFirst(
          plain,
          [
            "pricingType",
            "priceType",
            "billingType",
          ],
          "once"
        )
      ),

    sortOrder:
      Math.max(
        0,
        parseInteger(
          pickFirst(
            plain,
            [
              "sortOrder",
              "displayOrder",
              "order",
            ],
            0
          ),
          0
        )
      ),

    image:
      normalizeString(
        pickFirst(
          plain,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ],
          ""
        ),
        500
      ),

    description:
      normalizeString(
        pickFirst(
          plain,
          [
            "description",
            "details",
          ],
          ""
        ),
        2000
      ),

    active:
      pickFirst(
        plain,
        [
          "active",
          "isActive",
          "available",
          "enabled",
        ],
        true
      ) !==
      false,
  };
}

/* ============================================================
   BOOKING STATUS
============================================================ */

function canTransitionStatus(
  from,
  to
) {
  if (
    !ALL_STATUSES.includes(
      from
    ) ||
    !ALL_STATUSES.includes(
      to
    )
  ) {
    return false;
  }

  if (
    from ===
    to
  ) {
    return true;
  }

  return Boolean(
    STATUS_TRANSITIONS[
      from
    ]?.includes(
      to
    )
  );
}

function applyStatusTimestamps(
  appointment,
  status
) {
  const now =
    new Date();

  const timestampFields =
    {
      accepted: [
        "acceptedAt",
      ],

      confirmed: [
        "confirmedAt",
      ],

      declined: [
        "declinedAt",
      ],

      rejected: [
        "rejectedAt",
      ],

      cancelled: [
        "cancelledAt",
      ],

      "checked-in": [
        "checkedInAt",
        "checkInTime",
      ],

      "checked-out": [
        "checkedOutAt",
        "checkOutTime",
      ],

      completed: [
        "completedAt",
      ],
    };

  const fields =
    timestampFields[
      status
    ] ||
    [];

  if (
    fields.length
  ) {
    setModelValue(
      appointment,
      fields,
      now
    );
  }

  if (
    status ===
    "cancelled"
  ) {
    setModelValue(
      appointment,
      [
        "cancelledBy",
      ],
      "admin"
    );
  }

  if (
    status ===
    "checked-in"
  ) {
    setModelValue(
      appointment,
      [
        "checkedIn",
      ],
      true
    );
  }

  if (
    status ===
    "checked-out"
  ) {
    setModelValue(
      appointment,
      [
        "checkedOut",
      ],
      true
    );

    setModelValue(
      appointment,
      [
        "checkedIn",
      ],
      false
    );
  }
}

function statusNotification(
  status
) {
  switch (
    status
  ) {
    case "accepted":
      return {
        event:
          "accepted",

        title:
          "Booking Accepted",

        message:
          "Your resort booking request has been accepted.",
      };

    case "confirmed":
      return {
        event:
          "confirmed",

        title:
          "Booking Confirmed",

        message:
          "Your resort booking has been confirmed.",
      };

    case "declined":
      return {
        event:
          "declined",

        title:
          "Booking Declined",

        message:
          "Your resort booking request was declined.",
      };

    case "rejected":
      return {
        event:
          "rejected",

        title:
          "Booking Rejected",

        message:
          "Your resort booking request was rejected.",
      };

    case "cancelled":
      return {
        event:
          "cancelled",

        title:
          "Booking Cancelled",

        message:
          "Your resort booking has been cancelled.",
      };

    case "checked-in":
      return {
        event:
          "checked-in",

        title:
          "Check-in Completed",

        message:
          "Your resort check-in has been completed.",
      };

    case "checked-out":
      return {
        event:
          "checked-out",

        title:
          "Check-out Completed",

        message:
          "Your resort check-out has been completed.",
      };

    case "completed":
      return {
        event:
          "completed",

        title:
          "Stay Completed",

        message:
          "Your resort stay has been marked completed.",
      };

    default:
      return {
        event:
          "general",

        title:
          "Booking Update",

        message:
          "Your resort booking has been updated.",
      };
  }
}

function logAdminAction(
  req,
  action,
  details = {}
) {
  const admin =
    getAdminSession(
      req
    );

  const adminId =
    admin?.id ||
    admin?._id ||
    "unknown";

  const detailText =
    Object.entries(
      details
    )
      .map(
        (
          [key, value]
        ) =>
          `${key}=${String(
            value
          ).replace(
            /[\r\n]+/g,
            " "
          )}`
      )
      .join(" ");

  console.log(
    `[ADMIN ACTION] action=${action} adminId=${adminId} username=${
      admin?.username ||
      "unknown"
    } requestId=${
      getRequestId(
        req
      ) ||
      "none"
    } ${detailText}`
  );
}

/* ============================================================
   AUTHORITATIVE BOOKING STATUS UPDATE
============================================================ */

/**
 * All administrator booking mutations are serialized by room.
 *
 * This is critical.
 *
 * Old approach:
 *
 *   find appointment
 *   check status
 *   check room
 *   save
 *
 * Hardened approach:
 *
 *   find appointment
 *   identify room
 *   LOCK ROOM
 *   re-read appointment
 *   validate current status
 *   re-read room
 *   re-check inventory
 *   save status
 *   UNLOCK ROOM
 *
 * This keeps admin operations synchronized with customer booking
 * and cancellation requests.
 */
async function updateStatusInternal({
  bookingId,
  status,
  req =
    null,
}) {
  if (
    !isValidObjectId(
      bookingId
    )
  ) {
    return {
      ok:
        false,

      statusCode:
        400,

      code:
        "INVALID_BOOKING_ID",

      message:
        "Invalid booking ID.",
    };
  }

  if (
    !ALL_STATUSES.includes(
      status
    )
  ) {
    return {
      ok:
        false,

      statusCode:
        400,

      code:
        "INVALID_STATUS",

      message:
        "Invalid booking status.",
    };
  }

  /*
   * Initial read only identifies which room resource to lock.
   */
  const initial =
    await Appointment.findById(
      bookingId
    )
      .select(
        "_id userId roomId room roomType accommodation roomName checkin checkout status"
      )
      .lean();

  if (
    !initial
  ) {
    return {
      ok:
        false,

      statusCode:
        404,

      code:
        "BOOKING_NOT_FOUND",

      message:
        "Booking not found.",
    };
  }

  const roomResource = {
    _id:
      initial.roomId ||
      null,

    name:
      initial.room ||
      initial.roomName ||
      initial.roomType ||
      initial.accommodation ||
      "",
  };

  try {
    return await withRoomLock(
      roomResource,
      async () => {
        /*
         * Re-read the appointment after the lock is acquired.
         */
        const appointment =
          await Appointment.findById(
            bookingId
          );

        if (
          !appointment
        ) {
          return {
            ok:
              false,

            statusCode:
              404,

            code:
              "BOOKING_NOT_FOUND",

            message:
              "Booking not found.",
          };
        }

        const currentStatus =
          String(
            appointment.status ||
              "pending"
          ).toLowerCase();

        /*
         * Idempotent repeated request.
         */
        if (
          currentStatus ===
          status
        ) {
          return {
            ok:
              true,

            appointment,

            changed:
              false,

            message:
              "Booking already has this status.",
          };
        }

        if (
          !canTransitionStatus(
            currentStatus,
            status
          )
        ) {
          return {
            ok:
              false,

            statusCode:
              400,

            code:
              "INVALID_STATUS_TRANSITION",

            message:
              `Invalid booking status transition: ${currentStatus} → ${status}.`,
          };
        }

        /*
         * ------------------------------------------------------
         * INVENTORY CHECK
         * ------------------------------------------------------
         *
         * Any target status that blocks inventory must be checked
         * against current room capacity.
         */
        if (
          BLOCKING_STATUSES.includes(
            status
          ) &&
          appointment.checkin &&
          appointment.checkout
        ) {
          const room =
            await getRoomForAppointment(
              appointment
            );

          /*
           * A deleted/deactivated room should not silently make a
           * new booking active if the room no longer exists.
           */
          if (
            appointment.roomId &&
            !room?._id
          ) {
            return {
              ok:
                false,

              statusCode:
                409,

              code:
                "ROOM_NOT_AVAILABLE",

              message:
                "The accommodation assigned to this booking is no longer available.",
            };
          }

          const conflict =
            await findAvailabilityConflict(
              {
                room,

                checkin:
                  appointment.checkin,

                checkout:
                  appointment.checkout,

                excludeAppointmentId:
                  appointment._id,
              }
            );

          if (
            conflict
          ) {
            return {
              ok:
                false,

              statusCode:
                409,

              code:
                "ROOM_ALREADY_BOOKED",

              message:
                "This accommodation has no remaining inventory for the selected dates.",

              conflict:
                conflict.conflict ||
                null,
            };
          }
        }

        const previousStatus =
          currentStatus;

        appointment.status =
          status;

        applyStatusTimestamps(
          appointment,
          status
        );

        await appointment.save();

        const notification =
          statusNotification(
            status
          );

        await notifyUser(
          appointment.userId,
          notification.event,
          notification.title,
          notification.message,
          appointment._id
        );

        if (
          req
        ) {
          logAdminAction(
            req,
            "booking-status-change",
            {
              bookingId:
                appointment._id,

              from:
                previousStatus,

              to:
                status,
            }
          );
        }

        return {
          ok:
            true,

          appointment,

          changed:
            true,

          previousStatus,

          message:
            `Booking status updated to ${status}.`,
        };
      },
      BOOKING_LOCK_OPTIONS
    );
  } catch (
    error
  ) {
    if (
      error?.code ===
      "BOOKING_LOCK_TIMEOUT"
    ) {
      return {
        ok:
          false,

        statusCode:
          409,

        code:
          "BOOKING_LOCK_TIMEOUT",

        message:
          "This reservation is currently being updated. Please try again in a moment.",
      };
    }

    throw error;
  }
}

/* ============================================================
   DASHBOARD
============================================================ */

router.get(
  "/dashboard",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const today =
        startOfToday();

      const tomorrow =
        endOfToday();

      const [
        totalBookings,
        pendingBookings,
        acceptedBookings,
        confirmedBookings,
        cancelledBookings,
        checkedInCount,
        checkedOutCount,
        totalUsers,
        arrivalsToday,
        recentBookings,
      ] =
        await Promise.all(
          [
            Appointment.countDocuments(),

            Appointment.countDocuments(
              {
                status:
                  "pending",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "accepted",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "confirmed",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "cancelled",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "checked-in",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "checked-out",
              }
            ),

            User.countDocuments(),

            Appointment.countDocuments(
              {
                status: {
                  $in: [
                    "accepted",
                    "confirmed",
                  ],
                },

                checkin: {
                  $gte:
                    today,

                  $lt:
                    tomorrow,
                },
              }
            ),

            Appointment.find()
              .populate(
                "userId",
                "fullname email phone"
              )
              .sort({
                createdAt:
                  -1,
              })
              .limit(
                8
              )
              .lean(),
          ]
        );

      return res.render(
        "admin/dashboard",
        {
          title:
            "Isle Command",

          admin:
            getAdminSession(
              req
            ),

          totalBookings,

          pendingBookings,

          acceptedBookings,

          confirmedBookings,

          cancelledBookings,

          checkedInCount,

          checkedOutCount,

          totalUsers,

          arrivalsToday,

          inHouseCount:
            checkedInCount,

          recentBookings,
        }
      );
    } catch (
      error
    ) {
      console.error(
        "Dashboard Error:",
        error
      );

      return renderAdminError(
        res,
        500,
        "Dashboard Error",
        "Unable to load the admin dashboard."
      );
    }
  }
);

/* ============================================================
   ANALYTICS
============================================================ */

router.get(
  "/analytics",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const bookingValueStatuses = [
        "accepted",
        "confirmed",
        "checked-in",
        "checked-out",
        "completed",
      ];

      const [
        totalBookings,
        pending,
        accepted,
        confirmed,
        declined,
        cancelled,
        checkedIn,
        checkedOut,
        completed,
        totalUsers,
        revenueResult,
        roomBreakdown,
        recentActivity,
      ] =
        await Promise.all(
          [
            Appointment.countDocuments(),

            Appointment.countDocuments(
              {
                status:
                  "pending",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "accepted",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "confirmed",
              }
            ),

            Appointment.countDocuments(
              {
                status: {
                  $in: [
                    "declined",
                    "rejected",
                  ],
                },
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "cancelled",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "checked-in",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "checked-out",
              }
            ),

            Appointment.countDocuments(
              {
                status:
                  "completed",
              }
            ),

            User.countDocuments(),

            Appointment.aggregate(
              [
                {
                  $match: {
                    status: {
                      $in:
                        bookingValueStatuses,
                    },
                  },
                },

                {
                  $group: {
                    _id:
                      null,

                    total: {
                      $sum: {
                        $ifNull: [
                          "$totalPrice",
                          0,
                        ],
                      },
                    },
                  },
                },
              ]
            ),

            Appointment.aggregate(
              [
                {
                  $match: {
                    status: {
                      $in:
                        bookingValueStatuses,
                    },
                  },
                },

                {
                  $group: {
                    _id:
                      "$room",

                    bookings: {
                      $sum:
                        1,
                    },

                    grossBookingValue:
                      {
                        $sum: {
                          $ifNull:
                            [
                              "$totalPrice",
                              0,
                            ],
                        },
                      },
                  },
                },

                {
                  $sort: {
                    bookings:
                      -1,
                  },
                },
              ]
            ),

            Appointment.find()
              .populate(
                "userId",
                "fullname email phone"
              )
              .sort({
                updatedAt:
                  -1,

                createdAt:
                  -1,
              })
              .limit(
                20
              )
              .lean(),
          ]
        );

      /*
       * This value is intentionally still exposed as `revenue`
       * for compatibility with your existing analytics EJS.
       *
       * It represents BOOKING VALUE, not verified payment cash,
       * because IsleRMS does not currently have a Payment model.
       */
      const revenue =
        parseNumber(
          revenueResult?.[0]?.total,
          0
        );

      const normalizedRoomBreakdown =
        roomBreakdown.map(
          (
            entry
          ) => ({
            ...entry,

            revenue:
              parseNumber(
                entry.grossBookingValue,
                0
              ),
          })
        );

      return res.render(
        "admin/analytics",
        {
          title:
            "Resort Analytics",

          admin:
            getAdminSession(
              req
            ),

          totalBookings,

          totalUsers,

          pending,

          accepted,

          confirmed,

          declined,

          cancelled,

          checkedIn,

          checkedOut,

          completed,

          revenue,

          /*
           * New explicit name while keeping legacy `revenue`.
           */
          bookingValue:
            revenue,

          roomBreakdown:
            normalizedRoomBreakdown,

          recentActivity,
        }
      );
    } catch (
      error
    ) {
      console.error(
        "Analytics Error:",
        error
      );

      return renderAdminError(
        res,
        500,
        "Analytics Error",
        "Unable to load resort analytics."
      );
    }
  }
);

/* ============================================================
   HISTORY
============================================================ */

router.get(
  "/history",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const allBookings =
        await Appointment.find()
          .populate(
            "userId",
            "fullname email phone"
          )
          .sort({
            createdAt:
              -1,
          })
          .lean();

      return res.render(
        "admin/history",
        {
          title:
            "Isle Archive",

          admin:
            getAdminSession(
              req
            ),

          allBookings,

          bookings:
            allBookings,

          appointments:
            allBookings,
        }
      );
    } catch (
      error
    ) {
      console.error(
        "History Page Error:",
        error
      );

      return renderAdminError(
        res,
        500,
        "History Error",
        "Unable to load booking history."
      );
    }
  }
);

/* ============================================================
   FRONT DESK
============================================================ */

async function renderCheckinManager(
  req,
  res
) {
  try {
    const [
      arrivals,
      inHouse,
    ] =
      await Promise.all(
        [
          Appointment.find(
            {
              status: {
                $in: [
                  "accepted",
                  "confirmed",
                ],
              },
            }
          )
            .populate(
              "userId",
              "fullname email phone"
            )
            .sort({
              checkin:
                1,

              createdAt:
                -1,
            })
            .lean(),

          Appointment.find(
            {
              status:
                "checked-in",
            }
          )
            .populate(
              "userId",
              "fullname email phone"
            )
            .sort({
              checkedInAt:
                -1,

              checkin:
                1,

              checkout:
                1,

              createdAt:
                -1,
            })
            .lean(),
        ]
      );

    const bookings = [
      ...arrivals,
      ...inHouse,
    ];

    return res.render(
      "admin/checkin",
      {
        title:
          "Front Desk Operations",

        admin:
          getAdminSession(
            req
          ),

        arrivals,

        inHouse,

        bookings,

        appointments:
          bookings,
      }
    );
  } catch (
    error
  ) {
    console.error(
      "Check-in manager error:",
      error
    );

    return renderAdminError(
      res,
      500,
      "Front Desk Error",
      "Unable to load check-in manager."
    );
  }
}

router.get(
  "/checkin-manager",
  requireAdmin,
  renderCheckinManager
);

router.get(
  "/checkin",
  requireAdmin,
  renderCheckinManager
);

/* ============================================================
   CHECK-IN
============================================================ */

router.post(
  "/update-checkin",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal(
          {
            bookingId,

            status:
              "checked-in",

            req,
          }
        );

      if (
        !result.ok
      ) {
        return sendApiError(
          res,
          result.statusCode ||
            400,

          result.message,

          result.code ||
            "CHECKIN_FAILED",

          getRequestId(
            req
          )
        );
      }

      return res.json({
        success:
          true,

        message:
          result.changed
            ? "Guest checked in successfully."
            : "Guest is already checked in.",

        booking: {
          id:
            result.appointment
              ._id,

          status:
            result.appointment
              .status,

          checkedInAt:
            result.appointment
              .checkedInAt ||
            result.appointment
              .checkInTime ||
            null,
        },
      });
    } catch (
      error
    ) {
      console.error(
        `[CHECK-IN UPDATE ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Failed to update check-in status.",
        "CHECKIN_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   CHECK-OUT
============================================================ */

router.post(
  "/update-checkout",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal(
          {
            bookingId,

            status:
              "checked-out",

            req,
          }
        );

      if (
        !result.ok
      ) {
        return sendApiError(
          res,
          result.statusCode ||
            400,

          result.message,

          result.code ||
            "CHECKOUT_FAILED",

          getRequestId(
            req
          )
        );
      }

      return res.json({
        success:
          true,

        message:
          result.changed
            ? "Guest checked out successfully."
            : "Guest is already checked out.",

        booking: {
          id:
            result.appointment
              ._id,

          status:
            result.appointment
              .status,

          checkedOutAt:
            result.appointment
              .checkedOutAt ||
            result.appointment
              .checkOutTime ||
            null,
        },
      });
    } catch (
      error
    ) {
      console.error(
        `[CHECK-OUT UPDATE ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Failed to update check-out status.",
        "CHECKOUT_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   GENERAL BOOKING STATUS UPDATE
============================================================ */

router.post(
  "/booking/update-status",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const status =
        normalizeString(
          req.body?.status,
          50
        ).toLowerCase();

      const result =
        await updateStatusInternal(
          {
            bookingId,

            status,

            req,
          }
        );

      if (
        !result.ok
      ) {
        return sendApiError(
          res,
          result.statusCode ||
            400,

          result.message,

          result.code ||
            "BOOKING_STATUS_UPDATE_FAILED",

          getRequestId(
            req
          )
        );
      }

      return res.json({
        success:
          true,

        message:
          result.message,

        changed:
          result.changed,

        booking: {
          id:
            result.appointment
              ._id,

          status:
            result.appointment
              .status,

          checkin:
            result.appointment
              .checkin,

          checkout:
            result.appointment
              .checkout,
        },
      });
    } catch (
      error
    ) {
      console.error(
        `[BOOKING STATUS UPDATE ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Failed to update booking status.",
        "BOOKING_STATUS_UPDATE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   QUICK ACCEPT
============================================================ */

router.post(
  "/booking/accept",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal(
          {
            bookingId,

            status:
              "accepted",

            req,
          }
        );

      if (
        !result.ok
      ) {
        return sendApiError(
          res,
          result.statusCode ||
            400,

          result.message,

          result.code ||
            "BOOKING_ACCEPT_FAILED",

          getRequestId(
            req
          )
        );
      }

      return res.json({
        success:
          true,

        message:
          "Booking accepted successfully.",

        booking: {
          id:
            result.appointment
              ._id,

          status:
            result.appointment
              .status,
        },
      });
    } catch (
      error
    ) {
      console.error(
        `[QUICK ACCEPT ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Failed to accept booking.",
        "BOOKING_ACCEPT_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   QUICK DECLINE
============================================================ */

router.post(
  "/booking/decline",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal(
          {
            bookingId,

            status:
              "declined",

            req,
          }
        );

      if (
        !result.ok
      ) {
        return sendApiError(
          res,
          result.statusCode ||
            400,

          result.message,

          result.code ||
            "BOOKING_DECLINE_FAILED",

          getRequestId(
            req
          )
        );
      }

      return res.json({
        success:
          true,

        message:
          "Booking declined successfully.",

        booking: {
          id:
            result.appointment
              ._id,

          status:
            result.appointment
              .status,
        },
      });
    } catch (
      error
    ) {
      console.error(
        `[QUICK DECLINE ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Failed to decline booking.",
        "BOOKING_DECLINE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   USERS / CUSTOMER MANAGEMENT
============================================================ */

router.get(
  "/users",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const realizedStatuses = [
        "checked-out",
        "completed",
      ];

      const bookingValueStatuses = [
        "accepted",
        "confirmed",
        "checked-in",
        "checked-out",
        "completed",
      ];

      const upcomingStatuses = [
        "accepted",
        "confirmed",
      ];

      const activeStatuses = [
        "pending",
        "accepted",
        "confirmed",
        "checked-in",
      ];

      const now =
        new Date();

      const [
        users,
        bookingStats,
      ] =
        await Promise.all(
          [
            User.find()
              .select(
                "fullname username email phone status emailVerified " +
                  "memberLevel failedLoginAttempts lockedUntil lastLoginAt " +
                  "passwordChangedAt createdAt updatedAt"
              )
              .sort({
                createdAt:
                  -1,
              })
              .lean(),

            Appointment.aggregate(
              [
                {
                  $group: {
                    _id:
                      "$userId",

                    totalBookings: {
                      $sum:
                        1,
                    },

                    activeBookings: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              activeStatuses,
                            ],
                          },

                          1,

                          0,
                        ],
                      },
                    },

                    completedStays: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              realizedStatuses,
                            ],
                          },

                          1,

                          0,
                        ],
                      },
                    },

                    cancelledBookings: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              [
                                "cancelled",
                                "declined",
                                "rejected",
                              ],
                            ],
                          },

                          1,

                          0,
                        ],
                      },
                    },

                    pendingRequests: {
                      $sum: {
                        $cond: [
                          {
                            $eq: [
                              "$status",
                              "pending",
                            ],
                          },

                          1,

                          0,
                        ],
                      },
                    },

                    bookingValueBookings: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              bookingValueStatuses,
                            ],
                          },

                          1,

                          0,
                        ],
                      },
                    },

                    totalBookingValue: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              bookingValueStatuses,
                            ],
                          },

                          {
                            $ifNull: [
                              "$totalPrice",
                              0,
                            ],
                          },

                          0,
                        ],
                      },
                    },

                    realizedValue: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              realizedStatuses,
                            ],
                          },

                          {
                            $ifNull: [
                              "$totalPrice",
                              0,
                            ],
                          },

                          0,
                        ],
                      },
                    },

                    upcomingValue: {
                      $sum: {
                        $cond: [
                          {
                            $and: [
                              {
                                $in: [
                                  "$status",
                                  upcomingStatuses,
                                ],
                              },

                              {
                                $gte: [
                                  "$checkout",
                                  now,
                                ],
                              },
                            ],
                          },

                          {
                            $ifNull: [
                              "$totalPrice",
                              0,
                            ],
                          },

                          0,
                        ],
                      },
                    },

                    totalNights: {
                      $sum: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              realizedStatuses,
                            ],
                          },

                          {
                            $ifNull: [
                              "$numberOfNights",
                              0,
                            ],
                          },

                          0,
                        ],
                      },
                    },

                    upcomingNights: {
                      $sum: {
                        $cond: [
                          {
                            $and: [
                              {
                                $in: [
                                  "$status",
                                  upcomingStatuses,
                                ],
                              },

                              {
                                $gte: [
                                  "$checkout",
                                  now,
                                ],
                              },
                            ],
                          },

                          {
                            $ifNull: [
                              "$numberOfNights",
                              0,
                            ],
                          },

                          0,
                        ],
                      },
                    },

                    lastBookingAt: {
                      $max:
                        "$createdAt",
                    },

                    lastCheckout: {
                      $max: {
                        $cond: [
                          {
                            $in: [
                              "$status",
                              realizedStatuses,
                            ],
                          },

                          "$checkout",

                          null,
                        ],
                      },
                    },

                    nextCheckinCandidate:
                      {
                        $min: {
                          $cond: [
                            {
                              $and: [
                                {
                                  $in: [
                                    "$status",
                                    upcomingStatuses,
                                  ],
                                },

                                {
                                  $gte: [
                                    "$checkout",
                                    now,
                                  ],
                                },
                              ],
                            },

                            "$checkin",

                            new Date(
                              "2999-12-31T23:59:59.999Z"
                            ),
                          ],
                        },
                      },
                  },
                },
              ]
            ),
          ]
        );

      const statsByUser =
        new Map(
          bookingStats.map(
            (
              entry
            ) => {
              const totalBookings =
                Number(
                  entry.totalBookings ||
                    0
                );

              const totalBookingValue =
                Number(
                  entry.totalBookingValue ||
                    0
                );

              return [
                String(
                  entry._id
                ),

                {
                  totalBookings,

                  activeBookings:
                    Number(
                      entry.activeBookings ||
                        0
                    ),

                  completedStays:
                    Number(
                      entry.completedStays ||
                        0
                    ),

                  cancelledBookings:
                    Number(
                      entry.cancelledBookings ||
                        0
                    ),

                  pendingRequests:
                    Number(
                      entry.pendingRequests ||
                        0
                    ),

                  bookingValueBookings:
                    Number(
                      entry.bookingValueBookings ||
                        0
                    ),

                  totalBookingValue,

                  averageBookingValue:
                    totalBookings >
                    0
                      ? Math.round(
                          (
                            totalBookingValue /
                            totalBookings
                          ) *
                            100
                        ) /
                        100
                      : 0,

                  realizedValue:
                    Number(
                      entry.realizedValue ||
                        0
                    ),

                  upcomingValue:
                    Number(
                      entry.upcomingValue ||
                        0
                    ),

                  totalNights:
                    Number(
                      entry.totalNights ||
                        0
                    ),

                  upcomingNights:
                    Number(
                      entry.upcomingNights ||
                        0
                    ),

                  lastBookingAt:
                    entry.lastBookingAt ||
                    null,

                  lastCheckout:
                    entry.lastCheckout ||
                    null,

                  nextCheckin:
                    entry.nextCheckinCandidate &&
                    new Date(
                      entry.nextCheckinCandidate
                    ).getUTCFullYear() <
                      2999
                      ? entry.nextCheckinCandidate
                      : null,
                },
              ];
            }
          )
        );

      const emptyStats = {
        totalBookings:
          0,

        activeBookings:
          0,

        completedStays:
          0,

        cancelledBookings:
          0,

        pendingRequests:
          0,

        bookingValueBookings:
          0,

        totalBookingValue:
          0,

        averageBookingValue:
          0,

        realizedValue:
          0,

        upcomingValue:
          0,

        totalNights:
          0,

        upcomingNights:
          0,

        lastBookingAt:
          null,

        lastCheckout:
          null,

        nextCheckin:
          null,
      };

      const enrichedUsers =
        users.map(
          (
            user
          ) => ({
            ...user,

            bookingStats:
              statsByUser.get(
                String(
                  user._id
                )
              ) || {
                ...emptyStats,
              },
          })
        );

      /*
       * Overall customer-management metrics are useful to the
       * new professional users.ejs without requiring client-side
       * aggregation.
       */
      const customerSummary =
        enrichedUsers.reduce(
          (
            summary,
            user
          ) => {
            const stats =
              user.bookingStats;

            summary.totalUsers +=
              1;

            if (
              stats.totalBookings >
              0
            ) {
              summary.customersWithBookings +=
                1;
            }

            if (
              stats.totalBookings >
              1
            ) {
              summary.returningCustomers +=
                1;
            }

            if (
              stats.totalBookingValue >=
              10000
            ) {
              summary.highValueCustomers +=
                1;
            }

            summary.totalBookingValue +=
              Number(
                stats.totalBookingValue ||
                  0
              );

            summary.totalBookings +=
              Number(
                stats.totalBookings ||
                  0
              );

            return summary;
          },
          {
            totalUsers:
              0,

            customersWithBookings:
              0,

            returningCustomers:
              0,

            highValueCustomers:
              0,

            totalBookingValue:
              0,

            totalBookings:
              0,
          }
        );

      return res.render(
        "admin/users",
        {
          title:
            "User Management",

          admin:
            getAdminSession(
              req
            ),

          users:
            enrichedUsers,

          customerSummary,
        }
      );
    } catch (
      error
    ) {
      console.error(
        `[USERS PAGE ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return renderAdminError(
        res,
        500,
        "Users Error",
        "Unable to load user management."
      );
    }
  }
);

/* ============================================================
   USER DETAIL API
============================================================ */

router.get(
  "/users/:id",
  requireAdminApi,
  async (
    req,
    res
  ) => {
    try {
      const userId =
        getResourceIdFromRequest(
          req
        );

      if (
        !isValidObjectId(
          userId
        )
      ) {
        return sendApiError(
          res,
          400,
          "Invalid user ID.",
          "INVALID_USER_ID",
          getRequestId(
            req
          )
        );
      }

      const user =
        await User.findById(
          userId
        )
          .select(
            "fullname username email phone status emailVerified " +
              "memberLevel failedLoginAttempts lockedUntil lastLoginAt " +
              "passwordChangedAt createdAt updatedAt"
          )
          .lean();

      if (
        !user
      ) {
        return sendApiError(
          res,
          404,
          "User not found.",
          "USER_NOT_FOUND",
          getRequestId(
            req
          )
        );
      }

      const bookings =
        await Appointment.find(
          {
            userId,
          }
        )
          .sort({
            createdAt:
              -1,
          })
          .lean();

      const realizedStatuses =
        new Set([
          "checked-out",
          "completed",
        ]);

      const bookingValueStatuses =
        new Set([
          "accepted",
          "confirmed",
          "checked-in",
          "checked-out",
          "completed",
        ]);

      const upcomingStatuses =
        new Set([
          "accepted",
          "confirmed",
        ]);

      const activeStatuses =
        new Set([
          "pending",
          "accepted",
          "confirmed",
          "checked-in",
        ]);

      const now =
        new Date();

      let totalBookings =
        0;

      let activeBookings =
        0;

      let completedStays =
        0;

      let cancelledBookings =
        0;

      let pendingRequests =
        0;

      let totalBookingValue =
        0;

      let realizedValue =
        0;

      let upcomingValue =
        0;

      let totalNights =
        0;

      let upcomingNights =
        0;

      let lastBookingAt =
        null;

      let lastCheckout =
        null;

      let nextCheckin =
        null;

      bookings.forEach(
        (
          booking
        ) => {
          totalBookings +=
            1;

          const status =
            normalizeString(
              booking?.status,
              50
            ).toLowerCase();

          if (
            activeStatuses.has(
              status
            )
          ) {
            activeBookings +=
              1;
          }

          const bookingTotal =
            parseNumber(
              booking?.totalPrice,
              0
            );

          const storedNights =
            parseNumber(
              booking?.numberOfNights,
              0
            );

          const calculatedNights =
            calculateNights(
              booking?.checkin,
              booking?.checkout
            );

          const nights =
            storedNights >
            0
              ? storedNights
              : calculatedNights;

          const createdAt =
            booking?.createdAt
              ? new Date(
                  booking.createdAt
                )
              : null;

          const checkout =
            booking?.checkout
              ? new Date(
                  booking.checkout
                )
              : null;

          const checkin =
            booking?.checkin
              ? new Date(
                  booking.checkin
                )
              : null;

          if (
            realizedStatuses.has(
              status
            )
          ) {
            completedStays +=
              1;

            totalNights +=
              nights;

            realizedValue +=
              bookingTotal;

            if (
              checkout &&
              !Number.isNaN(
                checkout.getTime()
              ) &&
              (
                !lastCheckout ||
                checkout >
                  lastCheckout
              )
            ) {
              lastCheckout =
                checkout;
            }
          }

          if (
            [
              "cancelled",
              "declined",
              "rejected",
            ].includes(
              status
            )
          ) {
            cancelledBookings +=
              1;
          }

          if (
            status ===
            "pending"
          ) {
            pendingRequests +=
              1;
          }

          if (
            bookingValueStatuses.has(
              status
            )
          ) {
            totalBookingValue +=
              bookingTotal;
          }

          const isUpcoming =
            upcomingStatuses.has(
              status
            ) &&
            checkout &&
            !Number.isNaN(
              checkout.getTime()
            ) &&
            checkout >=
              now;

          if (
            isUpcoming
          ) {
            upcomingValue +=
              bookingTotal;

            upcomingNights +=
              nights;

            if (
              checkin &&
              !Number.isNaN(
                checkin.getTime()
              ) &&
              (
                !nextCheckin ||
                checkin <
                  nextCheckin
              )
            ) {
              nextCheckin =
                checkin;
            }
          }

          if (
            createdAt &&
            !Number.isNaN(
              createdAt.getTime()
            ) &&
            (
              !lastBookingAt ||
              createdAt >
                lastBookingAt
            )
          ) {
            lastBookingAt =
              createdAt;
          }
        }
      );

      const averageBookingValue =
        totalBookings >
        0
          ? Math.round(
              (
                totalBookingValue /
                totalBookings
              ) *
                100
            ) /
            100
          : 0;

      return res.json({
        success:
          true,

        user,

        bookingStats: {
          totalBookings,

          activeBookings,

          completedStays,

          cancelledBookings,

          pendingRequests,

          totalBookingValue,

          averageBookingValue,

          realizedValue,

          upcomingValue,

          totalNights,

          upcomingNights,

          lastBookingAt,

          lastCheckout,

          nextCheckin,
        },

        bookings,

        appointments:
          bookings,
      });
    } catch (
      error
    ) {
      console.error(
        `[USER DETAIL ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Unable to load user details.",
        "USER_DETAIL_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   ROOMS PAGE
============================================================ */

router.get(
  "/rooms",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const [
        rooms,
        bookings,
      ] =
        await Promise.all(
          [
            Room.find()
              .sort({
                sortOrder:
                  1,

                name:
                  1,

                createdAt:
                  1,
              })
              .lean(),

            Appointment.find(
              {
                status: {
                  $in:
                    BLOCKING_STATUSES,
                },
              }
            )
              .select(
                "roomId room status checkin checkout userId"
              )
              .populate(
                "userId",
                "fullname email phone"
              )
              .sort({
                checkin:
                  1,
              })
              .lean(),
          ]
        );

      return res.render(
        "admin/rooms",
        {
          title:
            "Room Management",

          admin:
            getAdminSession(
              req
            ),

          rooms,

          bookings,
        }
      );
    } catch (
      error
    ) {
      console.error(
        "Rooms Page Error:",
        error
      );

      return renderAdminError(
        res,
        500,
        "Rooms Error",
        "Unable to load room management."
      );
    }
  }
);

/* ============================================================
   CREATE ROOM
============================================================ */

router.post(
  "/rooms/create",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const payload =
        buildRoomCreatePayload(
          req.body
        );

      if (
        !payload.name
      ) {
        return sendApiError(
          res,
          400,
          "Room name is required.",
          "INVALID_ROOM",
          getRequestId(
            req
          )
        );
      }

      /*
       * The current Room schema does not contain type/displayName,
       * so only supported schema fields are assigned.
       */
      const room =
        new Room();

      Object.entries(
        payload
      ).forEach(
        (
          [key, value]
        ) => {
          if (
            room.schema.path(
              key
            )
          ) {
            room.set(
              key,
              value
            );
          }
        }
      );

      await room.save();

      logAdminAction(
        req,
        "room-create",
        {
          roomId:
            room._id,
        }
      );

      return res
        .status(
          201
        )
        .json({
          success:
            true,

          message:
            "Room created successfully.",

          room,
        });
    } catch (
      error
    ) {
      console.error(
        "Create Room Error:",
        error
      );

      if (
        error?.name ===
        "ValidationError"
      ) {
        return sendApiError(
          res,
          400,
          Object.values(
            error.errors ||
              {}
          )
            .map(
              (
                entry
              ) =>
                entry.message
            )
            .filter(
              Boolean
            )
            .join(" ") ||
            "Some room information is invalid.",

          "VALIDATION_ERROR",

          getRequestId(
            req
          )
        );
      }

      if (
        error?.code ===
        11000
      ) {
        return sendApiError(
          res,
          409,
          "A room with the same name or slug already exists.",
          "ROOM_ALREADY_EXISTS",
          getRequestId(
            req
          )
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to create room.",
        "ROOM_CREATE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   UPDATE ROOM
============================================================ */

async function updateRoomHandler(
  req,
  res
) {
  const roomId =
    getResourceIdFromRequest(
      req
    );

  if (
    !isValidObjectId(
      roomId
    )
  ) {
    return sendApiError(
      res,
      400,
      "Invalid room ID.",
      "INVALID_ROOM_ID",
      getRequestId(
        req
      )
    );
  }

  try {
    const payload =
      buildRoomUpdatePayload(
        req.body
      );

    if (
      Object.keys(
        payload
      ).length ===
      0
    ) {
      return sendApiError(
        res,
        400,
        "No room changes were provided.",
        "NO_CHANGES",
        getRequestId(
          req
        )
      );
    }

    /*
     * Room updates are serialized with booking creation/status
     * changes.
     */
    return await withRoomLock(
      {
        _id:
          roomId,
      },
      async () => {
        const room =
          await Room.findById(
            roomId
          );

        if (
          !room
        ) {
          return sendApiError(
            res,
            404,
            "Room not found.",
            "ROOM_NOT_FOUND",
            getRequestId(
              req
            )
          );
        }

        const previousQuantity =
          Math.max(
            1,
            parseInteger(
              room.quantity,
              1
            )
          );

        const requestedQuantity =
          Object.prototype.hasOwnProperty.call(
            payload,
            "quantity"
          )
            ? Math.max(
                1,
                parseInteger(
                  payload.quantity,
                  1
                )
              )
            : previousQuantity;

        /*
         * ------------------------------------------------------
         * INVENTORY SAFETY
         * ------------------------------------------------------
         *
         * Never let an administrator lower quantity beneath the
         * number of simultaneously occupied units required by
         * existing future reservations.
         */
        if (
          requestedQuantity <
          previousQuantity
        ) {
          const peakOccupancy =
            await getPeakOccupancy(
              {
                room,

                fromDate:
                  new Date(),
              }
            );

          if (
            requestedQuantity <
            peakOccupancy
          ) {
            return sendApiError(
              res,
              409,
              `Room quantity cannot be reduced to ${requestedQuantity}. Existing active/future reservations require up to ${peakOccupancy} units.`,
              "ROOM_QUANTITY_TOO_LOW",
              getRequestId(
                req
              )
            );
          }
        }

        /*
         * Apply only fields supported by the schema.
         *
         * This preserves compatibility with your current Room.js,
         * which does not currently persist `type` or `displayName`.
         */
        Object.entries(
          payload
        ).forEach(
          (
            [key, value]
          ) => {
            if (
              room.schema.path(
                key
              )
            ) {
              room.set(
                key,
                value
              );
            }
          }
        );

        await room.save();

        logAdminAction(
          req,
          "room-update",
          {
            roomId,

            previousQuantity,

            newQuantity:
              room.quantity,
          }
        );

        return res.json({
          success:
            true,

          message:
            "Room updated successfully.",

          room,
        });
      },
      BOOKING_LOCK_OPTIONS
    );
  } catch (
    error
  ) {
    console.error(
      `[UPDATE ROOM ERROR] requestId=${
        getRequestId(
          req
        ) ||
        "none"
      }`,

      error.stack ||
        error.message ||
        error
    );

    if (
      error?.code ===
      "BOOKING_LOCK_TIMEOUT"
    ) {
      return sendApiError(
        res,
        409,
        "This room is currently being updated by another operation. Please try again in a moment.",
        "BOOKING_LOCK_TIMEOUT",
        getRequestId(
          req
        )
      );
    }

    if (
      error?.name ===
      "ValidationError"
    ) {
      return sendApiError(
        res,
        400,
        Object.values(
          error.errors ||
            {}
        )
          .map(
            (
              entry
            ) =>
              entry.message
          )
          .filter(
            Boolean
          )
          .join(" ") ||
          "Some room information is invalid.",

        "VALIDATION_ERROR",

        getRequestId(
          req
        )
      );
    }

    if (
      error?.code ===
      11000
    ) {
      return sendApiError(
        res,
        409,
        "A room with the same name or slug already exists.",
        "ROOM_ALREADY_EXISTS",
        getRequestId(
          req
        )
      );
    }

    return sendApiError(
      res,
      500,
      "Unable to update room.",
      "ROOM_UPDATE_FAILED",
      getRequestId(
        req
      )
    );
  }
}

router.post(
  "/rooms/update/:id",
  requireAdminMutation,
  updateRoomHandler
);

router.post(
  "/rooms/update",
  requireAdminMutation,
  updateRoomHandler
);

/* ============================================================
   ROOM IMAGE UPLOAD
============================================================ */

router.post(
  "/rooms/:id/image",
  requireAdminMutation,

  (
    req,
    res,
    next
  ) => {
    parseRoomImageBody(
      req,
      res,
      (
        error
      ) => {
        if (
          !error
        ) {
          return next();
        }

        if (
          error?.type ===
            "entity.too.large" ||
          error?.status ===
            413
        ) {
          return sendApiError(
            res,
            413,
            "The selected image is larger than 8 MB.",
            "IMAGE_TOO_LARGE",
            getRequestId(
              req
            )
          );
        }

        return sendApiError(
          res,
          400,
          "Unable to read the uploaded image.",
          "IMAGE_BODY_INVALID",
          getRequestId(
            req
          )
        );
      }
    );
  },

  async (
    req,
    res
  ) => {
    let savedFile =
      null;

    try {
      const roomId =
        getResourceIdFromRequest(
          req
        );

      if (
        !isValidObjectId(
          roomId
        )
      ) {
        return sendApiError(
          res,
          400,
          "Invalid room ID.",
          "INVALID_ROOM_ID",
          getRequestId(
            req
          )
        );
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (
        !room
      ) {
        return sendApiError(
          res,
          404,
          "Room not found.",
          "ROOM_NOT_FOUND",
          getRequestId(
            req
          )
        );
      }

      const contentType =
        String(
          req.headers[
            "content-type"
          ] ||
            ""
        )
          .split(
            ";",
            1
          )[0]
          .trim()
          .toLowerCase();

      if (
        !ROOM_IMAGE_CONTENT_TYPES.includes(
          contentType
        )
      ) {
        return sendApiError(
          res,
          415,
          "Unsupported image type. Please upload a JPG, PNG, or WEBP image.",
          "UNSUPPORTED_IMAGE_TYPE",
          getRequestId(
            req
          )
        );
      }

      const buffer =
        req.body;

      if (
        !Buffer.isBuffer(
          buffer
        ) ||
        buffer.length ===
          0
      ) {
        return sendApiError(
          res,
          400,
          "No image file was received.",
          "IMAGE_MISSING",
          getRequestId(
            req
          )
        );
      }

      if (
        buffer.length >
        ROOM_IMAGE_MAX_BYTES
      ) {
        return sendApiError(
          res,
          413,
          "The selected image is larger than 8 MB.",
          "IMAGE_TOO_LARGE",
          getRequestId(
            req
          )
        );
      }

      const imageType =
        detectRoomImageType(
          buffer
        );

      if (
        !imageType
      ) {
        return sendApiError(
          res,
          400,
          "The uploaded file is not a supported JPG, PNG, or WEBP image.",
          "INVALID_IMAGE_FILE",
          getRequestId(
            req
          )
        );
      }

      if (
        imageType.contentType !==
        contentType
      ) {
        return sendApiError(
          res,
          400,
          "The uploaded image type does not match its actual file contents.",
          "IMAGE_TYPE_MISMATCH",
          getRequestId(
            req
          )
        );
      }

      const previousImage =
        pickFirst(
          room,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ],
          ""
        );

      savedFile =
        await saveRoomImageBuffer(
          buffer,
          imageType
        );

      const imageFieldWasSet =
        setModelValue(
          room,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ],
          savedFile.url
        );

      if (
        !imageFieldWasSet
      ) {
        await removeManagedRoomImage(
          savedFile.url
        );

        savedFile =
          null;

        return sendApiError(
          res,
          500,
          "This room model does not have a supported image field.",
          "ROOM_IMAGE_FIELD_MISSING",
          getRequestId(
            req
          )
        );
      }

      const finalImageUrl =
        savedFile.url;

      await room.save();

      savedFile =
        null;

      if (
        previousImage &&
        previousImage !==
          finalImageUrl
      ) {
        await removeManagedRoomImage(
          previousImage
        );
      }

      logAdminAction(
        req,
        "room-image-update",
        {
          roomId,

          imageUrl:
            finalImageUrl,
        }
      );

      return res.json({
        success:
          true,

        message:
          "Room image uploaded successfully.",

        room: {
          id:
            room._id,

          image:
            finalImageUrl,
        },
      });
    } catch (
      error
    ) {
      if (
        savedFile?.url
      ) {
        await removeManagedRoomImage(
          savedFile.url
        );
      }

      console.error(
        `[ROOM IMAGE UPLOAD ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Unable to upload the room image.",
        "ROOM_IMAGE_UPLOAD_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   DELETE / DEACTIVATE ROOM
============================================================ */

router.post(
  "/rooms/delete/:id",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    const roomId =
      getResourceIdFromRequest(
        req
      );

    if (
      !isValidObjectId(
        roomId
      )
    ) {
      return sendApiError(
        res,
        400,
        "Invalid room ID.",
        "INVALID_ROOM_ID",
        getRequestId(
          req
        )
      );
    }

    try {
      return await withRoomLock(
        {
          _id:
            roomId,
        },
        async () => {
          const room =
            await getRoomDocumentById(
              roomId
            );

          if (
            !room
          ) {
            return sendApiError(
              res,
              404,
              "Room not found.",
              "ROOM_NOT_FOUND",
              getRequestId(
                req
              )
            );
          }

          /*
           * Authoritative relationship: roomId.
           *
           * Legacy room-name fields are retained for old bookings
           * that were created before roomId was introduced.
           */
          const roomNames =
            [
              room.name,
              room.displayName,
              room.key,
            ]
              .map(
                (
                  value
                ) =>
                  normalizeString(
                    value,
                    150
                  )
              )
              .filter(
                Boolean
              );

          const conditions =
            [
              {
                roomId:
                  room._id,
              },
            ];

          if (
            roomNames.length
          ) {
            conditions.push(
              {
                room: {
                  $in:
                    roomNames,
                },
              },
              {
                roomType: {
                  $in:
                    roomNames,
                },
              },
              {
                accommodation: {
                  $in:
                    roomNames,
                },
              },
              {
                roomName: {
                  $in:
                    roomNames,
                },
              }
            );
          }

          const activeBooking =
            await Appointment.exists(
              {
                $and: [
                  {
                    $or:
                      conditions,
                  },

                  {
                    status: {
                      $in:
                        BLOCKING_STATUSES,
                    },
                  },

                  {
                    checkout: {
                      $gte:
                        new Date(),
                    },
                  },
                ],
              }
            );

          if (
            activeBooking
          ) {
            return sendApiError(
              res,
              409,
              "This room has an active or future booking and cannot be removed.",
              "ROOM_HAS_ACTIVE_BOOKINGS",
              getRequestId(
                req
              )
            );
          }

          if (
            modelHasPath(
              Room,
              "active"
            )
          ) {
            room.active =
              false;

            await room.save();
          } else if (
            modelHasPath(
              Room,
              "isActive"
            )
          ) {
            room.isActive =
              false;

            await room.save();
          } else {
            await room.deleteOne();
          }

          logAdminAction(
            req,
            "room-deactivate",
            {
              roomId,
            }
          );

          return res.json({
            success:
              true,

            message:
              "Room removed from active inventory.",
          });
        },
        BOOKING_LOCK_OPTIONS
      );
    } catch (
      error
    ) {
      console.error(
        "Delete Room Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to remove room.",
        "ROOM_DELETE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   ADD-ONS PAGE
============================================================ */

router.get(
  "/add-ons",
  requireAdmin,
  async (
    req,
    res
  ) => {
    try {
      const [
        rawAddOns,
        rooms,
      ] =
        await Promise.all(
          [
            AddOn.find()
              .sort({
                sortOrder:
                  1,

                name:
                  1,

                createdAt:
                  1,
              })
              .lean(),

            Room.find()
              .sort({
                sortOrder:
                  1,

                name:
                  1,
              })
              .lean(),
          ]
        );

      const addOns =
        rawAddOns
          .map(
            normalizeAddOnRecord
          )
          .filter(
            Boolean
          );

      return res.render(
        "admin/add-ons",
        {
          title:
            "Manage Add-ons",

          admin:
            getAdminSession(
              req
            ),

          addOns,

          rooms,
        }
      );
    } catch (
      error
    ) {
      console.error(
        "Add-ons Page Error:",
        error
      );

      return renderAdminError(
        res,
        500,
        "Add-ons Error",
        "Unable to load add-on management."
      );
    }
  }
);

/* ============================================================
   CREATE ADD-ON
============================================================ */

router.post(
  "/add-ons/create",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const payload =
        buildAddOnCreatePayload(
          req.body
        );

      if (
        !payload.name
      ) {
        return sendApiError(
          res,
          400,
          "Add-on name is required.",
          "INVALID_ADDON",
          getRequestId(
            req
          )
        );
      }

      const addOn =
        new AddOn();

      Object.entries(
        payload
      ).forEach(
        (
          [key, value]
        ) => {
          if (
            addOn.schema.path(
              key
            )
          ) {
            addOn.set(
              key,
              value
            );
          }
        }
      );

      await addOn.save();

      logAdminAction(
        req,
        "addon-create",
        {
          addOnId:
            addOn._id,
        }
      );

      return res
        .status(
          201
        )
        .json({
          success:
            true,

          message:
            "Add-on created successfully.",

          addOn,
        });
    } catch (
      error
    ) {
      console.error(
        `[CREATE ADD-ON ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      if (
        error?.name ===
        "ValidationError"
      ) {
        return sendApiError(
          res,
          400,
          Object.values(
            error.errors ||
              {}
          )
            .map(
              (
                entry
              ) =>
                entry.message
            )
            .filter(
              Boolean
            )
            .join(" ") ||
            "Some add-on information is invalid.",

          "VALIDATION_ERROR",

          getRequestId(
            req
          )
        );
      }

      if (
        error?.code ===
        11000
      ) {
        return sendApiError(
          res,
          409,
          "An add-on with the same name or slug already exists.",
          "ADDON_ALREADY_EXISTS",
          getRequestId(
            req
          )
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to create add-on.",
        "ADDON_CREATE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   UPDATE ADD-ON
============================================================ */

async function updateAddOnHandler(
  req,
  res
) {
  try {
    const addOnId =
      getResourceIdFromRequest(
        req
      );

    if (
      !isValidObjectId(
        addOnId
      )
    ) {
      return sendApiError(
        res,
        400,
        "Invalid add-on ID.",
        "INVALID_ADDON_ID",
        getRequestId(
          req
        )
      );
    }

    const addOn =
      await AddOn.findById(
        addOnId
      );

    if (
      !addOn
    ) {
      return sendApiError(
        res,
        404,
        "Add-on not found.",
        "ADDON_NOT_FOUND",
        getRequestId(
          req
        )
      );
    }

    const payload =
      buildAddOnUpdatePayload(
        req.body
      );

    if (
      Object.keys(
        payload
      ).length ===
      0
    ) {
      return sendApiError(
        res,
        400,
        "No add-on changes were provided.",
        "NO_CHANGES",
        getRequestId(
          req
        )
      );
    }

    Object.entries(
      payload
    ).forEach(
      (
        [key, value]
      ) => {
        if (
          addOn.schema.path(
            key
          )
        ) {
          addOn.set(
            key,
            value
          );
        }
      }
    );

    await addOn.save();

    logAdminAction(
      req,
      "addon-update",
      {
        addOnId,
      }
    );

    return res.json({
      success:
        true,

      message:
        "Add-on updated successfully.",

      addOn,
    });
  } catch (
    error
  ) {
    console.error(
      `[UPDATE ADD-ON ERROR] requestId=${
        getRequestId(
          req
        ) ||
        "none"
      }`,

      error.stack ||
        error.message ||
        error
    );

    if (
      error?.name ===
      "ValidationError"
    ) {
      return sendApiError(
        res,
        400,
        Object.values(
          error.errors ||
            {}
        )
          .map(
            (
              entry
            ) =>
              entry.message
          )
          .filter(
            Boolean
          )
          .join(" ") ||
          "Some add-on information is invalid.",

        "VALIDATION_ERROR",

        getRequestId(
          req
        )
      );
    }

    if (
      error?.code ===
      11000
    ) {
      return sendApiError(
        res,
        409,
        "An add-on with the same name or slug already exists.",
        "ADDON_ALREADY_EXISTS",
        getRequestId(
          req
        )
      );
    }

    return sendApiError(
      res,
      500,
      "Unable to update add-on.",
      "ADDON_UPDATE_FAILED",
      getRequestId(
        req
      )
    );
  }
}

router.post(
  "/add-ons/update/:id",
  requireAdminMutation,
  updateAddOnHandler
);

router.post(
  "/add-ons/update",
  requireAdminMutation,
  updateAddOnHandler
);

/* ============================================================
   ADD-ON IMAGE UPLOAD
============================================================ */

router.post(
  "/add-ons/:id/image",
  requireAdminMutation,

  (
    req,
    res,
    next
  ) => {
    parseAddOnImageBody(
      req,
      res,
      (
        error
      ) => {
        if (
          !error
        ) {
          return next();
        }

        if (
          error?.type ===
            "entity.too.large" ||
          error?.status ===
            413
        ) {
          return sendApiError(
            res,
            413,
            "The selected image is larger than 8 MB.",
            "IMAGE_TOO_LARGE",
            getRequestId(
              req
            )
          );
        }

        return sendApiError(
          res,
          400,
          "Unable to read the uploaded add-on image.",
          "IMAGE_BODY_INVALID",
          getRequestId(
            req
          )
        );
      }
    );
  },

  async (
    req,
    res
  ) => {
    let savedFile =
      null;

    try {
      const addOnId =
        getResourceIdFromRequest(
          req
        );

      if (
        !isValidObjectId(
          addOnId
        )
      ) {
        return sendApiError(
          res,
          400,
          "Invalid add-on ID.",
          "INVALID_ADDON_ID",
          getRequestId(
            req
          )
        );
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (
        !addOn
      ) {
        return sendApiError(
          res,
          404,
          "Add-on not found.",
          "ADDON_NOT_FOUND",
          getRequestId(
            req
          )
        );
      }

      const contentType =
        String(
          req.headers[
            "content-type"
          ] ||
            ""
        )
          .split(
            ";",
            1
          )[0]
          .trim()
          .toLowerCase();

      if (
        !ADDON_IMAGE_CONTENT_TYPES.includes(
          contentType
        )
      ) {
        return sendApiError(
          res,
          415,
          "Unsupported image type. Please upload a JPG, PNG, or WEBP image.",
          "UNSUPPORTED_IMAGE_TYPE",
          getRequestId(
            req
          )
        );
      }

      const buffer =
        req.body;

      if (
        !Buffer.isBuffer(
          buffer
        ) ||
        buffer.length ===
          0
      ) {
        return sendApiError(
          res,
          400,
          "No image file was received.",
          "IMAGE_MISSING",
          getRequestId(
            req
          )
        );
      }

      const imageType =
        detectAddOnImageType(
          buffer
        );

      if (
        !imageType
      ) {
        return sendApiError(
          res,
          400,
          "The uploaded file is not a supported JPG, PNG, or WEBP image.",
          "INVALID_IMAGE_FILE",
          getRequestId(
            req
          )
        );
      }

      if (
        imageType.contentType !==
        contentType
      ) {
        return sendApiError(
          res,
          400,
          "The uploaded image type does not match its actual file contents.",
          "IMAGE_TYPE_MISMATCH",
          getRequestId(
            req
          )
        );
      }

      const previousImage =
        pickFirst(
          addOn,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ],
          ""
        );

      savedFile =
        await saveAddOnImageBuffer(
          buffer,
          imageType
        );

      const imageFieldWasSet =
        setModelValue(
          addOn,
          [
            "image",
            "imageUrl",
            "photo",
            "photoUrl",
          ],
          savedFile.url
        );

      if (
        !imageFieldWasSet
      ) {
        await removeManagedAddOnImage(
          savedFile.url
        );

        savedFile =
          null;

        return sendApiError(
          res,
          500,
          "This add-on model does not have a supported image field.",
          "ADDON_IMAGE_FIELD_MISSING",
          getRequestId(
            req
          )
        );
      }

      const finalImageUrl =
        savedFile.url;

      await addOn.save();

      savedFile =
        null;

      if (
        previousImage &&
        previousImage !==
          finalImageUrl
      ) {
        await removeManagedAddOnImage(
          previousImage
        );
      }

      logAdminAction(
        req,
        "addon-image-update",
        {
          addOnId,

          imageUrl:
            finalImageUrl,
        }
      );

      return res.json({
        success:
          true,

        message:
          "Add-on image uploaded successfully.",

        addOn: {
          id:
            addOn._id,

          image:
            finalImageUrl,
        },
      });
    } catch (
      error
    ) {
      if (
        savedFile?.url
      ) {
        await removeManagedAddOnImage(
          savedFile.url
        );
      }

      console.error(
        `[ADD-ON IMAGE UPLOAD ERROR] requestId=${
          getRequestId(
            req
          ) ||
          "none"
        }`,

        error.stack ||
          error.message ||
          error
      );

      return sendApiError(
        res,
        500,
        "Unable to upload the add-on image.",
        "ADDON_IMAGE_UPLOAD_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   DELETE / DEACTIVATE ADD-ON
============================================================ */

router.post(
  "/add-ons/delete/:id",
  requireAdminMutation,
  async (
    req,
    res
  ) => {
    try {
      const addOnId =
        getResourceIdFromRequest(
          req
        );

      if (
        !isValidObjectId(
          addOnId
        )
      ) {
        return sendApiError(
          res,
          400,
          "Invalid add-on ID.",
          "INVALID_ADDON_ID",
          getRequestId(
            req
          )
        );
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (
        !addOn
      ) {
        return sendApiError(
          res,
          404,
          "Add-on not found.",
          "ADDON_NOT_FOUND",
          getRequestId(
            req
          )
        );
      }

      /*
       * Deactivation preserves historical appointment snapshots.
       */
      if (
        modelHasPath(
          AddOn,
          "active"
        )
      ) {
        addOn.active =
          false;

        await addOn.save();
      } else if (
        modelHasPath(
          AddOn,
          "isActive"
        )
      ) {
        addOn.isActive =
          false;

        await addOn.save();
      } else {
        await addOn.deleteOne();
      }

      logAdminAction(
        req,
        "addon-deactivate",
        {
          addOnId,
        }
      );

      return res.json({
        success:
          true,

        message:
          "Add-on removed from active inventory.",
      });
    } catch (
      error
    ) {
      console.error(
        "Delete Add-on Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to remove add-on.",
        "ADDON_DELETE_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   ADMIN ROOM DATA API
============================================================ */

router.get(
  "/api/rooms",
  requireAdminApi,
  async (
    req,
    res
  ) => {
    try {
      const rooms =
        await getConfiguredRooms();

      const cottage =
        await getConfiguredCottage();

      return res.json({
        success:
          true,

        rooms,

        cottage,
      });
    } catch (
      error
    ) {
      console.error(
        "Admin Room API Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to load room information.",
        "ROOM_API_FAILED",
        getRequestId(
          req
        )
      );
    }
  }
);

/* ============================================================
   ADMIN LOGOUT
============================================================ */

async function logoutAdminHandler(
  req,
  res
) {
  try {
    logAdminAction(
      req,
      "logout"
    );

    await new Promise(
      (
        resolve,
        reject
      ) => {
        if (
          !req.session
        ) {
          return resolve();
        }

        req.session.destroy(
          (
            error
          ) => {
            if (
              error
            ) {
              return reject(
                error
              );
            }

            resolve();
          }
        );
      }
    );

    /*
     * IMPORTANT:
     *
     * server.js uses:
     *
     *   islerms.sid
     *   islerms.admin.sid
     *
     * The admin logout MUST clear the admin cookie.
     */
    const cookieOptions =
      {
        httpOnly:
          true,

        sameSite:
          "lax",

        secure:
          process.env.NODE_ENV ===
          "production",

        path:
          "/admin",
      };

    res.clearCookie(
      "islerms.admin.sid",
      cookieOptions
    );

    /*
     * Compatibility cleanup in case an older deployment used
     * the root path for the admin cookie.
     */
    res.clearCookie(
      "islerms.admin.sid",
      {
        ...cookieOptions,

        path:
          "/",
      }
    );

    return res.redirect(
      "/admin/login"
    );
  } catch (
    error
  ) {
    console.error(
      `[ADMIN LOGOUT ERROR] requestId=${
        getRequestId(
          req
        ) ||
        "none"
      }`,

      error.stack ||
        error.message ||
        error
    );

    /*
     * Still attempt to remove the canonical admin cookie.
     */
    res.clearCookie(
      "islerms.admin.sid",
      {
        httpOnly:
          true,

        sameSite:
          "lax",

        secure:
          process.env.NODE_ENV ===
          "production",

        path:
          "/admin",
      }
    );

    return res.redirect(
      "/admin/login"
    );
  }
}

router.post(
  "/logout",
  requireAdminMutation,
  logoutAdminHandler
);

/*
 * GET remains for old links/bookmarks.
 *
 * POST is the canonical mutation.
 */
router.get(
  "/logout",
  logoutAdminHandler
);

/* ============================================================
   ADMIN API 404
============================================================ */

router.use(
  (
    req,
    res,
    next
  ) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return sendApiError(
        res,
        404,
        "Admin API route not found.",
        "ROUTE_NOT_FOUND",
        getRequestId(
          req
        )
      );
    }

    next();
  }
);

/* ============================================================
   EXPORT
============================================================ */

module.exports =
  router;