"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * routes/adminRoutes.js
 *
 * Responsibility:
 * - Administrator authentication
 * - Dashboard / analytics
 * - Booking management
 * - Front Desk check-in / check-out
 * - User management
 * - Room management
 * - Add-on management
 * - Admin APIs
 * - Booking notifications
 * - Production hardening and staged admin mutation security hooks
 *
 * This router is mounted by server.js at:
 *   /admin
 *
 * Therefore route definitions here intentionally use paths such as:
 *   /login
 *   /dashboard
 *   /checkin-manager
 *   /update-checkin
 *
 * and NOT /admin/login, /admin/dashboard, etc.
 * ============================================================
 */

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Admin = require("../models/Admin");
const Notification = require("../models/Notification");
const Room = require("../models/Room");
const AddOn = require("../models/AddOn");

const csrf = require("../middleware/csrf");

const verifyCsrfToken =
  csrf.verifyCsrfToken || csrf.verifyCsrf;

const router = express.Router();

if (typeof verifyCsrfToken !== "function") {
  throw new Error(
    "CSRF middleware is missing a compatible verification function."
  );
}

/* Prevent sensitive admin pages from being cached. */
router.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  next();
});

// ============================================================
// CONSTANTS
// ============================================================

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
 * Admin mutation CSRF is intentionally staged.
 *
 * Set ADMIN_CSRF_REQUIRED=true after the admin views/forms send
 * the session CSRF token as `_csrf` or `X-CSRF-Token`.
 *
 * Keeping this false by default prevents the current legacy admin
 * forms from being broken before those templates are updated.
 */
const ADMIN_CSRF_REQUIRED =
  String(
    process.env.ADMIN_CSRF_REQUIRED || "false"
  )
    .trim()
    .toLowerCase() === "true";

/*
 * Room image upload configuration.
 *
 * The upgraded rooms.ejs sends the selected image as the raw request body.
 * Express's built-in raw parser handles that request without adding a
 * multipart upload dependency.
 */
const ROOM_IMAGE_MAX_BYTES =
  8 * 1024 * 1024;

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
    { recursive: true }
  );
} catch (error) {
  console.error(
    "Room image upload directory initialization failed:",
    error.stack || error.message || error
  );
}

const parseRoomImageBody =
  express.raw({
    type: ROOM_IMAGE_CONTENT_TYPES,
    limit: ROOM_IMAGE_MAX_BYTES,
  });

/*
 * Add-on image upload configuration.
 *
 * The upgraded add-ons.ejs sends the selected image as the raw request body.
 */
const ADDON_IMAGE_MAX_BYTES =
  8 * 1024 * 1024;

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
    error.stack || error.message || error
  );
}

const parseAddOnImageBody =
  express.raw({
    type: ADDON_IMAGE_CONTENT_TYPES,
    limit: ADDON_IMAGE_MAX_BYTES,
  });

const LEGACY_ROOMS = [
  {
    key: "Aircon Room",
    name: "Aircon Room",
    displayName: "Aircon Room",
    price: 3500,
    maxGuests: 8,
    image: "/images/room1.jpg",
    type: "room",
    active: true,
  },

  {
    key: "Fan Room",
    name: "Fan Room",
    displayName: "Fan Room",
    price: 2500,
    maxGuests: 6,
    image: "/images/room2.jpg",
    type: "room",
    active: true,
  },
];

const LEGACY_COTTAGE = {
  key: "Seaside Cottage",
  name: "Seaside Cottage",
  displayName: "Seaside Cottage",
  price: 1200,
  maxGuests: 6,
  image: "/images/cottage.jpg",
  type: "cottage",
  active: true,
};

// ============================================================
// ROOM IMAGE HELPERS
// ============================================================

function detectRoomImageType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return null;
  }

  /* JPEG */
  if (
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return {
      extension: "jpg",
      contentType: "image/jpeg",
    };
  }

  /* PNG */
  const pngSignature = Buffer.from([
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
    buffer.length >= pngSignature.length &&
    buffer
      .subarray(0, pngSignature.length)
      .equals(pngSignature)
  ) {
    return {
      extension: "png",
      contentType: "image/png",
    };
  }

  /* WEBP: RIFF....WEBP */
  if (
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return {
      extension: "webp",
      contentType: "image/webp",
    };
  }

  return null;
}

function isManagedRoomImageUrl(value) {
  const normalized =
    normalizeString(value, 500);

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
    filename.includes("/") ||
    filename.includes("\\")
  ) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}

function roomImageAbsolutePathFromUrl(value) {
  if (!isManagedRoomImageUrl(value)) {
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
    absolutePath !== uploadRoot &&
    !absolutePath.startsWith(
      `${uploadRoot}${path.sep}`
    )
  ) {
    return null;
  }

  return absolutePath;
}

async function removeManagedRoomImage(value) {
  const filePath =
    roomImageAbsolutePathFromUrl(value);

  if (!filePath) {
    return;
  }

  try {
    await fs.promises.unlink(
      filePath
    );
  } catch (error) {
    if (error?.code !== "ENOENT") {
      console.warn(
        "Unable to remove previous room image:",
        error.message || error
      );
    }
  }
}

function createRoomImageFilename(extension) {
  return `room-${Date.now()}-${crypto
    .randomBytes(16)
    .toString("hex")}.${extension}`;
}

async function saveRoomImageBuffer(
  buffer,
  imageType
) {
  await fs.promises.mkdir(
    ROOM_IMAGE_UPLOAD_DIR,
    {
      recursive: true,
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
      .toString("hex")}.tmp`;

  await fs.promises.writeFile(
    tempPath,
    buffer,
    {
      flag: "wx",
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
    } catch (_) {
      /* Best-effort temporary-file cleanup. */
    }

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

// ============================================================
// ADD-ON IMAGE HELPERS
// ============================================================

function detectAddOnImageType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    return null;
  }

  /* JPEG */
  if (
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return {
      extension: "jpg",
      contentType: "image/jpeg",
    };
  }

  /* PNG */
  const pngSignature = Buffer.from([
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
    buffer.length >= pngSignature.length &&
    buffer
      .subarray(0, pngSignature.length)
      .equals(pngSignature)
  ) {
    return {
      extension: "png",
      contentType: "image/png",
    };
  }

  /* WEBP: RIFF....WEBP */
  if (
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return {
      extension: "webp",
      contentType: "image/webp",
    };
  }

  return null;
}

function isManagedAddOnImageUrl(value) {
  const normalized =
    normalizeString(value, 500);

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
    filename.includes("/") ||
    filename.includes("\\")
  ) {
    return false;
  }

  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}

function addOnImageAbsolutePathFromUrl(value) {
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
    absolutePath !== uploadRoot &&
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
        error.message || error
      );
    }
  }
}

function createAddOnImageFilename(
  extension
) {
  return `addon-${Date.now()}-${crypto
    .randomBytes(16)
    .toString("hex")}.${extension}`;
}

async function saveAddOnImageBuffer(
  buffer,
  imageType
) {
  await fs.promises.mkdir(
    ADDON_IMAGE_UPLOAD_DIR,
    {
      recursive: true,
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
      .toString("hex")}.tmp`;

  await fs.promises.writeFile(
    tempPath,
    buffer,
    {
      flag: "wx",
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
    } catch (_) {
      /* Best-effort temporary-file cleanup. */
    }

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

// ============================================================
// BASIC HELPERS
// ============================================================

function normalizeString(
  value,
  maxLength = 500
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

function normalizeUsername(value) {
  return normalizeString(
    value,
    120
  ).toLowerCase();
}

function normalizeEmail(value) {
  return normalizeString(
    value,
    320
  ).toLowerCase();
}

function isValidObjectId(id) {
  return (
    Boolean(id) &&
    mongoose.Types.ObjectId.isValid(id)
  );
}

function parseNumber(
  value,
  fallback = 0
) {
  const parsed =
    Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;
}

function parseInteger(
  value,
  fallback = 0
) {
  const parsed =
    Number(value);

  return Number.isInteger(parsed)
    ? parsed
    : fallback;
}

function asBoolean(value) {
  return (
    value === true ||
    value === "true" ||
    value === "1" ||
    value === "on" ||
    value === "yes"
  );
}

function startOfToday() {
  const now = new Date();

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
    start.getDate() + 1
  );
}

function parseBookingDate(value) {
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
    ] = stringValue
      .split("-")
      .map(Number);

    const date =
      new Date(
        year,
        month - 1,
        day
      );

    if (
      date.getFullYear() !== year ||
      date.getMonth() !==
        month - 1 ||
      date.getDate() !== day
    ) {
      return null;
    }

    return date;
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return null;
  }

  return date;
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

  if (!start || !end) {
    return {
      valid: false,
      message:
        "Invalid booking dates.",
    };
  }

  if (end <= start) {
    return {
      valid: false,
      message:
        "Check-out must be after check-in.",
    };
  }

  return {
    valid: true,
    start,
    end,
  };
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
    (endUtc - startUtc) /
      86400000
  );
}

function pickFirst(
  record,
  fields,
  fallback = undefined
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
      record[field] !== ""
    ) {
      return record[field];
    }
  }

  return fallback;
}

function modelHasPath(
  model,
  path
) {
  return Boolean(
    model &&
    model.schema &&
    typeof model.schema.path ===
      "function" &&
    model.schema.path(path)
  );
}

function setModelValue(
  document,
  fieldNames,
  value
) {
  if (
    !document ||
    !Array.isArray(fieldNames)
  ) {
    return false;
  }

  for (
    const field of
      fieldNames
  ) {
    if (
      document.schema &&
      document.schema.path(field)
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

function wantsJson(req) {
  const requested =
    String(
      req.headers?.accept ||
        ""
    ).toLowerCase();

  return (
    req.xhr ||
    requested.includes(
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

function getAdminSession(req) {
  return (
    req.session?.admin ||
    null
  );
}

function getRequestId(req) {
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
  code = "REQUEST_FAILED",
  requestId = null
) {
  return res
    .status(statusCode)
    .json({
      success: false,
      code,
      message,
      ...(requestId
        ? { requestId }
        : {}),
    });
}

function getAdminId(req) {
  const id =
    req.session?.admin?.id ||
    req.session?.admin?._id;

  return isValidObjectId(id)
    ? String(id)
    : null;
}

/**
 * Front Desk checkin.ejs sends `bookingId`.
 *
 * We support:
 *   bookingId
 *   appointmentId
 *   id
 */
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
        error: message,
        message,
      }
    );
}

function redirectWithMessage(
  res,
  path,
  key,
  value
) {
  const separator =
    path.includes("?")
      ? "&"
      : "?";

  return res.redirect(
    `${path}${separator}${key}=${encodeURIComponent(
      value
    )}`
  );
}

// ============================================================
// SESSION / AUTH MIDDLEWARE
// ============================================================

function requireAdmin(
  req,
  res,
  next
) {
  const sessionAdmin =
    req.session?.admin;

  const adminId =
    sessionAdmin?.id ||
    sessionAdmin?._id;

  if (
    !sessionAdmin ||
    !isValidObjectId(
      adminId
    )
  ) {
    if (wantsJson(req)) {
      return sendApiError(
        res,
        401,
        "Administrator authentication required.",
        "AUTHENTICATION_REQUIRED",
        getRequestId(req)
      );
    }

    return res.redirect(
      "/admin/login?error=" +
        encodeURIComponent(
          "Administrator login required."
        )
    );
  }

  next();
}

function requireAdminApi(
  req,
  res,
  next
) {
  const sessionAdmin =
    req.session?.admin;

  const adminId =
    sessionAdmin?.id ||
    sessionAdmin?._id;

  if (
    !sessionAdmin ||
    !isValidObjectId(
      adminId
    )
  ) {
    return sendApiError(
      res,
      401,
      "Administrator authentication required.",
      "AUTHENTICATION_REQUIRED",
      getRequestId(req)
    );
  }

  next();
}

function verifyAdminMutationCsrf(
  req,
  res,
  next
) {
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
      if (!req.session) {
        return reject(
          new Error(
            "Session middleware is unavailable."
          )
        );
      }

      req.session.regenerate(
        (error) => {
          if (error) {
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

function saveSession(req) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
      if (!req.session) {
        return reject(
          new Error(
            "Session middleware is unavailable."
          )
        );
      }

      req.session.save(
        (error) => {
          if (error) {
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

// ============================================================
// NOTIFICATIONS
// ============================================================

async function notifyUser(
  userId,
  event,
  title,
  message,
  bookingId = null
) {
  if (
    !isValidObjectId(
      userId
    )
  ) {
    return null;
  }

  try {
    if (!Notification) {
      return null;
    }

    /*
     * Prefer the current Notification model's purpose-built helper.
     */
    if (
      typeof
        Notification
          .createAppointmentNotification ===
        "function"
    ) {
      return await Notification
        .createAppointmentNotification({
          userId,

          appointmentId:
            isValidObjectId(
              bookingId
            )
              ? bookingId
              : null,

          event,

          title,

          message,

          priority:
            event === "declined" ||
            event === "rejected"
              ? "high"
              : "normal",

          actionLabel:
            isValidObjectId(
              bookingId
            )
              ? "View Reservation"
              : undefined,

          actionUrl:
            isValidObjectId(
              bookingId
            )
              ? `/profile?booking=${encodeURIComponent(
                  String(
                    bookingId
                  )
                )}`
              : undefined,
        });
    }

    const payload = {};

    if (
      modelHasPath(
        Notification,
        "userId"
      )
    ) {
      payload.userId =
        userId;
    } else if (
      modelHasPath(
        Notification,
        "recipient"
      )
    ) {
      payload.recipient =
        userId;
    } else if (
      modelHasPath(
        Notification,
        "recipientId"
      )
    ) {
      payload.recipientId =
        userId;
    }

    if (
      modelHasPath(
        Notification,
        "type"
      )
    ) {
      payload.type =
        modelHasPath(
          Notification,
          "event"
        )
          ? "appointment"
          : event;
    }

    if (
      modelHasPath(
        Notification,
        "event"
      )
    ) {
      payload.event =
        event;
    }

    if (
      modelHasPath(
        Notification,
        "title"
      )
    ) {
      payload.title =
        title;
    }

    if (
      modelHasPath(
        Notification,
        "message"
      )
    ) {
      payload.message =
        message;
    } else if (
      modelHasPath(
        Notification,
        "text"
      )
    ) {
      payload.text =
        message;
    }

    if (
      isValidObjectId(
        bookingId
      )
    ) {
      if (
        modelHasPath(
          Notification,
          "bookingId"
        )
      ) {
        payload.bookingId =
          bookingId;
      }

      if (
        modelHasPath(
          Notification,
          "appointmentId"
        )
      ) {
        payload.appointmentId =
          bookingId;
      }
    }

    if (
      modelHasPath(
        Notification,
        "read"
      )
    ) {
      payload.read =
        false;
    } else if (
      modelHasPath(
        Notification,
        "isRead"
      )
    ) {
      payload.isRead =
        false;
    }

    return await Notification.create(
      payload
    );
  } catch (error) {
    console.error(
      "Notification Error:",
      error.stack ||
        error.message ||
        error
    );

    return null;
  }
}

// ============================================================
// ROOM / CATALOG HELPERS
// ============================================================

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

  if (!name) {
    return null;
  }

  const price =
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
      .includes("cottage");

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

    key: name,

    name,

    displayName: name,

    price,

    maxGuests,

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

    quantity:
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
      activeValue !== false,
  };
}

async function getDynamicRooms() {
  try {
    const records =
      await Room.find({})
        .sort({
          sortOrder: 1,
          name: 1,
          createdAt: 1,
        })
        .lean();

    return records
      .map(
        normalizeRoomRecord
      )
      .filter(Boolean);
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
    dynamicRooms.length > 0
  ) {
    return dynamicRooms.filter(
      (room) =>
        room.active
    );
  }

  return LEGACY_ROOMS.map(
    (room) => ({
      ...room,
    })
  );
}

async function getConfiguredCottage() {
  const dynamicRooms =
    await getDynamicRooms();

  const dynamicCottage =
    dynamicRooms.find(
      (room) =>
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
      (room) =>
        room.name === requested ||
        room.displayName ===
          requested ||
        room.key === requested
    ) || null
  );
}

async function getRoomDocumentById(
  id
) {
  if (!isValidObjectId(id)) {
    return null;
  }

  return Room.findById(id);
}

function hasOwn(
  body,
  ...names
) {
  return names.some(
    (name) =>
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
    const name of names
  ) {
    if (
      hasOwn(body, name)
    ) {
      return body[name];
    }
  }

  return undefined;
}

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

  const payload = {
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
      rawActive === undefined
        ? true
        : asBoolean(
            rawActive
          ),
  };

  payload.displayName =
    payload.name;

  return payload;
}

function buildRoomUpdatePayload(
  body
) {
  const payload = {};

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

    payload.displayName =
      payload.name;
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

// ============================================================
// ADD-ON PAYLOAD / NORMALIZATION HELPERS
// ============================================================

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
  const rawName =
    firstPresent(
      body,
      [
        "name",
        "displayName",
        "title",
      ]
    );

  const rawPrice =
    firstPresent(
      body,
      [
        "price",
        "amount",
        "rate",
      ]
    );

  const rawPricingType =
    firstPresent(
      body,
      [
        "pricingType",
        "priceType",
        "billingType",
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

  const rawDescription =
    firstPresent(
      body,
      [
        "description",
        "details",
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

  const price =
    Math.max(
      0,
      parseNumber(
        rawPrice,
        0
      )
    );

  const sortOrder =
    Math.max(
      0,
      parseInteger(
        rawSortOrder,
        0
      )
    );

  const pricingType =
    normalizeAddOnPricingType(
      rawPricingType
    );

  const image =
    normalizeString(
      rawImage,
      500
    );

  return {
    name:
      normalizeString(
        rawName,
        150
      ),

    displayName:
      normalizeString(
        rawName,
        150
      ),

    price,

    amount:
      price,

    pricingType,

    sortOrder,

    image,

    description:
      normalizeString(
        rawDescription,
        2000
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

function buildAddOnUpdatePayload(
  body
) {
  const payload = {};

  if (
    hasOwn(
      body,
      "name",
      "displayName",
      "title"
    )
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

    payload.name =
      name;

    payload.displayName =
      name;
  }

  if (
    hasOwn(
      body,
      "price",
      "amount",
      "rate"
    )
  ) {
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

    payload.price =
      price;

    payload.amount =
      price;
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

  const rawPricingType =
    pickFirst(
      plain,
      [
        "pricingType",
        "priceType",
        "billingType",
      ],
      "once"
    );

  const rawSortOrder =
    pickFirst(
      plain,
      [
        "sortOrder",
        "displayOrder",
        "order",
      ],
      0
    );

  const rawImage =
    pickFirst(
      plain,
      [
        "image",
        "imageUrl",
        "photo",
        "photoUrl",
      ],
      ""
    );

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
      normalizeString(
        pickFirst(
          plain,
          [
            "displayName",
            "name",
            "title",
          ],
          name
        ),
        150
      ),

    price,

    amount:
      price,

    pricingType:
      normalizeAddOnPricingType(
        rawPricingType
      ),

    sortOrder:
      Math.max(
        0,
        parseInteger(
          rawSortOrder,
          0
        )
      ),

    image:
      normalizeString(
        rawImage,
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
      ) !== false,
  };
}

// ============================================================
// DOUBLE-BOOKING DETECTION
// ============================================================

async function findRoomConflict({
  room,
  checkin,
  checkout,
  excludeId = null,
}) {
  if (
    !room ||
    !checkin ||
    !checkout
  ) {
    return null;
  }

  const query = {
    room,

    status: {
      $in:
        BLOCKING_STATUSES,
    },

    checkin: {
      $lt: checkout,
    },

    checkout: {
      $gt: checkin,
    },
  };

  if (
    excludeId &&
    isValidObjectId(
      excludeId
    )
  ) {
    query._id = {
      $ne: excludeId,
    };
  }

  return Appointment.findOne(
    query
  )
    .sort({
      checkin: 1,
    })
    .lean();
}

// ============================================================
// BOOKING STATUS HELPERS
// ============================================================

function canTransitionStatus(
  from,
  to
) {
  if (
    !ALL_STATUSES.includes(
      from
    )
  ) {
    return false;
  }

  if (
    !ALL_STATUSES.includes(
      to
    )
  ) {
    return false;
  }

  if (
    from === to
  ) {
    return true;
  }

  return Boolean(
    STATUS_TRANSITIONS[
      from
    ]?.includes(to)
  );
}

function applyStatusTimestamps(
  appointment,
  status
) {
  const now =
    new Date();

  const timestampFields = {
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
    ] || [];

  if (
    fields.length > 0
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
    getAdminSession(req);

  const adminId =
    admin?.id ||
    admin?._id ||
    "unknown";

  const detailText =
    Object.entries(
      details
    )
      .map(
        ([key, value]) =>
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
      getRequestId(req) ||
      "none"
    } ${detailText}`
  );
}

async function updateStatusInternal({
  bookingId,
  status,
  req = null,
}) {
  if (
    !isValidObjectId(
      bookingId
    )
  ) {
    return {
      ok: false,
      statusCode: 400,
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
      ok: false,
      statusCode: 400,
      message:
        "Invalid booking status.",
    };
  }

  const appointment =
    await Appointment.findById(
      bookingId
    );

  if (!appointment) {
    return {
      ok: false,
      statusCode: 404,
      message:
        "Booking not found.",
    };
  }

  const currentStatus =
    appointment.status ||
    "pending";

  if (
    currentStatus ===
    status
  ) {
    return {
      ok: true,
      appointment,
      changed: false,
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
      ok: false,
      statusCode: 400,
      message:
        `Invalid booking status transition: ${currentStatus} → ${status}.`,
    };
  }

  if (
    BLOCKING_STATUSES.includes(
      status
    ) &&
    appointment.room &&
    appointment.checkin &&
    appointment.checkout
  ) {
    const conflict =
      await findRoomConflict({
        room:
          appointment.room,

        checkin:
          appointment.checkin,

        checkout:
          appointment.checkout,

        excludeId:
          appointment._id,
      });

    if (conflict) {
      return {
        ok: false,
        statusCode: 409,
        message:
          "This room is already occupied or reserved for an overlapping booking.",
        conflict,
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

  if (req) {
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
    ok: true,
    appointment,
    changed: true,
    previousStatus,
    message:
      `Booking status updated to ${status}.`,
  };
}

// ============================================================
// ADMIN LOGIN PAGE
// ============================================================

function renderAdminLogin(
  req,
  res,
  {
    statusCode = 200,
    error = null,
    username = "",
  } = {}
) {
  const csrfToken =
    res.locals?.csrfToken ||
    res.locals?._csrf ||
    "";

  return res
    .status(statusCode)
    .render(
      "admin/adminlogin",
      {
        title:
          "Admin Portal",

        error:
          error || null,

        username:
          String(
            username || ""
          )
            .trim()
            .slice(
              0,
              120
            ),

        csrfToken:
          String(
            csrfToken || ""
          ),
      }
    );
}

router.get(
  "/login",
  (req, res) => {
    if (
      req.session?.admin?.id &&
      isValidObjectId(
        req.session.admin.id
      )
    ) {
      return res.redirect(
        "/admin/dashboard"
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

// ============================================================
// ADMIN LOGIN
// ============================================================

router.post(
  "/login",
  verifyAdminMutationCsrf,
  async (req, res) => {
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
            username:
              displayUsername,
            error:
              "Username and password are required.",
          }
        );
      }

      if (
        rawUsername.length >
        120
      ) {
        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 400,
            username:
              displayUsername,
            error:
              "Administrator username is invalid.",
          }
        );
      }

      const submittedUsername =
        normalizeUsername(
          rawUsername
        );

      if (
        !submittedUsername
      ) {
        return renderAdminLogin(
          req,
          res,
          {
            statusCode: 400,
            username:
              displayUsername,
            error:
              "Administrator username is invalid.",
          }
        );
      }

      const admin =
        await Admin.findOne({
          username:
            submittedUsername,
        }).select(
          "+password"
        );

      let validPassword =
        false;

      if (admin) {
        if (
          typeof admin.comparePassword ===
          "function"
        ) {
          validPassword =
            await admin.comparePassword(
              password
            );
        } else if (
          admin.password
        ) {
          validPassword =
            await bcrypt.compare(
              password,
              admin.password
            );
        }
      }

      if (
        admin &&
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
        validPassword =
          false;
      }

      if (
        !admin ||
        !validPassword
      ) {
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
            username:
              displayUsername,
            error:
              "Access denied. Invalid credentials.",
          }
        );
      }

      await regenerateSession(
        req
      );

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
            admin.role ||
              "admin",
            80
          ).toLowerCase(),
      };

      delete req.session.user;

      await saveSession(
        req
      );

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
          getRequestId(req) ||
          "none"
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

          username:
            displayUsername,

          error:
            "We were unable to process the administrator login. Please try again.",
        }
      );
    }
  }
);

// ============================================================
// ADMIN DASHBOARD
// ============================================================

router.get(
  "/dashboard",
  requireAdmin,
  async (req, res) => {
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
        await Promise.all([
          Appointment.countDocuments(),

          Appointment.countDocuments({
            status:
              "pending",
          }),

          Appointment.countDocuments({
            status:
              "accepted",
          }),

          Appointment.countDocuments({
            status:
              "confirmed",
          }),

          Appointment.countDocuments({
            status:
              "cancelled",
          }),

          Appointment.countDocuments({
            status:
              "checked-in",
          }),

          Appointment.countDocuments({
            status:
              "checked-out",
          }),

          User.countDocuments(),

          Appointment.countDocuments({
            status: {
              $in: [
                "accepted",
                "confirmed",
              ],
            },

            checkin: {
              $gte: today,
              $lt: tomorrow,
            },
          }),

          Appointment.find()
            .populate(
              "userId",
              "fullname email phone"
            )
            .sort({
              createdAt: -1,
            })
            .limit(8)
            .lean(),
        ]);

      return res.render(
        "admin/dashboard",
        {
          title:
            "Isle Command",

          admin:
            getAdminSession(req),

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
    } catch (error) {
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

// ============================================================
// ADMIN ANALYTICS
// ============================================================

router.get(
  "/analytics",
  requireAdmin,
  async (req, res) => {
    try {
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
        await Promise.all([
          Appointment.countDocuments(),

          Appointment.countDocuments({
            status:
              "pending",
          }),

          Appointment.countDocuments({
            status:
              "accepted",
          }),

          Appointment.countDocuments({
            status:
              "confirmed",
          }),

          Appointment.countDocuments({
            status: {
              $in: [
                "declined",
                "rejected",
              ],
            },
          }),

          Appointment.countDocuments({
            status:
              "cancelled",
          }),

          Appointment.countDocuments({
            status:
              "checked-in",
          }),

          Appointment.countDocuments({
            status:
              "checked-out",
          }),

          Appointment.countDocuments({
            status:
              "completed",
          }),

          User.countDocuments(),

          Appointment.aggregate([
            {
              $match: {
                status: {
                  $in: [
                    "accepted",
                    "confirmed",
                    "checked-in",
                    "checked-out",
                    "completed",
                  ],
                },
              },
            },

            {
              $group: {
                _id: null,

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
          ]),

          Appointment.aggregate([
            {
              $match: {
                status: {
                  $in: [
                    "accepted",
                    "confirmed",
                    "checked-in",
                    "checked-out",
                    "completed",
                  ],
                },
              },
            },

            {
              $group: {
                _id: "$room",

                bookings: {
                  $sum: 1,
                },

                grossBookingValue: {
                  $sum: {
                    $ifNull: [
                      "$totalPrice",
                      0,
                    ],
                  },
                },
              },
            },

            {
              $sort: {
                bookings: -1,
              },
            },
          ]),

          Appointment.find()
            .populate(
              "userId",
              "fullname email phone"
            )
            .sort({
              updatedAt: -1,
              createdAt: -1,
            })
            .limit(20)
            .lean(),
        ]);

      const revenue =
        parseNumber(
          revenueResult?.[0]?.total,
          0
        );

      const normalizedRoomBreakdown =
        roomBreakdown.map(
          (entry) => ({
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
            getAdminSession(req),

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

          roomBreakdown:
            normalizedRoomBreakdown,

          recentActivity,
        }
      );
    } catch (error) {
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

// ============================================================
// ADMIN HISTORY
// ============================================================

router.get(
  "/history",
  requireAdmin,
  async (req, res) => {
    try {
      const allBookings =
        await Appointment.find()
          .populate(
            "userId",
            "fullname email phone"
          )
          .sort({
            createdAt: -1,
          })
          .lean();

      return res.render(
        "admin/history",
        {
          title:
            "Isle Archive",

          admin:
            getAdminSession(req),

          allBookings,

          bookings:
            allBookings,

          appointments:
            allBookings,
        }
      );
    } catch (error) {
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

// ============================================================
// FRONT DESK CHECK-IN MANAGER
// ============================================================

async function renderCheckinManager(
  req,
  res
) {
  try {
    const [
      arrivals,
      inHouse,
    ] =
      await Promise.all([
        Appointment.find({
          status: {
            $in: [
              "accepted",
              "confirmed",
            ],
          },
        })
          .populate(
            "userId",
            "fullname email phone"
          )
          .sort({
            checkin: 1,
            createdAt: -1,
          })
          .lean(),

        Appointment.find({
          status:
            "checked-in",
        })
          .populate(
            "userId",
            "fullname email phone"
          )
          .sort({
            checkedInAt: -1,
            checkin: 1,
            checkout: 1,
            createdAt: -1,
          })
          .lean(),
      ]);

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
          getAdminSession(req),

        arrivals,

        inHouse,

        bookings,

        appointments:
          bookings,
      }
    );
  } catch (error) {
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

// ============================================================
// FRONT DESK CHECK-IN UPDATE
// ============================================================

router.post(
  "/update-checkin",
  requireAdminMutation,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal({
          bookingId,

          status:
            "checked-in",

          req,
        });

      if (!result.ok) {
        return sendApiError(
          res,
          result.statusCode ||
            400,
          result.message,
          "CHECKIN_FAILED",
          getRequestId(req)
        );
      }

      return res.json({
        success: true,

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
    } catch (error) {
      console.error(
        `[CHECK-IN UPDATE ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// FRONT DESK CHECK-OUT UPDATE
// ============================================================

router.post(
  "/update-checkout",
  requireAdminMutation,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal({
          bookingId,

          status:
            "checked-out",

          req,
        });

      if (!result.ok) {
        return sendApiError(
          res,
          result.statusCode ||
            400,
          result.message,
          "CHECKOUT_FAILED",
          getRequestId(req)
        );
      }

      return res.json({
        success: true,

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
    } catch (error) {
      console.error(
        `[CHECK-OUT UPDATE ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// ADMIN BOOKING STATUS UPDATE
// ============================================================

router.post(
  "/booking/update-status",
  requireAdminMutation,
  async (req, res) => {
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
        await updateStatusInternal({
          bookingId,

          status,

          req,
        });

      if (!result.ok) {
        return sendApiError(
          res,
          result.statusCode ||
            400,
          result.message,
          "BOOKING_STATUS_UPDATE_FAILED",
          getRequestId(req)
        );
      }

      return res.json({
        success: true,

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
    } catch (error) {
      console.error(
        `[BOOKING STATUS UPDATE ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// QUICK ACCEPT
// ============================================================

router.post(
  "/booking/accept",
  requireAdminMutation,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal({
          bookingId,

          status:
            "accepted",

          req,
        });

      if (!result.ok) {
        return sendApiError(
          res,
          result.statusCode ||
            400,
          result.message,
          "BOOKING_ACCEPT_FAILED",
          getRequestId(req)
        );
      }

      return res.json({
        success: true,

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
    } catch (error) {
      console.error(
        `[QUICK ACCEPT ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// QUICK DECLINE
// ============================================================

router.post(
  "/booking/decline",
  requireAdminMutation,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(
          req
        );

      const result =
        await updateStatusInternal({
          bookingId,

          status:
            "declined",

          req,
        });

      if (!result.ok) {
        return sendApiError(
          res,
          result.statusCode ||
            400,
          result.message,
          "BOOKING_DECLINE_FAILED",
          getRequestId(req)
        );
      }

      return res.json({
        success: true,

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
    } catch (error) {
      console.error(
        `[QUICK DECLINE ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// USERS / CUSTOMER MANAGEMENT
// ============================================================

router.get(
  "/users",
  requireAdmin,
  async (req, res) => {
    try {
      /*
       * ========================================================
       * CUSTOMER RESERVATION SUMMARY
       * ========================================================
       *
       * totalBookingValue:
       *   Value of accepted, confirmed, checked-in,
       *   checked-out, and completed reservations.
       *
       * realizedValue:
       *   Value of checked-out and completed stays.
       *
       * upcomingValue:
       *   Value of accepted / confirmed reservations that
       *   have not passed their checkout date.
       *
       * NOTE:
       * These values are reservation totals stored in Appointment.
       * They are not payment transaction totals.
       */

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

      const now =
        new Date();

      const [
        users,
        bookingStats,
      ] =
        await Promise.all([
          /*
           * ====================================================
           * CUSTOMER RECORDS
           * ====================================================
           *
           * Explicitly expose only fields needed by the
           * administrator customer-management interface.
           *
           * Authentication secrets are intentionally excluded.
           */

          User.find()
            .select(
              "fullname username email phone status emailVerified " +
                "failedLoginAttempts lockedUntil lastLoginAt " +
                "passwordChangedAt createdAt updatedAt"
            )
            .sort({
              createdAt: -1,
            })
            .lean(),

          /*
           * ====================================================
           * RESERVATION AGGREGATION
           * ====================================================
           *
           * Build one summary record for each customer.
           */

          Appointment.aggregate([
            {
              $group: {
                _id: "$userId",

                /*
                 * ------------------------------------------------
                 * RESERVATION COUNTS
                 * ------------------------------------------------
                 */

                totalBookings: {
                  $sum: 1,
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

                /*
                 * ------------------------------------------------
                 * FINANCIAL SUMMARY
                 * ------------------------------------------------
                 */

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

                /*
                 * ------------------------------------------------
                 * STAY DURATION
                 * ------------------------------------------------
                 */

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

                /*
                 * ------------------------------------------------
                 * CUSTOMER ACTIVITY
                 * ------------------------------------------------
                 */

                lastBookingAt: {
                  $max: "$createdAt",
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

                /*
                 * ------------------------------------------------
                 * UPCOMING RESERVATION
                 * ------------------------------------------------
                 *
                 * We use a far-future date for non-matching
                 * records so $min does not incorrectly select null.
                 */

                nextCheckinCandidate: {
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
          ]),
        ]);

      /*
       * ========================================================
       * BUILD USER -> RESERVATION SUMMARY MAP
       * ========================================================
       */

      const statsByUser =
        new Map(
          bookingStats.map(
            (entry) => [
              String(
                entry._id
              ),

              {
                totalBookings:
                  Number(
                    entry.totalBookings ||
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

                totalBookingValue:
                  Number(
                    entry.totalBookingValue ||
                      0
                  ),

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
            ]
          )
        );

      /*
       * ========================================================
       * ENRICH CUSTOMERS
       * ========================================================
       *
       * Customers without reservations receive a complete
       * zero-value bookingStats structure.
       */

      const enrichedUsers =
        users.map(
          (user) => ({
            ...user,

            bookingStats:
              statsByUser.get(
                String(
                  user._id
                )
              ) || {
                totalBookings: 0,

                completedStays: 0,

                cancelledBookings: 0,

                pendingRequests: 0,

                totalBookingValue: 0,

                realizedValue: 0,

                upcomingValue: 0,

                totalNights: 0,

                upcomingNights: 0,

                lastBookingAt:
                  null,

                lastCheckout:
                  null,

                nextCheckin:
                  null,
              },
          })
        );

      return res.render(
        "admin/users",
        {
          title:
            "User Management",

          admin:
            getAdminSession(req),

          users:
            enrichedUsers,
        }
      );
    } catch (error) {
      console.error(
        `[USERS PAGE ERROR] requestId=${
          getRequestId(req) ||
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

// ============================================================
// USER DETAIL API
// ============================================================

router.get(
  "/users/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const userId =
        getResourceIdFromRequest(
          req
        );

      /*
       * --------------------------------------------------------
       * VALIDATE USER ID
       * --------------------------------------------------------
       */

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
          getRequestId(req)
        );
      }

      /*
       * --------------------------------------------------------
       * LOAD USER
       * --------------------------------------------------------
       *
       * Only return administrator-facing profile fields.
       *
       * Authentication credentials and secret fields are not
       * returned by this API.
       */

      const user =
        await User.findById(
          userId
        )
          .select(
            "fullname username email phone status emailVerified " +
              "failedLoginAttempts lockedUntil lastLoginAt " +
              "passwordChangedAt createdAt updatedAt"
          )
          .lean();

      if (!user) {
        return sendApiError(
          res,
          404,
          "User not found.",
          "USER_NOT_FOUND",
          getRequestId(req)
        );
      }

      /*
       * --------------------------------------------------------
       * LOAD CUSTOMER RESERVATIONS
       * --------------------------------------------------------
       */

      const bookings =
        await Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean();

      /*
       * --------------------------------------------------------
       * CUSTOMER SUMMARY
       * --------------------------------------------------------
       */

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

      const now =
        new Date();

      let totalBookings =
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

      /*
       * --------------------------------------------------------
       * PROCESS RESERVATIONS
       * --------------------------------------------------------
       */

      bookings.forEach(
        (booking) => {
          totalBookings += 1;

          const status =
            normalizeString(
              booking?.status,
              50
            ).toLowerCase();

          const bookingTotal =
            parseNumber(
              booking?.totalPrice,
              0
            );

          /*
           * Prefer stored numberOfNights.
           * If unavailable, calculate it from check-in/out dates.
           */
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
            storedNights > 0
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

          /*
           * ====================================================
           * REALIZED STAYS
           * ====================================================
           */

          if (
            realizedStatuses.has(
              status
            )
          ) {
            completedStays += 1;

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

          /*
           * ====================================================
           * CANCELLED / DECLINED / REJECTED
           * ====================================================
           */

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

          /*
           * ====================================================
           * PENDING
           * ====================================================
           */

          if (
            status ===
            "pending"
          ) {
            pendingRequests +=
              1;
          }

          /*
           * ====================================================
           * TOTAL BOOKING VALUE
           * ====================================================
           */

          if (
            bookingValueStatuses.has(
              status
            )
          ) {
            totalBookingValue +=
              bookingTotal;
          }

          /*
           * ====================================================
           * UPCOMING
           * ====================================================
           */

          const isUpcoming =
            upcomingStatuses.has(
              status
            ) &&
            checkout &&
            !Number.isNaN(
              checkout.getTime()
            ) &&
            checkout >= now;

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

          /*
           * ====================================================
           * LAST BOOKING
           * ====================================================
           */

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

      return res.json({
        success: true,

        user,

        bookingStats: {
          totalBookings,

          completedStays,

          cancelledBookings,

          pendingRequests,

          totalBookingValue,

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
    } catch (error) {
      console.error(
        `[USER DETAIL ERROR] requestId=${
          getRequestId(req) ||
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
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// ROOMS PAGE
// ============================================================

router.get(
  "/rooms",
  requireAdmin,
  async (req, res) => {
    try {
      const [
        rooms,
        bookings,
      ] =
        await Promise.all([
          Room.find()
            .sort({
              sortOrder: 1,
              name: 1,
              createdAt: 1,
            })
            .lean(),

          Appointment.find({
            status: {
              $in:
                BLOCKING_STATUSES,
            },
          })
            .select(
              "room status checkin checkout userId"
            )
            .populate(
              "userId",
              "fullname email phone"
            )
            .sort({
              checkin: 1,
            })
            .lean(),
        ]);

      return res.render(
        "admin/rooms",
        {
          title:
            "Room Management",

          admin:
            getAdminSession(req),

          rooms,

          bookings,
        }
      );
    } catch (error) {
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

// ============================================================
// CREATE ROOM
// ============================================================

router.post(
  "/rooms/create",
  requireAdminMutation,
  async (req, res) => {
    try {
      const payload =
        buildRoomCreatePayload(
          req.body
        );

      if (!payload.name) {
        return sendApiError(
          res,
          400,
          "Room name is required.",
          "INVALID_ROOM",
          getRequestId(req)
        );
      }

      if (
        payload.price < 0
      ) {
        return sendApiError(
          res,
          400,
          "Room price cannot be negative.",
          "INVALID_ROOM",
          getRequestId(req)
        );
      }

      const room =
        new Room(
          payload
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

      return res.status(
        201
      ).json({
        success: true,

        message:
          "Room created successfully.",

        room,
      });
    } catch (error) {
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
            error.errors || {}
          )
            .map(
              (entry) =>
                entry.message
            )
            .filter(Boolean)
            .join(" ") ||
            "Some room information is invalid.",
          "VALIDATION_ERROR",
          getRequestId(req)
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to create room.",
        "ROOM_CREATE_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// UPDATE ROOM
// ============================================================

async function updateRoomHandler(
  req,
  res
) {
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
        getRequestId(req)
      );
    }

    const room =
      await getRoomDocumentById(
        roomId
      );

    if (!room) {
      return sendApiError(
        res,
        404,
        "Room not found.",
        "ROOM_NOT_FOUND",
        getRequestId(req)
      );
    }

    const payload =
      buildRoomUpdatePayload(
        req.body
      );

    if (
      Object.keys(
        payload
      ).length === 0
    ) {
      return sendApiError(
        res,
        400,
        "No room changes were provided.",
        "NO_CHANGES",
        getRequestId(req)
      );
    }

    for (
      const [
        key,
        value,
      ] of Object.entries(
        payload
      )
    ) {
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

    await room.save();

    logAdminAction(
      req,
      "room-update",
      {
        roomId,
      }
    );

    return res.json({
      success: true,

      message:
        "Room updated successfully.",

      room,
    });
  } catch (error) {
    console.error(
      `[UPDATE ROOM ERROR] requestId=${
        getRequestId(req) ||
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
          error.errors || {}
        )
          .map(
            (entry) =>
              entry.message
          )
          .filter(Boolean)
          .join(" ") ||
          "Some room information is invalid.",

        "VALIDATION_ERROR",

        getRequestId(req)
      );
    }

    return sendApiError(
      res,
      500,
      "Unable to update room.",
      "ROOM_UPDATE_FAILED",
      getRequestId(req)
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

// ============================================================
// ROOM IMAGE UPLOAD
// ============================================================

router.post(
  "/rooms/:id/image",
  requireAdminMutation,

  (req, res, next) => {
    parseRoomImageBody(
      req,
      res,
      (error) => {
        if (!error) {
          return next();
        }

        console.error(
          `[ROOM IMAGE BODY ERROR] requestId=${
            getRequestId(req) ||
            "none"
          }`,

          error.message ||
            error
        );

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
            getRequestId(req)
          );
        }

        return sendApiError(
          res,
          400,
          "Unable to read the uploaded image.",
          "IMAGE_BODY_INVALID",
          getRequestId(req)
        );
      }
    );
  },

  async (req, res) => {
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
          getRequestId(req)
        );
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (!room) {
        return sendApiError(
          res,
          404,
          "Room not found.",
          "ROOM_NOT_FOUND",
          getRequestId(req)
        );
      }

      const contentType =
        String(
          req.headers[
            "content-type"
          ] || ""
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
          getRequestId(req)
        );
      }

      const buffer =
        req.body;

      if (
        !Buffer.isBuffer(
          buffer
        ) ||
        buffer.length === 0
      ) {
        return sendApiError(
          res,
          400,
          "No image file was received.",
          "IMAGE_MISSING",
          getRequestId(req)
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
          getRequestId(req)
        );
      }

      const imageType =
        detectRoomImageType(
          buffer
        );

      if (!imageType) {
        return sendApiError(
          res,
          400,
          "The uploaded file is not a supported JPG, PNG, or WEBP image.",
          "INVALID_IMAGE_FILE",
          getRequestId(req)
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
          getRequestId(req)
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
        success: true,

        message:
          "Room image uploaded successfully.",

        room: {
          id:
            room._id,

          image:
            finalImageUrl,
        },
      });
    } catch (error) {
      if (
        savedFile?.url
      ) {
        await removeManagedRoomImage(
          savedFile.url
        );
      }

      console.error(
        `[ROOM IMAGE UPLOAD ERROR] requestId=${
          getRequestId(req) ||
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
            error.errors || {}
          )
            .map(
              (entry) =>
                entry.message
            )
            .filter(Boolean)
            .join(" ") ||
            "The room image could not be saved.",
          "ROOM_IMAGE_VALIDATION_FAILED",
          getRequestId(req)
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to upload the room image.",
        "ROOM_IMAGE_UPLOAD_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// DELETE / DEACTIVATE ROOM
// ============================================================

router.post(
  "/rooms/delete/:id",
  requireAdminMutation,
  async (req, res) => {
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
          getRequestId(req)
        );
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (!room) {
        return sendApiError(
          res,
          404,
          "Room not found.",
          "ROOM_NOT_FOUND",
          getRequestId(req)
        );
      }

      const roomIdentifiers =
        [
          room.name,
          room.displayName,
          room.key,
        ]
          .map(
            (value) =>
              normalizeString(
                value,
                150
              )
          )
          .filter(Boolean);

      const hasFutureOrActiveBookings =
        roomIdentifiers.length >
          0 &&
        await Appointment.exists({
          room: {
            $in:
              roomIdentifiers,
          },

          status: {
            $in:
              BLOCKING_STATUSES,
          },

          checkout: {
            $gte:
              new Date(),
          },
        });

      if (
        hasFutureOrActiveBookings
      ) {
        return sendApiError(
          res,
          409,
          "This room has an active or future booking and cannot be deleted.",
          "ROOM_HAS_ACTIVE_BOOKINGS",
          getRequestId(req)
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
        success: true,

        message:
          "Room removed from active inventory.",
      });
    } catch (error) {
      console.error(
        "Delete Room Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to remove room.",
        "ROOM_DELETE_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// ADD-ONS PAGE
// ============================================================

router.get(
  "/add-ons",
  requireAdmin,
  async (req, res) => {
    try {
      const [
        rawAddOns,
        rooms,
      ] =
        await Promise.all([
          AddOn.find()
            .sort({
              sortOrder: 1,
              name: 1,
              createdAt: 1,
            })
            .lean(),

          Room.find()
            .sort({
              sortOrder: 1,
              name: 1,
            })
            .lean(),
        ]);

      const addOns =
        rawAddOns
          .map(
            normalizeAddOnRecord
          )
          .filter(Boolean);

      return res.render(
        "admin/add-ons",
        {
          title:
            "Manage Add-ons",

          admin:
            getAdminSession(req),

          addOns,

          rooms,
        }
      );
    } catch (error) {
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

// ============================================================
// CREATE ADD-ON
// ============================================================

router.post(
  "/add-ons/create",
  requireAdminMutation,
  async (req, res) => {
    try {
      const payload =
        buildAddOnCreatePayload(
          req.body
        );

      if (!payload.name) {
        return sendApiError(
          res,
          400,
          "Add-on name is required.",
          "INVALID_ADDON",
          getRequestId(req)
        );
      }

      /*
       * Prevent silent failure when the upgraded frontend sends
       * pricingType but the current schema does not support it.
       */
      if (
        modelHasPath(
          AddOn,
          "pricingType"
        ) === false &&
        hasOwn(
          req.body,
          "pricingType",
          "priceType",
          "billingType"
        )
      ) {
        return sendApiError(
          res,
          500,
          "The AddOn model is missing the pricingType field required by the admin catalog.",
          "ADDON_MODEL_FIELD_MISSING",
          getRequestId(req)
        );
      }

      /*
       * Prevent silent failure when the upgraded frontend sends
       * sortOrder but the current schema does not support it.
       */
      if (
        modelHasPath(
          AddOn,
          "sortOrder"
        ) === false &&
        hasOwn(
          req.body,
          "sortOrder",
          "displayOrder",
          "order"
        )
      ) {
        return sendApiError(
          res,
          500,
          "The AddOn model is missing the sortOrder field required by the admin catalog.",
          "ADDON_MODEL_FIELD_MISSING",
          getRequestId(req)
        );
      }

      const addOn =
        new AddOn({});

      Object.entries(
        payload
      ).forEach(
        ([key, value]) => {
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
        .status(201)
        .json({
          success: true,

          message:
            "Add-on created successfully.",

          addOn,
        });
    } catch (error) {
      console.error(
        `[CREATE ADD-ON ERROR] requestId=${
          getRequestId(req) ||
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
              (entry) =>
                entry.message
            )
            .filter(Boolean)
            .join(" ") ||
            "Some add-on information is invalid.",

          "VALIDATION_ERROR",

          getRequestId(req)
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to create add-on.",
        "ADDON_CREATE_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// UPDATE ADD-ON
// ============================================================

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
        getRequestId(req)
      );
    }

    const addOn =
      await AddOn.findById(
        addOnId
      );

    if (!addOn) {
      return sendApiError(
        res,
        404,
        "Add-on not found.",
        "ADDON_NOT_FOUND",
        getRequestId(req)
      );
    }

    const payload =
      buildAddOnUpdatePayload(
        req.body
      );

    if (
      Object.keys(
        payload
      ).length === 0
    ) {
      return sendApiError(
        res,
        400,
        "No add-on changes were provided.",
        "NO_CHANGES",
        getRequestId(req)
      );
    }

    /*
     * Check schema compatibility before saving.
     */
    if (
      Object.prototype.hasOwnProperty.call(
        payload,
        "pricingType"
      ) &&
      modelHasPath(
        AddOn,
        "pricingType"
      ) === false
    ) {
      return sendApiError(
        res,
        500,
        "The AddOn model is missing the pricingType field required by the admin catalog.",
        "ADDON_MODEL_FIELD_MISSING",
        getRequestId(req)
      );
    }

    if (
      Object.prototype.hasOwnProperty.call(
        payload,
        "sortOrder"
      ) &&
      modelHasPath(
        AddOn,
        "sortOrder"
      ) === false
    ) {
      return sendApiError(
        res,
        500,
        "The AddOn model is missing the sortOrder field required by the admin catalog.",
        "ADDON_MODEL_FIELD_MISSING",
        getRequestId(req)
      );
    }

    Object.entries(
      payload
    ).forEach(
      ([key, value]) => {
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
      success: true,

      message:
        "Add-on updated successfully.",

      addOn,
    });
  } catch (error) {
    console.error(
      `[UPDATE ADD-ON ERROR] requestId=${
        getRequestId(req) ||
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
            (entry) =>
              entry.message
          )
          .filter(Boolean)
          .join(" ") ||
          "Some add-on information is invalid.",

        "VALIDATION_ERROR",

        getRequestId(req)
      );
    }

    return sendApiError(
      res,
      500,
      "Unable to update add-on.",
      "ADDON_UPDATE_FAILED",
      getRequestId(req)
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

// ============================================================
// ADD-ON IMAGE UPLOAD
// ============================================================

router.post(
  "/add-ons/:id/image",

  requireAdminMutation,

  /*
   * The upgraded add-ons.ejs sends the file as raw binary.
   */
  (req, res, next) => {
    parseAddOnImageBody(
      req,
      res,
      (error) => {
        if (!error) {
          return next();
        }

        console.error(
          `[ADD-ON IMAGE BODY ERROR] requestId=${
            getRequestId(req) ||
            "none"
          }`,

          error.message ||
            error
        );

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
            getRequestId(req)
          );
        }

        return sendApiError(
          res,
          400,
          "Unable to read the uploaded add-on image.",
          "IMAGE_BODY_INVALID",
          getRequestId(req)
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
          getRequestId(req)
        );
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (!addOn) {
        return sendApiError(
          res,
          404,
          "Add-on not found.",
          "ADDON_NOT_FOUND",
          getRequestId(req)
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
          getRequestId(req)
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
          getRequestId(req)
        );
      }

      if (
        buffer.length >
        ADDON_IMAGE_MAX_BYTES
      ) {
        return sendApiError(
          res,
          413,
          "The selected image is larger than 8 MB.",
          "IMAGE_TOO_LARGE",
          getRequestId(req)
        );
      }

      /*
       * Validate actual file contents.
       */
      const imageType =
        detectAddOnImageType(
          buffer
        );

      if (!imageType) {
        return sendApiError(
          res,
          400,
          "The uploaded file is not a supported JPG, PNG, or WEBP image.",
          "INVALID_IMAGE_FILE",
          getRequestId(req)
        );
      }

      /*
       * Validate MIME type against the detected signature.
       */
      if (
        imageType.contentType !==
        contentType
      ) {
        return sendApiError(
          res,
          400,
          "The uploaded image type does not match its actual file contents.",
          "IMAGE_TYPE_MISMATCH",
          getRequestId(req)
        );
      }

      /*
       * Preserve the old image until the database save succeeds.
       */
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

      /*
       * Save new file atomically.
       */
      savedFile =
        await saveAddOnImageBuffer(
          buffer,
          imageType
        );

      /*
       * Update whichever image field exists in the current schema.
       */
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
          getRequestId(req)
        );
      }

      const finalImageUrl =
        savedFile.url;

      /*
       * Save DB record first.
       */
      await addOn.save();

      /*
       * DB now references the new file.
       */
      savedFile =
        null;

      /*
       * Remove previous image only if it was managed by IsleRMS.
       */
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
        success: true,

        message:
          "Add-on image uploaded successfully.",

        addOn: {
          id:
            addOn._id,

          image:
            finalImageUrl,
        },
      });
    } catch (error) {
      /*
       * If DB save failed after file creation,
       * clean the newly-created file.
       */
      if (
        savedFile?.url
      ) {
        await removeManagedAddOnImage(
          savedFile.url
        );
      }

      console.error(
        `[ADD-ON IMAGE UPLOAD ERROR] requestId=${
          getRequestId(req) ||
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
              (entry) =>
                entry.message
            )
            .filter(Boolean)
            .join(" ") ||
            "The add-on image could not be saved.",

          "ADDON_IMAGE_VALIDATION_FAILED",

          getRequestId(req)
        );
      }

      return sendApiError(
        res,
        500,
        "Unable to upload the add-on image.",

        "ADDON_IMAGE_UPLOAD_FAILED",

        getRequestId(req)
      );
    }
  }
);

// ============================================================
// DELETE / DEACTIVATE ADD-ON
// ============================================================

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
          getRequestId(req)
        );
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (!addOn) {
        return sendApiError(
          res,
          404,
          "Add-on not found.",
          "ADDON_NOT_FOUND",
          getRequestId(req)
        );
      }

      /*
       * Prefer deactivation so historical references are not
       * destroyed accidentally.
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
        /*
         * Legacy schema fallback.
         */
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
        success: true,

        message:
          "Add-on removed from active inventory.",
      });
    } catch (error) {
      console.error(
        "Delete Add-on Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to remove add-on.",
        "ADDON_DELETE_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// ADMIN ROOM DATA API
// ============================================================

router.get(
  "/api/rooms",
  requireAdminApi,
  async (req, res) => {
    try {
      const rooms =
        await getConfiguredRooms();

      const cottage =
        await getConfiguredCottage();

      return res.json({
        success: true,

        rooms,

        cottage,
      });
    } catch (error) {
      console.error(
        "Admin Room API Error:",
        error
      );

      return sendApiError(
        res,
        500,
        "Unable to load room information.",
        "ROOM_API_FAILED",
        getRequestId(req)
      );
    }
  }
);

// ============================================================
// ADMIN LOGOUT
// ============================================================

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
        if (!req.session) {
          return resolve();
        }

        req.session.destroy(
          (error) => {
            if (error) {
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
     * Clear the canonical IsleRMS admin session cookie.
     */
    res.clearCookie(
      "islerms.sid",
      {
        httpOnly: true,

        sameSite:
          "lax",

        secure:
          process.env.NODE_ENV ===
          "production",

        path:
          "/",
      }
    );

    return res.redirect(
      "/admin/login"
    );
  } catch (error) {
    console.error(
      `[ADMIN LOGOUT ERROR] requestId=${
        getRequestId(req) ||
        "none"
      }`,

      error.stack ||
        error.message ||
        error
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
 * Temporary GET compatibility.
 *
 * POST /admin/logout is the canonical endpoint.
 */
router.get(
  "/logout",
  logoutAdminHandler
);

// ============================================================
// ADMIN API 404
// ============================================================

router.use(
  (req, res, next) => {
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
        getRequestId(req)
      );
    }

    next();
  }
);

// ============================================================
// ROUTER EXPORT
// ============================================================

module.exports = router;