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

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Admin = require("../models/Admin");
const Notification = require("../models/Notification");
const Room = require("../models/Room");
const AddOn = require("../models/AddOn");

const router = express.Router();

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
// BASIC HELPERS
// ============================================================

function normalizeString(value, maxLength = 500) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, maxLength);
}

function normalizeUsername(value) {
  return normalizeString(value, 120).toLowerCase();
}

function normalizeEmail(value) {
  return normalizeString(value, 320).toLowerCase();
}

function isValidObjectId(id) {
  return Boolean(id) && mongoose.Types.ObjectId.isValid(id);
}

function parseNumber(value, fallback = 0) {
  const parsed = Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;
}

function parseInteger(value, fallback = 0) {
  const parsed = Number(value);

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
  const start = startOfToday();

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

  const stringValue = String(value).trim();

  if (/^\d{4}-\d{2}-\d{2}$/.test(stringValue)) {
    const [year, month, day] = stringValue
      .split("-")
      .map(Number);

    const date = new Date(
      year,
      month - 1,
      day
    );

    if (
      date.getFullYear() !== year ||
      date.getMonth() !== month - 1 ||
      date.getDate() !== day
    ) {
      return null;
    }

    return date;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date;
}

function validateBookingDates(checkin, checkout) {
  const start = parseBookingDate(checkin);
  const end = parseBookingDate(checkout);

  if (!start || !end) {
    return {
      valid: false,
      message: "Invalid booking dates.",
    };
  }

  if (end <= start) {
    return {
      valid: false,
      message: "Check-out must be after check-in.",
    };
  }

  return {
    valid: true,
    start,
    end,
  };
}

function calculateNights(checkin, checkout) {
  const start = parseBookingDate(checkin);
  const end = parseBookingDate(checkout);

  if (!start || !end || end <= start) {
    return 0;
  }

  const startUtc = Date.UTC(
    start.getFullYear(),
    start.getMonth(),
    start.getDate()
  );

  const endUtc = Date.UTC(
    end.getFullYear(),
    end.getMonth(),
    end.getDate()
  );

  return Math.round(
    (endUtc - startUtc) / 86400000
  );
}

function pickFirst(record, fields, fallback = undefined) {
  for (const field of fields) {
    if (
      record &&
      record[field] !== undefined &&
      record[field] !== null &&
      record[field] !== ""
    ) {
      return record[field];
    }
  }

  return fallback;
}

function modelHasPath(model, path) {
  return Boolean(
    model &&
    model.schema &&
    typeof model.schema.path === "function" &&
    model.schema.path(path)
  );
}

function setModelValue(document, fieldNames, value) {
  if (!document || !Array.isArray(fieldNames)) {
    return false;
  }

  for (const field of fieldNames) {
    if (
      document.schema &&
      document.schema.path(field)
    ) {
      document.set(field, value);
      return true;
    }
  }

  return false;
}

function wantsJson(req) {
  const requested = String(
    req.headers?.accept || ""
  ).toLowerCase();

  return (
    req.xhr ||
    requested.includes("application/json") ||
    req.path.startsWith("/api/") ||
    req.path.startsWith("/booking/") ||
    req.path.startsWith("/update-")
  );
}

function getAdminSession(req) {
  return req.session?.admin || null;
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
 * IMPORTANT:
 * Front Desk checkin.ejs sends `bookingId`.
 *
 * We support:
 *   bookingId
 *   appointmentId
 *   id
 *
 * so older frontend code remains compatible.
 */
function getBookingIdFromRequest(req) {
  return normalizeString(
    req.body?.bookingId ||
      req.body?.appointmentId ||
      req.body?.id
  );
}

function getResourceIdFromRequest(req) {
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
  return res.status(statusCode).render(
    "error",
    {
      title,
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
  const separator = path.includes("?")
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

function requireAdmin(req, res, next) {
  if (!req.session?.admin?.id) {
    if (wantsJson(req)) {
      return res.status(401).json({
        success: false,
        message:
          "Administrator authentication required.",
      });
    }

    return res.redirect("/admin/login");
  }

  next();
}

function requireAdminApi(req, res, next) {
  if (!req.session?.admin?.id) {
    return res.status(401).json({
      success: false,
      message:
        "Administrator authentication required.",
    });
  }

  next();
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        return reject(error);
      }

      resolve();
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        return reject(error);
      }

      resolve();
    });
  });
}

// ============================================================
// NOTIFICATIONS
// ============================================================

async function notifyUser(
  userId,
  type,
  title,
  message,
  bookingId = null
) {
  if (!isValidObjectId(userId)) {
    return null;
  }

  try {
    if (!Notification) {
      return null;
    }

    const payload = {};

    // Support common Notification schema naming conventions.
    if (modelHasPath(Notification, "userId")) {
      payload.userId = userId;
    } else if (
      modelHasPath(
        Notification,
        "recipient"
      )
    ) {
      payload.recipient = userId;
    } else if (
      modelHasPath(
        Notification,
        "recipientId"
      )
    ) {
      payload.recipientId = userId;
    }

    if (modelHasPath(Notification, "type")) {
      payload.type = type;
    }

    if (modelHasPath(Notification, "title")) {
      payload.title = title;
    }

    if (
      modelHasPath(
        Notification,
        "message"
      )
    ) {
      payload.message = message;
    } else if (
      modelHasPath(
        Notification,
        "text"
      )
    ) {
      payload.text = message;
    }

    if (
      bookingId &&
      isValidObjectId(bookingId)
    ) {
      if (
        modelHasPath(
          Notification,
          "bookingId"
        )
      ) {
        payload.bookingId = bookingId;
      } else if (
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
      payload.read = false;
    } else if (
      modelHasPath(
        Notification,
        "isRead"
      )
    ) {
      payload.isRead = false;
    }

    if (
      modelHasPath(
        Notification,
        "createdAt"
      )
    ) {
      payload.createdAt = new Date();
    }

    return await Notification.create(
      payload
    );
  } catch (error) {
    // Notification failure must never prevent
    // a booking status change.
    console.error(
      "Notification Error:",
      error
    );

    return null;
  }
}

// ============================================================
// ROOM / CATALOG HELPERS
// ============================================================

function normalizeRoomRecord(record) {
  if (!record) {
    return null;
  }

  const plain =
    typeof record.toObject === "function"
      ? record.toObject()
      : record;

  const name = normalizeString(
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

  const price = parseNumber(
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

  const maxGuests = Math.max(
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

  const image = normalizeString(
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

  const typeValue = normalizeString(
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
    typeValue.includes("cottage") ||
    name
      .toLowerCase()
      .includes("cottage");

  const activeValue = pickFirst(
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
    id: plain._id
      ? plain._id.toString()
      : null,
    key: name,
    name,
    displayName: name,
    price,
    maxGuests,
    image,
    type: isCottage
      ? "cottage"
      : "room",
    active: activeValue !== false,
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
      .map(normalizeRoomRecord)
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

  if (dynamicRooms.length > 0) {
    return dynamicRooms.filter(
      (room) => room.active
    );
  }

  return LEGACY_ROOMS.map((room) => ({
    ...room,
  }));
}

async function getConfiguredCottage() {
  const dynamicRooms =
    await getDynamicRooms();

  const dynamicCottage =
    dynamicRooms.find(
      (room) =>
        room.type === "cottage"
    );

  return dynamicCottage
    ? { ...dynamicCottage }
    : { ...LEGACY_COTTAGE };
}

async function getConfiguredAccommodation(
  roomName
) {
  const requested =
    normalizeString(roomName, 150);

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
        room.displayName === requested ||
        room.key === requested
    ) || null
  );
}

async function getRoomDocumentById(id) {
  if (!isValidObjectId(id)) {
    return null;
  }

  return Room.findById(id);
}

function buildRoomPayload(body) {
  const name = normalizeString(
    body?.name ||
      body?.displayName ||
      body?.roomName ||
      body?.title,
    150
  );

  const price = Math.max(
    0,
    parseNumber(
      body?.price ??
        body?.nightlyPrice ??
        body?.pricePerNight ??
        body?.rate,
      0
    )
  );

  const maxGuests = Math.max(
    1,
    parseInteger(
      body?.maxGuests ??
        body?.capacity ??
        body?.guestLimit ??
        body?.maxOccupancy,
      1
    )
  );

  const image = normalizeString(
    body?.image ||
      body?.imageUrl ||
      body?.photo ||
      body?.photoUrl ||
      "/images/room1.jpg",
    500
  );

  const type = normalizeString(
    body?.type ||
      body?.category ||
      body?.roomType ||
      "room",
    80
  );

  const active =
    body?.active === undefined &&
    body?.isActive === undefined &&
    body?.available === undefined
      ? true
      : asBoolean(
          body?.active ??
            body?.isActive ??
            body?.available
        );

  return {
    name,
    displayName: name,
    price,
    maxGuests,
    image,
    type,
    active,
  };
}

function normalizeAddOnRecord(record) {
  if (!record) {
    return null;
  }

  const plain =
    typeof record.toObject === "function"
      ? record.toObject()
      : record;

  const name = normalizeString(
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

  return {
    ...plain,
    id: plain._id
      ? plain._id.toString()
      : null,
    name,
    displayName: normalizeString(
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
    price: Math.max(
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
    ),
    description: normalizeString(
      pickFirst(
        plain,
        [
          "description",
          "details",
        ],
        ""
      ),
      1000
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

function buildAddOnPayload(body) {
  const name = normalizeString(
    body?.name ||
      body?.displayName ||
      body?.title,
    150
  );

  const price = Math.max(
    0,
    parseNumber(
      body?.price ??
        body?.amount ??
        body?.rate,
      0
    )
  );

  const description = normalizeString(
    body?.description ||
      body?.details,
    1000
  );

  const active =
    body?.active === undefined &&
    body?.isActive === undefined &&
    body?.available === undefined
      ? true
      : asBoolean(
          body?.active ??
            body?.isActive ??
            body?.available
        );

  return {
    name,
    displayName: name,
    price,
    amount: price,
    description,
    active,
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
      $in: BLOCKING_STATUSES,
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
    isValidObjectId(excludeId)
  ) {
    query._id = {
      $ne: excludeId,
    };
  }

  return Appointment.findOne(query)
    .sort({
      checkin: 1,
    })
    .lean();
}

// ============================================================
// BOOKING STATUS HELPERS
// ============================================================

function canTransitionStatus(from, to) {
  if (!ALL_STATUSES.includes(from)) {
    return false;
  }

  if (!ALL_STATUSES.includes(to)) {
    return false;
  }

  if (from === to) {
    return true;
  }

  return Boolean(
    STATUS_TRANSITIONS[from]?.includes(to)
  );
}

function applyStatusTimestamps(
  appointment,
  status
) {
  const now = new Date();

  if (status === "checked-in") {
    setModelValue(
      appointment,
      [
        "checkedInAt",
        "checkInTime",
      ],
      now
    );

    setModelValue(
      appointment,
      ["checkedIn"],
      true
    );
  }

  if (status === "checked-out") {
    setModelValue(
      appointment,
      [
        "checkedOutAt",
        "checkOutTime",
      ],
      now
    );

    setModelValue(
      appointment,
      ["checkedOut"],
      true
    );

    setModelValue(
      appointment,
      ["checkedIn"],
      false
    );
  }
}

function statusNotification(status) {
  switch (status) {
    case "accepted":
    case "confirmed":
      return {
        type: "accepted",
        title: "Booking Confirmed",
        message:
          "Your resort booking has been confirmed.",
      };

    case "declined":
    case "rejected":
      return {
        type: "declined",
        title: "Booking Declined",
        message:
          "Your resort booking request was declined.",
      };

    case "cancelled":
      return {
        type: "cancelled",
        title: "Booking Cancelled",
        message:
          "Your resort booking has been cancelled.",
      };

    case "checked-in":
      return {
        type: "checked-in",
        title: "Checked In",
        message:
          "Your resort check-in has been completed.",
      };

    case "checked-out":
      return {
        type: "checked-out",
        title: "Checked Out",
        message:
          "Your resort check-out has been completed.",
      };

    case "completed":
      return {
        type: "completed",
        title: "Stay Completed",
        message:
          "Your resort stay has been marked completed.",
      };

    default:
      return {
        type: status || "update",
        title: "Booking Update",
        message:
          "Your resort booking has been updated.",
      };
  }
}

async function updateStatusInternal({
  bookingId,
  status,
}) {
  if (!isValidObjectId(bookingId)) {
    return {
      ok: false,
      statusCode: 400,
      message: "Invalid booking ID.",
    };
  }

  if (!ALL_STATUSES.includes(status)) {
    return {
      ok: false,
      statusCode: 400,
      message: "Invalid booking status.",
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
      message: "Booking not found.",
    };
  }

  const currentStatus =
    appointment.status || "pending";

  if (
    currentStatus === status
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
        room: appointment.room,
        checkin: appointment.checkin,
        checkout: appointment.checkout,
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

  appointment.status = status;

  applyStatusTimestamps(
    appointment,
    status
  );

  await appointment.save();

  const notification =
    statusNotification(status);

  await notifyUser(
    appointment.userId,
    notification.type,
    notification.title,
    notification.message,
    appointment._id
  );

  return {
    ok: true,
    appointment,
    changed: true,
    message:
      `Booking status updated to ${status}.`,
  };
}

// ============================================================
// ADMIN LOGIN PAGE
// ============================================================

router.get(
  "/login",
  (req, res) => {
    if (req.session?.admin?.id) {
      return res.redirect(
        "/admin/dashboard"
      );
    }

    return res.render(
      "admin/adminlogin",
      {
        title: "Admin Portal",
        error:
          req.query?.error ||
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
  async (req, res) => {
    try {
      const username =
        normalizeUsername(
          req.body?.username ||
            req.body?.email
        );

      const password = String(
        req.body?.password || ""
      );

      if (!username || !password) {
        return res
          .status(400)
          .render(
            "admin/adminlogin",
            {
              title: "Admin Portal",
              error:
                "Username and password are required.",
            }
          );
      }

      const admin =
        await Admin.findOne({
          username,
        }).select("+password");

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

      if (!admin || !validPassword) {
        return res
          .status(401)
          .render(
            "admin/adminlogin",
            {
              title: "Admin Portal",
              error:
                "Access denied. Invalid credentials.",
            }
          );
      }

      // Session fixation protection.
      await regenerateSession(req);

      req.session.admin = {
        id: admin._id.toString(),
        _id: admin._id.toString(),
        username: admin.username,
        role: "admin",
      };

      await saveSession(req);

      console.log(
        `✅ Admin logged in: ${admin.username}`
      );

      return res.redirect(
        "/admin/dashboard"
      );
    } catch (error) {
      console.error(
        "Admin Login Error:",
        error
      );

      return res
        .status(500)
        .render(
          "admin/adminlogin",
          {
            title: "Admin Portal",
            error:
              "An unexpected login error occurred.",
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
      ] = await Promise.all([
        Appointment.countDocuments(),

        Appointment.countDocuments({
          status: "pending",
        }),

        Appointment.countDocuments({
          status: "accepted",
        }),

        Appointment.countDocuments({
          status: "confirmed",
        }),

        Appointment.countDocuments({
          status: "cancelled",
        }),

        Appointment.countDocuments({
          status: "checked-in",
        }),

        Appointment.countDocuments({
          status: "checked-out",
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
          title: "Isle Command",
          admin: getAdminSession(req),

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
      ] = await Promise.all([
        Appointment.countDocuments(),

        Appointment.countDocuments({
          status: "pending",
        }),

        Appointment.countDocuments({
          status: "accepted",
        }),

        Appointment.countDocuments({
          status: "confirmed",
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
          status: "cancelled",
        }),

        Appointment.countDocuments({
          status: "checked-in",
        }),

        Appointment.countDocuments({
          status: "checked-out",
        }),

        Appointment.countDocuments({
          status: "completed",
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
            $group: {
              _id: "$room",
              bookings: {
                $sum: 1,
              },
              revenue: {
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

      return res.render(
        "admin/analytics",
        {
          title: "Resort Analytics",
          admin: getAdminSession(req),

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
          roomBreakdown,
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
          title: "Isle Archive",
          admin: getAdminSession(req),

          allBookings,
          bookings: allBookings,
          appointments: allBookings,
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
    const [arrivals, inHouse] =
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
          status: "checked-in",
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
        appointments: bookings,
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

// Compatibility alias.
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
  requireAdminApi,
  async (req, res) => {
    try {
      /**
       * IMPORTANT:
       * checkin.ejs sends `bookingId`.
       * We also accept appointmentId and id
       * for compatibility.
       */
      const bookingId =
        getBookingIdFromRequest(req);

      if (!isValidObjectId(bookingId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid booking ID.",
        });
      }

      const appointment =
        await Appointment.findById(
          bookingId
        );

      if (!appointment) {
        return res.status(404).json({
          success: false,
          message:
            "Booking not found.",
        });
      }

      const currentStatus =
        appointment.status ||
        "pending";

      if (
        currentStatus ===
        "checked-in"
      ) {
        return res.json({
          success: true,
          message:
            "Guest is already checked in.",
          booking: {
            id: appointment._id,
            status:
              appointment.status,
            checkedInAt:
              appointment.checkedInAt ||
              appointment.checkInTime ||
              null,
          },
        });
      }

      if (
        ![
          "accepted",
          "confirmed",
        ].includes(currentStatus)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Only accepted or confirmed bookings can be checked in.",
        });
      }

      if (
        appointment.room &&
        appointment.checkin &&
        appointment.checkout
      ) {
        const conflict =
          await findRoomConflict({
            room: appointment.room,
            checkin:
              appointment.checkin,
            checkout:
              appointment.checkout,
            excludeId:
              appointment._id,
          });

        if (conflict) {
          return res.status(409).json({
            success: false,
            message:
              "The room is already occupied or reserved by another booking.",
          });
        }
      }

      appointment.status =
        "checked-in";

      applyStatusTimestamps(
        appointment,
        "checked-in"
      );

      await appointment.save();

      await notifyUser(
        appointment.userId,
        "checked-in",
        "Guest Checked In",
        "Your resort check-in has been completed.",
        appointment._id
      );

      return res.json({
        success: true,
        message:
          "Guest checked in successfully.",
        booking: {
          id: appointment._id,
          status:
            appointment.status,
          checkedInAt:
            appointment.checkedInAt ||
            appointment.checkInTime ||
            null,
        },
      });
    } catch (error) {
      console.error(
        "Check-in Update Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to update check-in status.",
      });
    }
  }
);

// ============================================================
// FRONT DESK CHECK-OUT UPDATE
// ============================================================

router.post(
  "/update-checkout",
  requireAdminApi,
  async (req, res) => {
    try {
      /**
       * IMPORTANT:
       * checkin.ejs sends `bookingId`.
       * We also accept appointmentId and id
       * for compatibility.
       */
      const bookingId =
        getBookingIdFromRequest(req);

      if (!isValidObjectId(bookingId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid booking ID.",
        });
      }

      const appointment =
        await Appointment.findById(
          bookingId
        );

      if (!appointment) {
        return res.status(404).json({
          success: false,
          message:
            "Booking not found.",
        });
      }

      if (
        appointment.status ===
        "checked-out"
      ) {
        return res.json({
          success: true,
          message:
            "Guest is already checked out.",
          booking: {
            id: appointment._id,
            status:
              appointment.status,
            checkedOutAt:
              appointment.checkedOutAt ||
              appointment.checkOutTime ||
              null,
          },
        });
      }

      if (
        appointment.status !==
        "checked-in"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Guest must be checked in before check-out.",
        });
      }

      appointment.status =
        "checked-out";

      applyStatusTimestamps(
        appointment,
        "checked-out"
      );

      await appointment.save();

      await notifyUser(
        appointment.userId,
        "checked-out",
        "Guest Checked Out",
        "Your resort check-out has been completed.",
        appointment._id
      );

      return res.json({
        success: true,
        message:
          "Guest checked out successfully.",
        booking: {
          id: appointment._id,
          status:
            appointment.status,
          checkedOutAt:
            appointment.checkedOutAt ||
            appointment.checkOutTime ||
            null,
        },
      });
    } catch (error) {
      console.error(
        "Check-out Update Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to update check-out status.",
      });
    }
  }
);

// ============================================================
// ADMIN BOOKING STATUS UPDATE
// ============================================================

router.post(
  "/booking/update-status",
  requireAdminApi,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(req);

      const status =
        normalizeString(
          req.body?.status,
          50
        ).toLowerCase();

      const result =
        await updateStatusInternal({
          bookingId,
          status,
        });

      if (!result.ok) {
        return res
          .status(
            result.statusCode || 400
          )
          .json({
            success: false,
            message:
              result.message,
          });
      }

      return res.json({
        success: true,
        message:
          result.message,

        changed:
          result.changed,

        booking: {
          id:
            result.appointment._id,

          status:
            result.appointment.status,

          checkin:
            result.appointment.checkin,

          checkout:
            result.appointment.checkout,
        },
      });
    } catch (error) {
      console.error(
        "Booking Status Update Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to update booking status.",
      });
    }
  }
);

// ============================================================
// QUICK ACCEPT
// ============================================================

router.post(
  "/booking/accept",
  requireAdminApi,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(req);

      const result =
        await updateStatusInternal({
          bookingId,
          status: "accepted",
        });

      if (!result.ok) {
        return res
          .status(
            result.statusCode || 400
          )
          .json({
            success: false,
            message:
              result.message,
          });
      }

      return res.json({
        success: true,
        message:
          "Booking accepted successfully.",
        booking: {
          id:
            result.appointment._id,
          status:
            result.appointment.status,
        },
      });
    } catch (error) {
      console.error(
        "Quick Accept Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to accept booking.",
      });
    }
  }
);

// ============================================================
// QUICK DECLINE
// ============================================================

router.post(
  "/booking/decline",
  requireAdminApi,
  async (req, res) => {
    try {
      const bookingId =
        getBookingIdFromRequest(req);

      const result =
        await updateStatusInternal({
          bookingId,
          status: "declined",
        });

      if (!result.ok) {
        return res
          .status(
            result.statusCode || 400
          )
          .json({
            success: false,
            message:
              result.message,
          });
      }

      return res.json({
        success: true,
        message:
          "Booking declined successfully.",
        booking: {
          id:
            result.appointment._id,
          status:
            result.appointment.status,
        },
      });
    } catch (error) {
      console.error(
        "Quick Decline Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to decline booking.",
      });
    }
  }
);

// ============================================================
// USERS
// ============================================================

router.get(
  "/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .sort({
            createdAt: -1,
          })
          .lean();

      return res.render(
        "admin/users",
        {
          title: "User Management",
          admin:
            getAdminSession(req),
          users,
        }
      );
    } catch (error) {
      console.error(
        "Users Page Error:",
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

router.get(
  "/users/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const userId =
        getResourceIdFromRequest(req);

      if (!isValidObjectId(userId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid user ID.",
        });
      }

      const user =
        await User.findById(
          userId
        ).lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "User not found.",
        });
      }

      const bookings =
        await Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean();

      return res.json({
        success: true,
        user,
        bookings,
        appointments:
          bookings,
      });
    } catch (error) {
      console.error(
        "User Detail Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load user details.",
      });
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
      const [rooms, bookings] =
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
          title: "Room Management",
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
  requireAdminApi,
  async (req, res) => {
    try {
      const payload =
        buildRoomPayload(req.body);

      if (!payload.name) {
        return res.status(400).json({
          success: false,
          message:
            "Room name is required.",
        });
      }

      const room =
        new Room(payload);

      await room.save();

      return res.status(201).json({
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

      return res.status(500).json({
        success: false,
        message:
          "Unable to create room.",
      });
    }
  }
);

// ============================================================
// UPDATE ROOM
// ============================================================

router.post(
  "/rooms/update/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const roomId =
        getResourceIdFromRequest(req);

      if (!isValidObjectId(roomId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid room ID.",
        });
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (!room) {
        return res.status(404).json({
          success: false,
          message:
            "Room not found.",
        });
      }

      const payload =
        buildRoomPayload(req.body);

      if (
        !payload.name &&
        room.name
      ) {
        payload.name =
          room.name;

        payload.displayName =
          room.displayName ||
          room.name;
      }

      Object.entries(
        payload
      ).forEach(
        ([key, value]) => {
          if (
            room.schema.path(key)
          ) {
            room.set(
              key,
              value
            );
          }
        }
      );

      await room.save();

      return res.json({
        success: true,
        message:
          "Room updated successfully.",
        room,
      });
    } catch (error) {
      console.error(
        "Update Room Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update room.",
      });
    }
  }
);

// Compatibility alias for forms that use
// POST /rooms/update.
router.post(
  "/rooms/update",
  requireAdminApi,
  async (req, res) => {
    try {
      const roomId =
        getResourceIdFromRequest(req);

      if (!isValidObjectId(roomId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid room ID.",
        });
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (!room) {
        return res.status(404).json({
          success: false,
          message:
            "Room not found.",
        });
      }

      const payload =
        buildRoomPayload(req.body);

      if (
        !payload.name &&
        room.name
      ) {
        payload.name =
          room.name;

        payload.displayName =
          room.displayName ||
          room.name;
      }

      Object.entries(
        payload
      ).forEach(
        ([key, value]) => {
          if (
            room.schema.path(key)
          ) {
            room.set(
              key,
              value
            );
          }
        }
      );

      await room.save();

      return res.json({
        success: true,
        message:
          "Room updated successfully.",
        room,
      });
    } catch (error) {
      console.error(
        "Update Room Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update room.",
      });
    }
  }
);

// ============================================================
// DELETE / DEACTIVATE ROOM
// ============================================================

router.post(
  "/rooms/delete/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const roomId =
        getResourceIdFromRequest(req);

      if (!isValidObjectId(roomId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid room ID.",
        });
      }

      const room =
        await getRoomDocumentById(
          roomId
        );

      if (!room) {
        return res.status(404).json({
          success: false,
          message:
            "Room not found.",
        });
      }

      const hasFutureOrActiveBookings =
        await Appointment.exists({
          room:
            pickFirst(
              room,
              [
                "name",
                "displayName",
                "key",
              ],
              ""
            ),
          status: {
            $in:
              BLOCKING_STATUSES,
          },
          checkout: {
            $gte: new Date(),
          },
        });

      if (
        hasFutureOrActiveBookings
      ) {
        return res.status(409).json({
          success: false,
          message:
            "This room has an active or future booking and cannot be deleted.",
        });
      }

      if (
        modelHasPath(
          Room,
          "active"
        )
      ) {
        room.active = false;
        await room.save();
      } else if (
        modelHasPath(
          Room,
          "isActive"
        )
      ) {
        room.isActive = false;
        await room.save();
      } else {
        await room.deleteOne();
      }

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

      return res.status(500).json({
        success: false,
        message:
          "Unable to remove room.",
      });
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
      const [rawAddOns, rooms] =
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

      // IMPORTANT:
      // The existing project view is add-on.ejs,
      // not add-ons.ejs.
      return res.render(
        "admin/add-on",
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
  requireAdminApi,
  async (req, res) => {
    try {
      const payload =
        buildAddOnPayload(
          req.body
        );

      if (!payload.name) {
        return res.status(400).json({
          success: false,
          message:
            "Add-on name is required.",
        });
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
        "Create Add-on Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create add-on.",
      });
    }
  }
);

// ============================================================
// UPDATE ADD-ON
// ============================================================

router.post(
  "/add-ons/update/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const addOnId =
        getResourceIdFromRequest(
          req
        );

      if (!isValidObjectId(addOnId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid add-on ID.",
        });
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (!addOn) {
        return res.status(404).json({
          success: false,
          message:
            "Add-on not found.",
        });
      }

      const payload =
        buildAddOnPayload(
          req.body
        );

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

      return res.json({
        success: true,
        message:
          "Add-on updated successfully.",
        addOn,
      });
    } catch (error) {
      console.error(
        "Update Add-on Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update add-on.",
      });
    }
  }
);

router.post(
  "/add-ons/update",
  requireAdminApi,
  async (req, res) => {
    try {
      const id =
        getResourceIdFromRequest(
          req
        );

      if (!isValidObjectId(id)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid add-on ID.",
        });
      }

      const addOn =
        await AddOn.findById(
          id
        );

      if (!addOn) {
        return res.status(404).json({
          success: false,
          message:
            "Add-on not found.",
        });
      }

      const payload =
        buildAddOnPayload(
          req.body
        );

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

      return res.json({
        success: true,
        message:
          "Add-on updated successfully.",
        addOn,
      });
    } catch (error) {
      console.error(
        "Update Add-on Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update add-on.",
      });
    }
  }
);

// ============================================================
// DELETE / DEACTIVATE ADD-ON
// ============================================================

router.post(
  "/add-ons/delete/:id",
  requireAdminApi,
  async (req, res) => {
    try {
      const addOnId =
        getResourceIdFromRequest(
          req
        );

      if (!isValidObjectId(addOnId)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid add-on ID.",
        });
      }

      const addOn =
        await AddOn.findById(
          addOnId
        );

      if (!addOn) {
        return res.status(404).json({
          success: false,
          message:
            "Add-on not found.",
        });
      }

      if (
        modelHasPath(
          AddOn,
          "active"
        )
      ) {
        addOn.active = false;
        await addOn.save();
      } else if (
        modelHasPath(
          AddOn,
          "isActive"
        )
      ) {
        addOn.isActive = false;
        await addOn.save();
      } else {
        await addOn.deleteOne();
      }

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

      return res.status(500).json({
        success: false,
        message:
          "Unable to remove add-on.",
      });
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

      return res.status(500).json({
        success: false,
        message:
          "Unable to load room information.",
      });
    }
  }
);

// ============================================================
// ADMIN LOGOUT
// ============================================================

router.get(
  "/logout",
  async (req, res) => {
    try {
      await new Promise(
        (resolve) => {
          req.session.destroy(
            (error) => {
              if (error) {
                console.error(
                  "Admin Logout Error:",
                  error
                );
              }

              resolve();
            }
          );
        }
      );

      return res.redirect(
        "/admin/login"
      );
    } catch (error) {
      console.error(
        "Admin Logout Error:",
        error
      );

      return res.redirect(
        "/admin/login"
      );
    }
  }
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
      return res.status(404).json({
        success: false,
        message:
          "Admin API route not found.",
      });
    }

    next();
  }
);

// ============================================================
// ROUTER EXPORT
// ============================================================

module.exports = router;