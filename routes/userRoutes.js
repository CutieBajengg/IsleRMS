"use strict";

/**
 * Puffer Isle Resort | IsleRMS | Customer Routes
 * Mounted by server.js at "/".
 *
 * Responsibilities:
 * - Customer profile/dashboard
 * - Booking catalog and submission
 * - Customer booking history/cancellation
 * - Notification center
 * - Password changes
 *
 * Security:
 * - Identity comes from the authenticated session.
 * - Customer resources are always scoped by userId.
 * - Client totalPrice is never trusted.
 * - Appointment adminNotes are never exposed to customers.
 */

const express = require("express");
const mongoose = require("mongoose");

const router = express.Router();

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Notification = require("../models/Notification");
const Room = require("../models/Room");
const AddOn = require("../models/AddOn");

const BLOCKING_STATUSES =
  typeof Appointment.getBlockingStatuses === "function"
    ? Appointment.getBlockingStatuses()
    : ["pending", "accepted", "confirmed", "checked-in"];

const CANCELLABLE_STATUSES =
  typeof Appointment.getCancellableStatuses === "function"
    ? Appointment.getCancellableStatuses()
    : ["pending", "accepted", "confirmed"];

const ALL_BOOKING_STATUSES =
  typeof Appointment.getAllStatuses === "function"
    ? Appointment.getAllStatuses()
    : [
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

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_BOOKING_NIGHTS = 365;
const MAX_SPECIAL_REQUESTS = 1000;
const MAX_CONTACT_LENGTH = 40;

/* ============================================================
   GENERIC HELPERS
============================================================ */

function isValidObjectId(value) {
  return mongoose.Types.ObjectId.isValid(value);
}

function clean(value, max = 500) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, max);
}

function number(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function integer(value, fallback = 0) {
  return Math.floor(number(value, fallback));
}

function boolean(value) {
  if (typeof value === "boolean") {
    return value;
  }

  return ["true", "1", "yes", "on"].includes(
    String(value ?? "")
      .trim()
      .toLowerCase()
  );
}

function page(value) {
  return Math.max(
    1,
    integer(value, DEFAULT_PAGE)
  );
}

function limit(value) {
  return Math.min(
    MAX_LIMIT,
    Math.max(
      1,
      integer(value, DEFAULT_LIMIT)
    )
  );
}

function wantsJson(req) {
  return Boolean(
    req.path.startsWith("/api/") ||
      req.xhr ||
      req.headers.accept?.includes(
        "application/json"
      )
  );
}

function queryRedirect(
  path,
  key,
  message
) {
  return (
    `${path}?${key}=` +
    encodeURIComponent(message)
  );
}

function sessionUserId(req) {
  return (
    req.session?.user?.id ||
    req.session?.user?._id ||
    req.session?.user?.userId ||
    null
  );
}

function jsonError(
  res,
  status,
  message,
  code
) {
  return res
    .status(status)
    .json({
      success: false,
      ...(code ? { code } : {}),
      message,
    });
}

function destroySession(req) {
  return new Promise((resolve) => {
    if (!req.session) {
      return resolve();
    }

    req.session.destroy(() => resolve());
  });
}

function saveSession(req) {
  return new Promise(
    (resolve, reject) => {
      req.session.save(
        (error) => {
          if (error) {
            return reject(error);
          }

          resolve();
        }
      );
    }
  );
}

function safeSessionUser(user) {
  return {
    id: String(user._id),

    username:
      user.username ||
      (
        user.email
          ? String(user.email).split("@")[0]
          : "guest"
      ),

    email:
      user.email || "",

    name:
      user.fullname ||
      user.name ||
      "",
  };
}

function serializeUser(user) {
  return {
    id: String(user._id),

    fullname:
      user.fullname || "",

    username:
      user.username || "",

    email:
      user.email || "",

    phone:
      user.phone || "",

    status:
      user.status || "active",

    emailVerified:
      Boolean(user.emailVerified),

    memberLevel:
      user.memberLevel ||
      "Resort Member",

    createdAt:
      user.createdAt || null,
  };
}

function serializeAppointment(
  appointment
) {
  if (!appointment) {
    return null;
  }

  const data =
    typeof appointment.toObject ===
    "function"
      ? appointment.toObject()
      : { ...appointment };

  // Internal staff information must not
  // be exposed to customers.
  delete data.adminNotes;

  delete data.userId;

  return data;
}

/* ============================================================
   AUTHENTICATION
============================================================ */

function requireLogin(
  req,
  res,
  next
) {
  const id =
    sessionUserId(req);

  if (
    !req.session?.user ||
    !id ||
    !isValidObjectId(id)
  ) {
    if (
      wantsJson(req)
    ) {
      return jsonError(
        res,
        401,
        "Your session has expired. Please log in again.",
        "AUTHENTICATION_REQUIRED"
      );
    }

    return res.redirect(
      "/?error=" +
        encodeURIComponent(
          "Please log in to continue."
        )
    );
  }

  next();
}

async function currentUser(
  req,
  res
) {
  const id =
    sessionUserId(req);

  if (
    !id ||
    !isValidObjectId(id)
  ) {
    await destroySession(req);

    if (
      wantsJson(req)
    ) {
      jsonError(
        res,
        401,
        "Your session is no longer valid. Please log in again.",
        "INVALID_SESSION"
      );
    } else {
      res.redirect(
        "/?error=" +
          encodeURIComponent(
            "Your session is no longer valid. Please log in again."
          )
      );
    }

    return null;
  }

  const user =
    await User.findById(id)
      .select("-password")
      .lean();

  if (!user) {
    await destroySession(req);

    if (
      wantsJson(req)
    ) {
      jsonError(
        res,
        401,
        "Your account session is no longer valid.",
        "INVALID_SESSION"
      );
    } else {
      res.redirect("/");
    }

    return null;
  }

  const status =
    String(
      user.status ||
        "active"
    ).toLowerCase();

  if (
    status !== "active"
  ) {
    await destroySession(req);

    const message =
      status === "suspended"
        ? "Your account is currently suspended."
        : "Your account is currently unavailable.";

    if (
      wantsJson(req)
    ) {
      jsonError(
        res,
        403,
        message,
        "ACCOUNT_UNAVAILABLE"
      );
    } else {
      res.redirect(
        queryRedirect(
          "/",
          "error",
          message
        )
      );
    }

    return null;
  }

  return user;
}

/* ============================================================
   DATES / CONTACT
============================================================ */

function parseBookingDate(
  value
) {
  const raw =
    String(value ?? "")
      .trim();

  if (!raw) {
    return null;
  }

  /*
   * Booking forms normally submit
   * YYYY-MM-DD. Parse this explicitly
   * to avoid timezone surprises.
   */
  if (
    /^\d{4}-\d{2}-\d{2}$/.test(raw)
  ) {
    const [
      year,
      month,
      day,
    ] =
      raw
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
    new Date(raw);

  return Number.isNaN(
    date.getTime()
  )
    ? null
    : date;
}

function validateDates(
  checkinValue,
  checkoutValue
) {
  const start =
    parseBookingDate(
      checkinValue
    );

  const end =
    parseBookingDate(
      checkoutValue
    );

  if (
    !start ||
    !end
  ) {
    return {
      valid: false,
      message:
        "Please provide valid check-in and check-out dates.",
    };
  }

  if (
    end <= start
  ) {
    return {
      valid: false,
      message:
        "Check-out must be after check-in.",
    };
  }

  const nights =
    Math.round(
      (
        end.getTime() -
        start.getTime()
      ) /
        (
          1000 *
          60 *
          60 *
          24
        )
    );

  if (
    nights < 1
  ) {
    return {
      valid: false,
      message:
        "Your stay must be at least one night.",
    };
  }

  if (
    nights >
    MAX_BOOKING_NIGHTS
  ) {
    return {
      valid: false,
      message:
        `Reservations cannot exceed ${MAX_BOOKING_NIGHTS} nights online.`,
    };
  }

  return {
    valid: true,
    start,
    end,
    nights,
  };
}

function dateIsInPast(
  date
) {
  const now =
    new Date();

  const todayStart =
    new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate()
    );

  return (
    date <
    todayStart
  );
}

function dateLabel(
  value
) {
  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "";
  }

  return date.toLocaleDateString(
    "en-US",
    {
      month: "short",
      day: "numeric",
      year: "numeric",
    }
  );
}

function validateContact(
  value
) {
  const contact =
    clean(
      value,
      MAX_CONTACT_LENGTH
    ).replace(
      /[^0-9+()\-\s]/g,
      ""
    );

  const digits =
    contact.replace(
      /\D/g,
      ""
    );

  if (
    digits.length <
      7 ||
    digits.length >
      15
  ) {
    return {
      valid: false,
      message:
        "Please provide a valid contact number.",
    };
  }

  return {
    valid: true,
    value: contact,
  };
}

/* ============================================================
   CATALOG
============================================================ */

async function getActiveRooms() {
  return Room.find({
    active: true,
  })
    .sort({
      sortOrder: 1,
      name: 1,
    })
    .lean();
}

async function findRoom(
  selection
) {
  const requested =
    clean(
      selection,
      150
    );

  if (
    !requested
  ) {
    return null;
  }

  if (
    isValidObjectId(
      requested
    )
  ) {
    const room =
      await Room.findOne({
        _id: requested,
        active: true,
      }).lean();

    if (room) {
      return room;
    }
  }

  return Room.findOne({
    active: true,
    $or: [
      {
        slug:
          requested.toLowerCase(),
      },
      {
        name:
          requested,
      },
    ],
  }).lean();
}

function roomResponse(room) {
  return {
    _id: String(room._id),
    id: String(room._id),

    name:
      room.name || "",

    slug:
      room.slug || "",

    price:
      number(room.price),

    maxGuests:
      Math.max(
        1,
        integer(
          room.maxGuests,
          1
        )
      ),

    quantity:
      Math.max(
        0,
        integer(
          room.quantity,
          1
        )
      ),

    image:
      room.image || "",

    description:
      room.description || "",

    active:
      room.active !== false,

    sortOrder:
      integer(
        room.sortOrder,
        0
      ),
  };
}

async function getActiveAddOns() {
  return AddOn.find({
    active: true,
  })
    .sort({
      sortOrder: 1,
      name: 1,
    })
    .lean();
}

async function findAddOn(
  selection
) {
  const requested =
    clean(
      selection,
      150
    );

  if (
    !requested
  ) {
    return null;
  }

  if (
    isValidObjectId(
      requested
    )
  ) {
    const addOn =
      await AddOn.findOne({
        _id: requested,
        active: true,
      }).lean();

    if (addOn) {
      return addOn;
    }
  }

  return AddOn.findOne({
    active: true,

    $or: [
      {
        slug:
          requested.toLowerCase(),
      },
      {
        name:
          requested,
      },
    ],
  }).lean();
}

function addOnResponse(
  addOn
) {
  return {
    id:
      String(addOn._id),

    name:
      addOn.name || "",

    slug:
      addOn.slug || "",

    price:
      number(addOn.price),

    pricingType:
      addOn.pricingType ||
      "once",

    image:
      addOn.image || "",

    description:
      addOn.description || "",

    active:
      addOn.active !== false,

    sortOrder:
      integer(
        addOn.sortOrder,
        0
      ),
  };
}

function normalizeAddOnSelections(
  body
) {
  const values = [];

  for (
    const item of [
      body?.addOns,
      body?.addOnIds,
      body?.addonIds,
      body?.addOn,
      body?.addon,
    ]
  ) {
    if (
      Array.isArray(item)
    ) {
      values.push(
        ...item
      );
    } else if (
      item !==
        undefined &&
      item !==
        null &&
      String(item).trim()
        !== ""
    ) {
      values.push(
        ...String(item)
          .split(",")
      );
    }
  }

  return [
    ...new Set(
      values
        .map(
          (value) =>
            clean(
              value,
              150
            )
        )
        .filter(
          Boolean
        )
    ),
  ];
}

async function resolveLegacyCottage(
  body
) {
  if (
    !(
      boolean(
        body?.cottageAddon
      ) ||
      boolean(
        body?.cottage
      )
    )
  ) {
    return null;
  }

  return AddOn.findOne({
    active: true,
    $or: [
      {
        slug: {
          $in: [
            "seaside-cottage",
            "cottage",
          ],
        },
      },
      {
        name: {
          $regex:
            /seaside\s+cottage|cottage/i,
        },
      },
    ],
  })
    .sort({
      sortOrder: 1,
      name: 1,
    })
    .lean();
}

/* ============================================================
   AVAILABILITY
============================================================ */

async function findAvailabilityConflict({
  room,
  checkin,
  checkout,
  excludeAppointmentId = null,
}) {
  if (!room?._id) {
    return null;
  }

  const quantity =
    room.quantity ===
      undefined ||
    room.quantity ===
      null
      ? 1
      : integer(
          room.quantity,
          0
        );

  if (
    quantity <= 0
  ) {
    return {
      reason:
        "NO_INVENTORY",
    };
  }

  const roomRegex =
    room.name
      ? new RegExp(
          `^${String(room.name).replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&"
          )}$`,
          "i"
        )
      : null;

  const roomConditions = [
    {
      roomId:
        room._id,
    },
  ];

  if (
    roomRegex
  ) {
    roomConditions.push(
      {
        room:
          roomRegex,
      },
      {
        roomType:
          roomRegex,
      },
      {
        accommodation:
          roomRegex,
      },
      {
        roomName:
          roomRegex,
      }
    );
  }

  const query = {
    status: {
      $in:
        BLOCKING_STATUSES,
    },

    checkin: {
      $lt:
        checkout,
    },

    checkout: {
      $gt:
        checkin,
    },

    $or:
      roomConditions,
  };

  if (
    excludeAppointmentId &&
    isValidObjectId(
      excludeAppointmentId
    )
  ) {
    query._id = {
      $ne:
        excludeAppointmentId,
    };
  }

  const appointments =
    await Appointment.find(
      query
    )
      .select(
        "_id roomId room roomType accommodation roomName checkin checkout status"
      )
      .sort({
        checkin: 1,
        checkout: 1,
      })
      .lean();

  const events = [];

  for (
    const appointment of
      appointments
  ) {
    const start =
      new Date(
        appointment.checkin
      );

    const end =
      new Date(
        appointment.checkout
      );

    if (
      Number.isNaN(
        start.getTime()
      ) ||
      Number.isNaN(
        end.getTime()
      ) ||
      end <= start
    ) {
      continue;
    }

    const overlapStart =
      start > checkin
        ? start
        : checkin;

    const overlapEnd =
      end < checkout
        ? end
        : checkout;

    if (
      overlapEnd <=
      overlapStart
    ) {
      continue;
    }

    events.push({
      time:
        overlapStart.getTime(),

      delta: 1,

      appointment,
    });

    events.push({
      time:
        overlapEnd.getTime(),

      delta: -1,

      appointment,
    });
  }

  events.sort(
    (a, b) =>
      a.time !== b.time
        ? a.time - b.time
        : a.delta - b.delta
  );

  let occupancy = 0;

  for (
    const event of events
  ) {
    occupancy +=
      event.delta;

    if (
      occupancy >=
      quantity
    ) {
      return event.appointment;
    }
  }

  return null;
}

/* ============================================================
   PRICING / NOTIFICATIONS
============================================================ */

async function calculateBookingPrice({
  room,
  addOnSelections,
  checkin,
  checkout,
}) {
  if (
    typeof Appointment.calculateSnapshotPrice !==
    "function"
  ) {
    return {
      valid: false,
      error:
        "Booking pricing is not configured correctly.",
    };
  }

  const nights =
    getNumberOfNights(
      checkin,
      checkout
    );

  if (
    nights < 1
  ) {
    return {
      valid: false,
      error:
        "Your stay must be at least one night.",
    };
  }

  const resolved =
    await Promise.all(
      addOnSelections.map(
        (selection) =>
          findAddOn(
            selection
          )
      )
    );

  if (
    resolved.some(
      (addOn) =>
        !addOn
    )
  ) {
    return {
      valid: false,
      error:
        "One of the selected add-ons is no longer available.",
    };
  }

  const unique =
    new Map(
      resolved.map(
        (addOn) => [
          String(
            addOn._id
          ),
          addOn,
        ]
      )
    );

  const snapshots =
    [
      ...unique.values(),
    ].map(
      (addOn) => ({
        addOnId:
          addOn._id,

        name:
          addOn.name,

        price:
          number(
            addOn.price
          ),

        pricingType:
          addOn.pricingType ||
          "once",

        quantity: 1,
      })
    );

  const pricing =
    Appointment.calculateSnapshotPrice(
      {
        roomPrice:
          number(
            room.price
          ),

        numberOfNights:
          nights,

        addOns:
          snapshots,
      }
    );

  return {
    valid: true,

    nights,

    roomPrice:
      pricing.roomPrice,

    roomSubtotal:
      pricing.roomSubtotal,

    addOns:
      pricing.addOns,

    addOnSubtotal:
      pricing.addOnSubtotal,

    totalPrice:
      pricing.totalPrice,
  };
}

function getNumberOfNights(
  checkin,
  checkout
) {
  return Math.round(
    (
      new Date(
        checkout
      ).getTime() -
      new Date(
        checkin
      ).getTime()
    ) /
      (
        1000 *
        60 *
        60 *
        24
      )
  );
}

async function createAppointmentNotification({
  userId,
  appointmentId,
  event,
  title,
  message,
  priority = "normal",
  metadata,
}) {
  try {
    if (
      typeof Notification.createAppointmentNotification ===
      "function"
    ) {
      return await Notification.createAppointmentNotification(
        {
          userId,

          appointmentId,

          event,

          title,

          message,

          priority,

          actionLabel:
            "View My Bookings",

          actionUrl:
            "/profile#bookings",

          metadata,
        }
      );
    }

    return await Notification.create({
      userId,

      appointmentId:
        appointmentId ||
        null,

      bookingId:
        appointmentId ||
        null,

      type:
        "appointment",

      event,

      title,

      message,

      priority,

      actionLabel:
        "View My Bookings",

      actionUrl:
        "/profile#bookings",

      metadata,
    });
  } catch (error) {
    /*
     * A notification failure must not
     * break the primary business action.
     */
    console.error(
      "Notification creation error:",
      error.message
    );

    return null;
  }
}

/* ============================================================
   BOOKING PAGE
============================================================ */

router.get(
  "/booking",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const [
        appointments,
        rooms,
        addOns,
      ] = await Promise.all([
        Appointment.find({
          userId:
            user._id,
        })
          .select(
            "-adminNotes"
          )
          .sort({
            createdAt: -1,
          })
          .lean(),

        getActiveRooms(),

        getActiveAddOns(),
      ]);

      return res.render(
        "appointments",
        {
          title:
            "Book Your Stay",

          user,

          appointments,

          rooms:
            rooms.map(
              roomResponse
            ),

          addOns:
            addOns.map(
              addOnResponse
            ),

          cottage:
            addOns.find(
              (addOn) =>
                /cottage/i.test(
                  addOn.name ||
                    ""
                )
            ) ||
            null,

          error:
            req.query.error ||
            null,

          success:
            req.query.success ||
            null,

          csrfToken:
            res.locals.csrfToken ||
            null,
        }
      );
    } catch (error) {
      console.error(
        "Booking Page Error:",
        error
      );

      return res
        .status(500)
        .render(
          "error",
          {
            title:
              "Booking Error",

            message:
              "Failed to load the booking page.",
          }
        );
    }
  }
);

/* ============================================================
   PROFILE PAGE
============================================================ */

router.get(
  "/profile",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const [
        appointments,
        notifications,
        totalBookings,
        unreadNotifications,
      ] = await Promise.all([
        Appointment.find({
          userId:
            user._id,
        })
          .select(
            "-adminNotes"
          )
          .sort({
            createdAt: -1,
          })
          .limit(100)
          .lean(),

        Notification.find({
          userId:
            user._id,

          archived:
            false,
        })
          .sort({
            createdAt: -1,
          })
          .limit(100)
          .lean(),

        Appointment.countDocuments({
          userId:
            user._id,
        }),

        Notification.countDocuments({
          userId:
            user._id,

          archived:
            false,

          read:
            false,
        }),
      ]);

      return res.render(
        "profile",
        {
          title:
            `${user.fullname || "User"} | Isle RMS Profile`,

          user,

          appointments,

          notifications,

          stats: {
            totalBookings,

            unreadNotifications,
          },

          csrfToken:
            res.locals.csrfToken ||
            null,
        }
      );
    } catch (error) {
      console.error(
        "Profile Error:",
        error
      );

      return res
        .status(500)
        .render(
          "error",
          {
            title:
              "Profile Error",

            message:
              "An error occurred while loading your profile.",
          }
        );
    }
  }
);

/* ============================================================
   LEGACY PROFILE BY ID
============================================================ */

router.get(
  "/profile/:id",
  requireLogin,
  async (req, res) => {
    const requested =
      String(
        req.params.id ||
          ""
      ).trim();

    const id =
      sessionUserId(
        req
      );

    if (
      !isValidObjectId(
        requested
      )
    ) {
      return res
        .status(400)
        .render(
          "error",
          {
            title:
              "Invalid Request",

            message:
              "Invalid user ID.",
          }
        );
    }

    if (
      String(id) !==
      requested
    ) {
      return res
        .status(403)
        .render(
          "error",
          {
            title:
              "Unauthorized",

            message:
              "You are not authorized to view this profile.",
          }
        );
    }

    return res.redirect(
      "/profile"
    );
  }
);

/* ============================================================
   SUBMIT BOOKING
============================================================ */

async function submitBooking(
  req,
  res
) {
  const json =
    wantsJson(req);

  try {
    const user =
      await currentUser(
        req,
        res
      );

    if (!user) {
      return;
    }

    const roomSelection =
      clean(
        req.body?.room ||
          req.body?.roomId ||
          req.body?.roomType ||
          req.body?.accommodation,
        150
      );

    const guests =
      integer(
        req.body?.guests,
        0
      );

    const contact =
      validateContact(
        req.body?.contact ||
          req.body?.phone ||
          req.body?.contactNumber
      );

    const checkinValue =
      req.body?.checkin ||
      req.body?.checkIn ||
      req.body?.checkInDate;

    const checkoutValue =
      req.body?.checkout ||
      req.body?.checkOut ||
      req.body?.checkOutDate;

    const specialRequests =
      clean(
        req.body?.specialRequests,
        MAX_SPECIAL_REQUESTS
      );

    if (
      !roomSelection ||
      guests < 1 ||
      !contact.valid ||
      !checkinValue ||
      !checkoutValue
    ) {
      const message =
        !contact.valid
          ? contact.message
          : "Please complete all required booking fields.";

      return json
        ? jsonError(
            res,
            400,
            message,
            "MISSING_BOOKING_FIELDS"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    const dates =
      validateDates(
        checkinValue,
        checkoutValue
      );

    if (
      !dates.valid
    ) {
      return json
        ? jsonError(
            res,
            400,
            dates.message,
            "INVALID_DATES"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              dates.message
            )
          );
    }

    if (
      dateIsInPast(
        dates.start
      )
    ) {
      const message =
        "Check-in cannot be in the past.";

      return json
        ? jsonError(
            res,
            400,
            message,
            "PAST_DATE"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    const room =
      await findRoom(
        roomSelection
      );

    if (!room) {
      const message =
        "The selected accommodation is not available.";

      return json
        ? jsonError(
            res,
            400,
            message,
            "INVALID_ROOM"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    const quantity =
      room.quantity ===
        undefined ||
      room.quantity ===
        null
        ? 1
        : integer(
            room.quantity,
            0
          );

    if (
      quantity <= 0
    ) {
      const message =
        "The selected accommodation is currently unavailable.";

      return json
        ? jsonError(
            res,
            409,
            message,
            "NO_INVENTORY"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    const maxGuests =
      Math.max(
        1,
        integer(
          room.maxGuests,
          1
        )
      );

    if (
      guests >
      maxGuests
    ) {
      const message =
        `The selected room allows a maximum of ${maxGuests} guests.`;

      return json
        ? jsonError(
            res,
            400,
            message,
            "INVALID_GUEST_COUNT"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    let addOnSelections =
      normalizeAddOnSelections(
        req.body ||
          {}
      );

    /*
     * Legacy cottage support.
     */
    const legacyCottage =
      await resolveLegacyCottage(
        req.body ||
          {}
      );

    if (
      legacyCottage
    ) {
      const duplicate =
        addOnSelections.some(
          (selection) =>
            String(
              selection
            ).toLowerCase() ===
              String(
                legacyCottage._id
              ).toLowerCase() ||

            String(
              selection
            ).toLowerCase() ===
              String(
                legacyCottage.slug ||
                  ""
              ).toLowerCase() ||

            String(
              selection
            ).toLowerCase() ===
              String(
                legacyCottage.name ||
                  ""
              ).toLowerCase()
        );

      if (
        !duplicate
      ) {
        addOnSelections.push(
          String(
            legacyCottage._id
          )
        );
      }
    }

    /*
     * Inventory validation.
     */
    const conflict =
      await findAvailabilityConflict(
        {
          room,

          checkin:
            dates.start,

          checkout:
            dates.end,
        }
      );

    if (
      conflict
    ) {
      const message =
        conflict.reason ===
        "NO_INVENTORY"
          ? "The selected accommodation is currently unavailable."
          : "This accommodation is already reserved for your selected dates. Please choose different dates.";

      return json
        ? jsonError(
            res,
            409,
            message,
            "ROOM_UNAVAILABLE"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              message
            )
          );
    }

    /*
     * Server-side pricing.
     * req.body.totalPrice is intentionally ignored.
     */
    const pricing =
      await calculateBookingPrice(
        {
          room,

          addOnSelections,

          checkin:
            dates.start,

          checkout:
            dates.end,
        }
      );

    if (
      !pricing.valid
    ) {
      return json
        ? jsonError(
            res,
            400,
            pricing.error,
            "PRICING_ERROR"
          )
        : res.redirect(
            queryRedirect(
              "/booking",
              "error",
              pricing.error
            )
          );
    }

    const cottageSnapshot =
      pricing.addOns.find(
        (addOn) =>
          /cottage/i.test(
            String(
              addOn.name ||
                ""
            )
          )
      );

    /*
     * Create historical pricing snapshots.
     */
    const appointment =
      new Appointment({
        userId:
          user._id,

        roomId:
          room._id,

        room:
          room.name,

        roomType:
          room.name,

        accommodation:
          room.name,

        roomName:
          room.name,

        roomPrice:
          pricing.roomPrice,

        numberOfNights:
          pricing.nights,

        roomSubtotal:
          pricing.roomSubtotal,

        addOns:
          pricing.addOns,

        addOnSubtotal:
          pricing.addOnSubtotal,

        /*
         * Legacy cottage compatibility.
         */
        cottageAddon:
          Boolean(
            cottageSnapshot
          ),

        cottagePrice:
          cottageSnapshot?.price ||
          0,

        cottageSubtotal:
          cottageSnapshot?.subtotal ||
          0,

        guests,

        contact:
          contact.value,

        checkin:
          dates.start,

        checkout:
          dates.end,

        specialRequests,

        totalPrice:
          pricing.totalPrice,

        status:
          "pending",
      });

    await appointment.save();

    /*
     * Customer confirmation notification.
     */
    await createAppointmentNotification({
      userId:
        user._id,

      appointmentId:
        appointment._id,

      event:
        "created",

      title:
        "Reservation Request Received",

      message:
        `Your reservation request for ${room.name} ` +
        `from ${dateLabel(
          dates.start
        )} to ${dateLabel(
          dates.end
        )} has been received and is awaiting confirmation.`,

      metadata: {
        roomName:
          room.name,

        checkin:
          dates.start,

        checkout:
          dates.end,

        guests,

        totalPrice:
          appointment.totalPrice,

        status:
          appointment.status,
      },
    });

    const booking = {
      id:
        String(
          appointment._id
        ),

      room:
        appointment.room,

      roomId:
        String(
          appointment.roomId
        ),

      checkin:
        appointment.checkin,

      checkout:
        appointment.checkout,

      guests:
        appointment.guests,

      numberOfNights:
        appointment.numberOfNights,

      addOns:
        appointment.addOns,

      totalPrice:
        appointment.totalPrice,

      status:
        appointment.status,

      createdAt:
        appointment.createdAt,
    };

    if (json) {
      return res
        .status(201)
        .json({
          success:
            true,

          message:
            "Your reservation request was submitted successfully.",

          booking,
        });
    }

    return res.redirect(
      queryRedirect(
        "/profile",
        "success",
        "Your reservation request was submitted successfully."
      )
    );
  } catch (error) {
    console.error(
      "Appointment Submission Error:",
      error
    );

    const validationMessage =
      error?.name ===
      "ValidationError"
        ? Object.values(
            error.errors ||
              {}
          )
            .map(
              (entry) =>
                entry.message
            )
            .filter(Boolean)
            .join(" ")
        : null;

    const message =
      validationMessage ||
      (
        error?.code ===
        11000
          ? "This booking conflicts with a reservation created at the same time. Please choose different dates."
          : "Failed to submit your booking. Please try again."
      );

    const code =
      error?.name ===
      "ValidationError"
        ? "VALIDATION_ERROR"
        : error?.code ===
          11000
        ? "BOOKING_CONFLICT"
        : "BOOKING_ERROR";

    const statusCode =
      error?.name ===
      "ValidationError"
        ? 400
        : error?.code ===
          11000
        ? 409
        : 500;

    return json
      ? jsonError(
          res,
          statusCode,
          message,
          code
        )
      : res.redirect(
          queryRedirect(
            "/booking",
            "error",
            message
          )
        );
  }
}

router.post(
  "/appointment/submit",
  requireLogin,
  submitBooking
);

router.post(
  "/booking/submit",
  requireLogin,
  submitBooking
);

/* ============================================================
   CUSTOMER PROFILE API
============================================================ */

router.get(
  "/api/me",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      return res.json({
        success:
          true,

        user:
          serializeUser(
            user
          ),
      });
    } catch (error) {
      console.error(
        "GET /api/me error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load your account information."
      );
    }
  }
);

/* ============================================================
   CUSTOMER DASHBOARD API
============================================================ */

router.get(
  "/api/me/dashboard",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const activeStatuses = [
        "pending",
        "accepted",
        "confirmed",
        "checked-in",
      ];

      const today =
        new Date();

      today.setHours(
        0,
        0,
        0,
        0
      );

      const [
        totalBookings,
        activeBookings,
        upcomingBookings,
        unreadNotifications,
        totalNotifications,
        recentBookings,
        recentNotifications,
      ] =
        await Promise.all([
          Appointment.countDocuments({
            userId:
              user._id,
          }),

          Appointment.countDocuments({
            userId:
              user._id,

            status: {
              $in:
                activeStatuses,
            },
          }),

          Appointment.countDocuments({
            userId:
              user._id,

            status: {
              $in:
                activeStatuses,
            },

            checkin: {
              $gte:
                today,
            },
          }),

          Notification.countDocuments({
            userId:
              user._id,

            archived:
              false,

            read:
              false,
          }),

          Notification.countDocuments({
            userId:
              user._id,

            archived:
              false,
          }),

          Appointment.find({
            userId:
              user._id,
          })
            .select(
              "-adminNotes"
            )
            .sort({
              createdAt: -1,
            })
            .limit(10)
            .lean(),

          Notification.find({
            userId:
              user._id,

            archived:
              false,
          })
            .sort({
              createdAt: -1,
            })
            .limit(10)
            .lean(),
        ]);

      return res.json({
        success:
          true,

        user:
          serializeUser(
            user
          ),

        stats: {
          totalBookings,

          activeBookings,

          upcomingBookings,

          unreadNotifications,

          totalNotifications,
        },

        recentBookings:
          recentBookings.map(
            serializeAppointment
          ),

        recentNotifications,
      });
    } catch (error) {
      console.error(
        "GET /api/me/dashboard error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load your dashboard."
      );
    }
  }
);

/* ============================================================
   CUSTOMER BOOKINGS API
============================================================ */

router.get(
  "/api/me/bookings",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const currentPage =
        page(
          req.query.page
        );

      const currentLimit =
        limit(
          req.query.limit
        );

      const filter = {
        userId:
          user._id,
      };

      if (
        req.query.status
      ) {
        const status =
          String(
            req.query.status
          )
            .trim()
            .toLowerCase();

        if (
          !ALL_BOOKING_STATUSES.includes(
            status
          )
        ) {
          return jsonError(
            res,
            400,
            "Invalid booking status.",
            "INVALID_STATUS"
          );
        }

        filter.status =
          status;
      }

      const [
        total,
        bookings,
      ] = await Promise.all([
        Appointment.countDocuments(
          filter
        ),

        Appointment.find(
          filter
        )
          .select(
            "-adminNotes"
          )
          .sort({
            createdAt: -1,
          })
          .skip(
            (
              currentPage -
              1
            ) *
              currentLimit
          )
          .limit(
            currentLimit
          )
          .lean(),
      ]);

      const totalPages =
        Math.max(
          1,
          Math.ceil(
            total /
              currentLimit
          )
        );

      return res.json({
        success:
          true,

        bookings:
          bookings.map(
            serializeAppointment
          ),

        pagination: {
          page:
            currentPage,

          limit:
            currentLimit,

          total,

          totalPages,

          hasNextPage:
            currentPage <
            totalPages,

          hasPreviousPage:
            currentPage >
            1,
        },
      });
    } catch (error) {
      console.error(
        "GET /api/me/bookings error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load your bookings."
      );
    }
  }
);

/* ============================================================
   CUSTOMER NOTIFICATION API
============================================================ */

router.get(
  "/api/me/notifications/unread-count",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const unreadCount =
        typeof Notification.getUnreadCount ===
        "function"
          ? await Notification.getUnreadCount(
              user._id
            )
          : await Notification.countDocuments({
              userId:
                user._id,

              archived:
                false,

              read:
                false,
            });

      return res.json({
        success:
          true,

        unreadCount,
      });
    } catch (error) {
      console.error(
        "Unread notification count error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load your notification count."
      );
    }
  }
);

router.get(
  "/api/me/notifications",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const currentPage =
        page(
          req.query.page
        );

      const currentLimit =
        limit(
          req.query.limit
        );

      const includeArchived =
        String(
          req.query
            .includeArchived
        ) ===
        "true";

      const unreadOnly =
        String(
          req.query.unreadOnly
        ) ===
        "true";

      const filter = {
        userId:
          user._id,

        ...(includeArchived
          ? {}
          : {
              archived:
                false,
            }),

        ...(unreadOnly
          ? {
              read:
                false,
            }
          : {}),
      };

      const [
        total,
        unreadCount,
        notifications,
      ] =
        await Promise.all([
          Notification.countDocuments(
            filter
          ),

          Notification.countDocuments(
            {
              userId:
                user._id,

              archived:
                false,

              read:
                false,
            }
          ),

          Notification.find(
            filter
          )
            .sort({
              createdAt: -1,
            })
            .skip(
              (
                currentPage -
                1
              ) *
                currentLimit
            )
            .limit(
              currentLimit
            )
            .lean(),
        ]);

      const totalPages =
        Math.max(
          1,
          Math.ceil(
            total /
              currentLimit
          )
        );

      return res.json({
        success:
          true,

        notifications,

        unreadCount,

        pagination: {
          page:
            currentPage,

          limit:
            currentLimit,

          total,

          totalPages,

          hasNextPage:
            currentPage <
            totalPages,

          hasPreviousPage:
            currentPage >
            1,
        },
      });
    } catch (error) {
      console.error(
        "GET /api/me/notifications error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load your notifications."
      );
    }
  }
);

/* ============================================================
   NOTIFICATION MUTATIONS
============================================================ */

async function ownedNotification(
  req,
  userId
) {
  const id =
    String(
      req.params.notificationId ||
        ""
    ).trim();

  if (
    !isValidObjectId(id)
  ) {
    return null;
  }

  /*
   * IMPORTANT:
   * The query always includes userId.
   * This prevents notification IDOR.
   */
  return Notification.findOne({
    _id: id,
    userId,
  });
}

async function setNotificationRead(
  req,
  res,
  read
) {
  try {
    const user =
      await currentUser(
        req,
        res
      );

    if (!user) {
      return;
    }

    const notification =
      await ownedNotification(
        req,
        user._id
      );

    if (!notification) {
      return jsonError(
        res,
        404,
        "Notification not found.",
        "NOTIFICATION_NOT_FOUND"
      );
    }

    if (read) {
      if (
        typeof notification.markAsRead ===
        "function"
      ) {
        await notification.markAsRead();
      } else {
        notification.read =
          true;

        notification.readAt =
          new Date();

        await notification.save();
      }
    } else {
      if (
        typeof notification.markAsUnread ===
        "function"
      ) {
        await notification.markAsUnread();
      } else {
        notification.read =
          false;

        notification.readAt =
          null;

        await notification.save();
      }
    }

    return res.json({
      success:
        true,

      notification:
        notification.toObject(),
    });
  } catch (error) {
    console.error(
      "Notification read state error:",
      error
    );

    return jsonError(
      res,
      500,
      "Unable to update the notification."
    );
  }
}

router.patch(
  "/api/me/notifications/:notificationId/read",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationRead(
      req,
      res,
      true
    )
);

router.post(
  "/api/me/notifications/:notificationId/read",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationRead(
      req,
      res,
      true
    )
);

router.patch(
  "/api/me/notifications/:notificationId/unread",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationRead(
      req,
      res,
      false
    )
);

router.post(
  "/api/me/notifications/:notificationId/unread",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationRead(
      req,
      res,
      false
    )
);

router.post(
  "/api/me/notifications/read-all",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      if (
        typeof Notification.markAllAsReadForUser ===
        "function"
      ) {
        await Notification.markAllAsReadForUser(
          user._id
        );
      } else {
        await Notification.updateMany(
          {
            userId:
              user._id,

            archived:
              false,

            read:
              false,
          },
          {
            $set: {
              read:
                true,

              readAt:
                new Date(),
            },
          }
        );
      }

      return res.json({
        success:
          true,

        message:
          "All notifications have been marked as read.",

        unreadCount:
          0,
      });
    } catch (error) {
      console.error(
        "Mark all notifications error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to mark all notifications as read."
      );
    }
  }
);

async function setNotificationArchived(
  req,
  res,
  archived
) {
  try {
    const user =
      await currentUser(
        req,
        res
      );

    if (!user) {
      return;
    }

    const notification =
      await ownedNotification(
        req,
        user._id
      );

    if (!notification) {
      return jsonError(
        res,
        404,
        "Notification not found.",
        "NOTIFICATION_NOT_FOUND"
      );
    }

    if (archived) {
      if (
        typeof notification.archive ===
        "function"
      ) {
        await notification.archive();
      } else {
        notification.archived =
          true;

        notification.archivedAt =
          new Date();

        await notification.save();
      }
    } else {
      if (
        typeof notification.unarchive ===
        "function"
      ) {
        await notification.unarchive();
      } else {
        notification.archived =
          false;

        notification.archivedAt =
          null;

        await notification.save();
      }
    }

    return res.json({
      success:
        true,

      notification:
        notification.toObject(),
    });
  } catch (error) {
    console.error(
      "Notification archive state error:",
      error
    );

    return jsonError(
      res,
      500,
      "Unable to update the notification."
    );
  }
}

router.patch(
  "/api/me/notifications/:notificationId/archive",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationArchived(
      req,
      res,
      true
    )
);

router.post(
  "/api/me/notifications/:notificationId/archive",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationArchived(
      req,
      res,
      true
    )
);

router.patch(
  "/api/me/notifications/:notificationId/unarchive",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationArchived(
      req,
      res,
      false
    )
);

router.post(
  "/api/me/notifications/:notificationId/unarchive",
  requireLogin,
  (
    req,
    res
  ) =>
    setNotificationArchived(
      req,
      res,
      false
    )
);

/* ============================================================
   LIVE USER UPDATES
============================================================ */

async function buildLiveUpdates(
  userId
) {
  const [
    appointments,
    notifications,
    totalBookings,
    unreadNotifications,
  ] =
    await Promise.all([
      Appointment.find({
        userId,
      })
        .select(
          "-adminNotes"
        )
        .sort({
          createdAt: -1,
        })
        .limit(100)
        .lean(),

      Notification.find({
        userId,

        archived:
          false,
      })
        .sort({
          createdAt: -1,
        })
        .limit(100)
        .lean(),

      Appointment.countDocuments({
        userId,
      }),

      Notification.countDocuments({
        userId,

        archived:
          false,

        read:
          false,
      }),
    ]);

  return {
    appointments,

    notifications,

    stats: {
      totalBookings,

      unreadNotifications,
    },
  };
}

router.get(
  "/userUpdates",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      return res.json({
        success:
          true,

        ...(await buildLiveUpdates(
          user._id
        )),
      });
    } catch (error) {
      console.error(
        "User Updates Error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to fetch your latest updates."
      );
    }
  }
);

/*
 * Legacy endpoint retained for compatibility
 * with older profile implementations.
 *
 * The supplied ID is NEVER trusted by itself.
 */
router.get(
  "/userUpdates/:userId",
  requireLogin,
  async (req, res) => {
    try {
      const requested =
        String(
          req.params.userId ||
            ""
        ).trim();

      const id =
        sessionUserId(
          req
        );

      if (
        !isValidObjectId(
          requested
        )
      ) {
        return jsonError(
          res,
          400,
          "Invalid user ID.",
          "INVALID_USER_ID"
        );
      }

      if (
        String(id) !==
        requested
      ) {
        return jsonError(
          res,
          403,
          "Unauthorized access.",
          "FORBIDDEN"
        );
      }

      const user =
        await User.findById(
          id
        )
          .select(
            "-password"
          )
          .lean();

      if (!user) {
        return jsonError(
          res,
          401,
          "Your session has expired. Please log in again.",
          "INVALID_SESSION"
        );
      }

      return res.json({
        success:
          true,

        ...(await buildLiveUpdates(
          user._id
        )),
      });
    } catch (error) {
      console.error(
        "Legacy User Updates Error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to fetch your latest updates."
      );
    }
  }
);

/* ============================================================
   CUSTOMER CANCELLATION
============================================================ */

router.post(
  "/appointment/cancel/:appointmentId",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const appointmentId =
        clean(
          req.params.appointmentId,
          100
        );

      if (
        !isValidObjectId(
          appointmentId
        )
      ) {
        return jsonError(
          res,
          400,
          "Invalid appointment ID.",
          "INVALID_APPOINTMENT_ID"
        );
      }

      const existing =
        await Appointment.findOne({
          _id:
            appointmentId,

          userId:
            user._id,
        });

      if (!existing) {
        return jsonError(
          res,
          404,
          "Appointment not found.",
          "APPOINTMENT_NOT_FOUND"
        );
      }

      const status =
        String(
          existing.status ||
            "pending"
        ).toLowerCase();

      if (
        !CANCELLABLE_STATUSES.includes(
          status
        )
      ) {
        return jsonError(
          res,
          400,
          `A booking with status "${existing.status}" cannot be cancelled.`,
          "BOOKING_NOT_CANCELLABLE"
        );
      }

      /*
       * Conditional update:
       * even if another request changes the booking
       * after the validation above, this update will
       * only succeed while the status is cancellable.
       */
      const appointment =
        await Appointment.findOneAndUpdate(
          {
            _id:
              appointmentId,

            userId:
              user._id,

            status: {
              $in:
                CANCELLABLE_STATUSES,
            },
          },
          {
            $set: {
              status:
                "cancelled",

              cancelledAt:
                new Date(),

              cancelledBy:
                "user",
            },
          },
          {
            new:
              true,

            runValidators:
              true,
          }
        )
          .select(
            "-adminNotes"
          );

      if (!appointment) {
        return jsonError(
          res,
          409,
          "This booking was already updated and can no longer be cancelled.",
          "BOOKING_STATE_CHANGED"
        );
      }

      await createAppointmentNotification({
        userId:
          user._id,

        appointmentId:
          appointment._id,

        event:
          "cancelled",

        title:
          "Reservation Cancelled",

        message:
          `Your reservation for ${appointment.room} ` +
          `from ${dateLabel(
            appointment.checkin
          )} to ${dateLabel(
            appointment.checkout
          )} has been cancelled successfully.`,

        priority:
          "high",

        metadata: {
          roomName:
            appointment.room,

          checkin:
            appointment.checkin,

          checkout:
            appointment.checkout,

          status:
            appointment.status,
        },
      });

      return res.json({
        success:
          true,

        message:
          "Your reservation has been cancelled successfully.",

        appointment:
          serializeAppointment(
            appointment
          ),
      });
    } catch (error) {
      console.error(
        "Appointment Cancellation Error:",
        error
      );

      return jsonError(
        res,
        error?.name ===
          "ValidationError"
          ? 400
          : 500,
        "Failed to cancel the appointment."
      );
    }
  }
);

/* ============================================================
   CUSTOMER CATALOG API
============================================================ */

router.get(
  "/api/user-catalog",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await currentUser(
          req,
          res
        );

      if (!user) {
        return;
      }

      const [
        rooms,
        addOns,
      ] =
        await Promise.all([
          getActiveRooms(),

          getActiveAddOns(),
        ]);

      return res.json({
        success:
          true,

        rooms:
          rooms.map(
            roomResponse
          ),

        addOns:
          addOns.map(
            addOnResponse
          ),
      });
    } catch (error) {
      console.error(
        "User Catalog API Error:",
        error
      );

      return jsonError(
        res,
        500,
        "Unable to load the current accommodation catalog."
      );
    }
  }
);

/* ============================================================
   PASSWORD UPDATE
============================================================ */

router.post(
  "/profile/update-password",
  requireLogin,
  async (req, res) => {
    const json =
      wantsJson(req);

    const fail =
      (
        message,
        code,
        status = 400
      ) =>
        json
          ? jsonError(
              res,
              status,
              message,
              code
            )
          : res.redirect(
              queryRedirect(
                "/profile",
                "error",
                message
              )
            );

    try {
      const userId =
        sessionUserId(
          req
        );

      if (
        !userId ||
        !isValidObjectId(
          userId
        )
      ) {
        return fail(
          "Your session has expired. Please log in again.",
          "AUTHENTICATION_REQUIRED",
          401
        );
      }

      /*
       * Password is select:false in the upgraded User model,
       * so it must be explicitly selected for verification.
       */
      const user =
        await User.findById(
          userId
        ).select(
          "+password +passwordResetTokenHash +passwordResetExpires"
        );

      if (!user) {
        await destroySession(
          req
        );

        return fail(
          "Your account session is no longer valid.",
          "INVALID_SESSION",
          401
        );
      }

      const accountStatus =
        String(
          user.status ||
            "active"
        ).toLowerCase();

      if (
        accountStatus !==
        "active"
      ) {
        await destroySession(
          req
        );

        return fail(
          "Your account is not currently available for password changes.",
          "ACCOUNT_UNAVAILABLE",
          403
        );
      }

      const currentPassword =
        String(
          req.body?.currentPassword ||
            ""
        );

      const newPassword =
        String(
          req.body?.newPassword ||
            ""
        );

      const confirmPassword =
        String(
          req.body?.confirmPassword ||
            ""
        );

      const minimumLength =
        Math.max(
          10,
          Number(
            User.PASSWORD_MIN_LENGTH ||
              10
          )
        );

      if (
        !currentPassword ||
        !newPassword
      ) {
        return fail(
          "Current password and new password are required.",
          "PASSWORD_FIELDS_REQUIRED"
        );
      }

      if (
        newPassword.length <
        minimumLength
      ) {
        return fail(
          `New password must contain at least ${minimumLength} characters.`,
          "PASSWORD_TOO_SHORT"
        );
      }

      if (
        newPassword.length >
        128
      ) {
        return fail(
          "New password cannot exceed 128 characters.",
          "PASSWORD_TOO_LONG"
        );
      }

      if (
        newPassword !==
        confirmPassword
      ) {
        return fail(
          "New passwords do not match.",
          "PASSWORD_MISMATCH"
        );
      }

      if (
        typeof user.comparePassword !==
          "function" ||
        !(
          await user.comparePassword(
            currentPassword
          )
        )
      ) {
        return fail(
          "Your current password is incorrect.",
          "CURRENT_PASSWORD_INVALID"
        );
      }

      if (
        await user.comparePassword(
          newPassword
        )
      ) {
        return fail(
          "Your new password must be different from your current password.",
          "PASSWORD_UNCHANGED"
        );
      }

      if (
        typeof user.setPassword ===
        "function"
      ) {
        await user.setPassword(
          newPassword
        );
      } else {
        user.password =
          newPassword;

        user.passwordChangedAt =
          new Date();
      }

      /*
       * Invalidate an outstanding reset token
       * whenever the password is changed.
       */
      if (
        user.schema.path(
          "passwordResetTokenHash"
        )
      ) {
        user.passwordResetTokenHash =
          null;
      }

      if (
        user.schema.path(
          "passwordResetExpires"
        )
      ) {
        user.passwordResetExpires =
          null;
      }

      if (
        user.schema.path(
          "passwordChangedAt"
        ) &&
        !user.passwordChangedAt
      ) {
        user.passwordChangedAt =
          new Date();
      }

      await user.save();

      /*
       * Refresh only the safe session identity.
       * Never put the password into the session.
       */
      req.session.user =
        safeSessionUser(
          user
        );

      await saveSession(
        req
      );

      if (json) {
        return res.json({
          success:
            true,

          message:
            "Your password has been updated successfully.",
        });
      }

      return res.redirect(
        queryRedirect(
          "/profile",
          "success",
          "Your password has been updated successfully."
        )
      );
    } catch (error) {
      console.error(
        "Update password error:",
        error
      );

      return json
        ? jsonError(
            res,
            500,
            "Unable to update your password right now. Please try again."
          )
        : res.redirect(
            queryRedirect(
              "/profile",
              "error",
              "Unable to update your password right now. Please try again."
            )
          );
    }
  }
);

/* ============================================================
   EXPORT
============================================================ */

module.exports = router;