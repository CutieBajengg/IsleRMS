"use strict";

/*
|--------------------------------------------------------------------------
| Puffer Isle Resort | IsleRMS
| routes/userRoutes.js
|--------------------------------------------------------------------------
| User-facing routes for:
|
| - Booking page
| - Dynamic room catalog
| - Dynamic add-on catalog
| - Server-side booking pricing
| - Appointment history
| - Notifications
| - Live user updates
| - User booking cancellation
|
| IMPORTANT:
| The customer/browser NEVER controls the final booking price.
|
| Current catalog prices come from:
|   models/Room.js
|   models/AddOn.js
|
| Historical booking prices are stored in:
|   models/Appointment.js
|--------------------------------------------------------------------------
*/

const express = require("express");
const mongoose = require("mongoose");

const router = express.Router();

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Notification = require("../models/Notification");
const Room = require("../models/Room");
const AddOn = require("../models/AddOn");

/*
|--------------------------------------------------------------------------
| Constants
|--------------------------------------------------------------------------
*/

const BLOCKING_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
  "checked-in",
];

const CANCELLABLE_STATUSES = [
  "pending",
  "accepted",
  "confirmed",
];

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/

function requireLogin(req, res, next) {
  if (!req.session?.user) {
    return res.redirect(
      "/?error=" +
        encodeURIComponent(
          "Please log in to continue."
        )
    );
  }

  next();
}

/*
|--------------------------------------------------------------------------
| Generic Helpers
|--------------------------------------------------------------------------
*/

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

function normalizeString(value) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function parseNumber(value, fallback = 0) {
  const number = Number(value);

  return Number.isFinite(number)
    ? number
    : fallback;
}

function getSessionUserId(req) {
  /*
   * Support both:
   *
   * req.session.user.id
   * req.session.user._id
   *
   * This keeps the router compatible with the
   * current server session structure.
   */
  return (
    req.session?.user?.id ||
    req.session?.user?._id ||
    null
  );
}

function wantsJson(req) {
  return Boolean(
    req.headers.accept?.includes(
      "application/json"
    )
  );
}

/*
|--------------------------------------------------------------------------
| Date Helpers
|--------------------------------------------------------------------------
*/

function parseBookingDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date;
}

function validateBookingDates(
  checkin,
  checkout
) {
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

function isDateInPast(date) {
  const now = new Date();

  const todayStart = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate()
  );

  return date < todayStart;
}

function getNumberOfNights(
  checkin,
  checkout
) {
  const start = new Date(checkin);
  const end = new Date(checkout);

  const milliseconds =
    end.getTime() - start.getTime();

  return Math.ceil(
    milliseconds /
      (1000 * 60 * 60 * 24)
  );
}

/*
|--------------------------------------------------------------------------
| Room Catalog
|--------------------------------------------------------------------------
*/

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

async function findRoomBySelection(
  selection
) {
  const requested = normalizeString(
    selection
  );

  if (!requested) {
    return null;
  }

  /*
   * Try ObjectId first.
   */
  if (isValidObjectId(requested)) {
    const roomById =
      await Room.findOne({
        _id: requested,
        active: true,
      }).lean();

    if (roomById) {
      return roomById;
    }
  }

  /*
   * Then try slug or name.
   */
  return Room.findOne({
    active: true,
    $or: [
      {
        slug: requested.toLowerCase(),
      },
      {
        name: requested,
      },
    ],
  }).lean();
}

/*
|--------------------------------------------------------------------------
| Add-on Catalog
|--------------------------------------------------------------------------
*/

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

async function findAddOnBySelection(
  selection
) {
  const requested = normalizeString(
    selection
  );

  if (!requested) {
    return null;
  }

  /*
   * Try ObjectId first.
   */
  if (isValidObjectId(requested)) {
    const addOnById =
      await AddOn.findOne({
        _id: requested,
        active: true,
      }).lean();

    if (addOnById) {
      return addOnById;
    }
  }

  /*
   * Then try slug or name.
   */
  return AddOn.findOne({
    active: true,
    $or: [
      {
        slug: requested.toLowerCase(),
      },
      {
        name: requested,
      },
    ],
  }).lean();
}

/*
|--------------------------------------------------------------------------
| Add-on Input Normalization
|--------------------------------------------------------------------------
|
| The frontend may eventually send:
|
| addOns[]
| addOnIds[]
| addonIds[]
| addOn
| addon
|
| We normalize all of them into a simple array.
|--------------------------------------------------------------------------
*/

function normalizeAddOnSelections(
  body
) {
  const values = [];

  const candidates = [
    body.addOns,
    body.addOnIds,
    body.addonIds,
    body.addOn,
    body.addon,
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      values.push(...candidate);
      continue;
    }

    if (
      candidate !== undefined &&
      candidate !== null &&
      String(candidate).trim() !== ""
    ) {
      /*
       * Support comma-separated form values too.
       */
      const pieces = String(candidate)
        .split(",");

      values.push(...pieces);
    }
  }

  return [
    ...new Set(
      values
        .map((value) =>
          normalizeString(value)
        )
        .filter(Boolean)
    ),
  ];
}

/*
|--------------------------------------------------------------------------
| Legacy Cottage Compatibility
|--------------------------------------------------------------------------
|
| Older forms used:
|
| cottageAddon=true
|
| The new system uses AddOn.js.
|
| Therefore, when that legacy field is received,
| we try to locate an active cottage/seaside add-on
| in the database.
|--------------------------------------------------------------------------
*/

async function resolveLegacyCottageAddon(
  body
) {
  const requested =
    body.cottageAddon === true ||
    body.cottageAddon === "true" ||
    body.cottageAddon === "on" ||
    body.cottageAddon === 1 ||
    body.cottageAddon === "1" ||
    body.cottage === true ||
    body.cottage === "true" ||
    body.cottage === "on" ||
    body.cottage === 1 ||
    body.cottage === "1";

  if (!requested) {
    return null;
  }

  const addOn =
    await AddOn.findOne({
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

  return addOn || null;
}

/*
|--------------------------------------------------------------------------
| Booking Availability
|--------------------------------------------------------------------------
|
| Standard hotel overlap:
|
| existing.checkin < requested.checkout
| AND
| existing.checkout > requested.checkin
|
| Pending, accepted, confirmed and checked-in
| bookings occupy inventory.
|--------------------------------------------------------------------------
*/

async function findConflictingBooking({
  room,
  checkin,
  checkout,
  excludeId = null,
}) {
  if (!room?._id) {
    return null;
  }

  const query = {
    roomId: room._id,

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

  /*
   * For the first deployment stage, a room with
   * quantity = 1 is treated as a single reservable unit.
   *
   * If quantity is greater than 1, we count overlapping
   * appointments and only block once all units are occupied.
   */
  const quantity =
    Math.max(
      1,
      Math.floor(
        parseNumber(
          room.quantity,
          1
        )
      )
    );

  const appointments =
    await Appointment.find(query)
      .sort({
        checkin: 1,
      })
      .lean();

  if (appointments.length >= quantity) {
    return appointments[0];
  }

  return null;
}

/*
|--------------------------------------------------------------------------
| Notification Helper
|--------------------------------------------------------------------------
|
| Notification.js accepts appointment/system/alert.
|
| We therefore use "appointment".
|--------------------------------------------------------------------------
*/

async function createBookingNotification({
  userId,
  message,
}) {
  try {
    if (!userId || !message) {
      return null;
    }

    return await Notification.create({
      userId,
      message,
      type: "appointment",
    });
  } catch (error) {
    /*
     * Notification failure must not destroy
     * an otherwise successful booking operation.
     */
    console.error(
      "Notification creation failed:",
      error.message
    );

    return null;
  }
}

/*
|--------------------------------------------------------------------------
| Server-Side Pricing
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| The request's totalPrice is NEVER used.
|
| Current Room/AddOn prices come from MongoDB.
|
| The final snapshot is generated through
| Appointment.calculateSnapshotPrice().
|--------------------------------------------------------------------------
*/

async function calculateBookingPrice({
  room,
  addOnSelections,
  checkin,
  checkout,
}) {
  if (!room) {
    return {
      valid: false,
      error:
        "The selected room is not available.",
    };
  }

  const nights =
    getNumberOfNights(
      checkin,
      checkout
    );

  if (nights < 1) {
    return {
      valid: false,
      error:
        "Your stay must be at least one night.",
    };
  }

  /*
   * Resolve requested add-ons from the
   * CURRENT database catalog.
   */
  const resolvedAddOns = [];

  for (const selection of addOnSelections) {
    const addOn =
      await findAddOnBySelection(
        selection
      );

    if (!addOn) {
      return {
        valid: false,
        error:
          "One of the selected add-ons is no longer available.",
      };
    }

    resolvedAddOns.push({
      addOnId: addOn._id,
      name: addOn.name,
      price: addOn.price,
      pricingType:
        addOn.pricingType,
      quantity: 1,
    });
  }

  /*
   * Build the historical pricing snapshot.
   */
  const pricing =
    Appointment.calculateSnapshotPrice({
      roomPrice:
        Number(room.price),

      numberOfNights:
        nights,

      addOns:
        resolvedAddOns,
    });

  return {
    valid: true,

    room,

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

/*
|--------------------------------------------------------------------------
| BOOKING PAGE
|--------------------------------------------------------------------------
*/

router.get(
  "/booking",
  requireLogin,
  async (req, res) => {
    try {
      const userId =
        getSessionUserId(req);

      if (
        !userId ||
        !isValidObjectId(userId)
      ) {
        return req.session.destroy(
          () => res.redirect("/")
        );
      }

      const [
        user,
        appointments,
        rooms,
        addOns,
      ] = await Promise.all([
        User.findById(userId).lean(),

        Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),

        getActiveRooms(),

        getActiveAddOns(),
      ]);

      if (!user) {
        return req.session.destroy(
          () => res.redirect("/")
        );
      }

      return res.render(
        "appointments",
        {
          title:
            "Book Your Stay",

          user,

          appointments,

          rooms,

          addOns,

          /*
           * Compatibility data for older EJS templates.
           */
          cottage:
            addOns.find(
              (addOn) =>
                /cottage/i.test(
                  addOn.name
                )
            ) || null,

          error:
            req.query.error ||
            null,

          success:
            req.query.success ||
            null,
        }
      );
    } catch (error) {
      console.error(
        "Booking Page Error:",
        error
      );

      return res.status(500).render(
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

/*
|--------------------------------------------------------------------------
| USER PROFILE
|--------------------------------------------------------------------------
*/

router.get(
  "/profile",
  requireLogin,
  async (req, res) => {
    try {
      const userId =
        getSessionUserId(req);

      if (
        !userId ||
        !isValidObjectId(userId)
      ) {
        return req.session.destroy(
          () => res.redirect("/")
        );
      }

      const [
        user,
        appointments,
        notifications,
      ] = await Promise.all([
        User.findById(userId).lean(),

        Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),

        Notification.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),
      ]);

      if (!user) {
        return req.session.destroy(
          () => res.redirect("/")
        );
      }

      return res.render(
        "profile",
        {
          title:
            `${user.fullname || "User"} | Isle RMS Profile`,

          user,

          appointments,

          notifications,
        }
      );
    } catch (error) {
      console.error(
        "Profile Error:",
        error
      );

      return res.status(500).render(
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

router.get(
  "/profile/:id",
  requireLogin,
  async (req, res) => {
    try {
      const requestedUserId =
        req.params.id;

      const sessionUserId =
        getSessionUserId(req);

      if (
        !isValidObjectId(
          requestedUserId
        )
      ) {
        return res.status(400).render(
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
        !sessionUserId ||
        String(sessionUserId) !==
          String(requestedUserId)
      ) {
        return res.status(403).render(
          "error",
          {
            title:
              "Unauthorized",

            message:
              "You are not authorized to view this profile.",
          }
        );
      }

      const [
        user,
        appointments,
        notifications,
      ] = await Promise.all([
        User.findById(
          requestedUserId
        ).lean(),

        Appointment.find({
          userId:
            requestedUserId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),

        Notification.find({
          userId:
            requestedUserId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),
      ]);

      if (!user) {
        return res.status(404).render(
          "error",
          {
            title:
              "User Not Found",

            message:
              "The requested user account could not be found.",
          }
        );
      }

      return res.render(
        "profile",
        {
          title:
            `${user.fullname || "User"} | Isle RMS Profile`,

          user,

          appointments,

          notifications,
        }
      );
    } catch (error) {
      console.error(
        "User Profile Error:",
        error
      );

      return res.status(500).render(
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

/*
|--------------------------------------------------------------------------
| SUBMIT BOOKING
|--------------------------------------------------------------------------
|
| Supported:
|
| POST /appointment/submit
| POST /booking/submit
|
| The second route is retained for compatibility with
| the current appointments.ejs until that view is updated.
|--------------------------------------------------------------------------
*/

async function submitBooking(
  req,
  res
) {
  try {
    const userId =
      getSessionUserId(req);

    if (
      !userId ||
      !isValidObjectId(userId)
    ) {
      if (wantsJson(req)) {
        return res.status(401).json({
          success: false,
          message:
            "Your session has expired. Please log in again.",
        });
      }

      return res.redirect(
        "/?error=" +
          encodeURIComponent(
            "Your session has expired. Please log in again."
          )
      );
    }

    /*
     * Accept several common field names
     * for frontend compatibility.
     */
    const roomSelection =
      normalizeString(
        req.body.room ||
          req.body.roomId ||
          req.body.roomType ||
          req.body.accommodation
      );

    const guests = Math.floor(
      parseNumber(
        req.body.guests,
        0
      )
    );

    const contact =
      normalizeString(
        req.body.contact ||
          req.body.phone ||
          req.body.contactNumber
      );

    const checkinValue =
      req.body.checkin ||
      req.body.checkIn ||
      req.body.checkInDate;

    const checkoutValue =
      req.body.checkout ||
      req.body.checkOut ||
      req.body.checkOutDate;

    const specialRequests =
      normalizeString(
        req.body.specialRequests
      );

    /*
     * Required fields.
     */
    if (
      !roomSelection ||
      !contact ||
      !checkinValue ||
      !checkoutValue ||
      guests < 1
    ) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "MISSING_BOOKING_FIELDS",
          message:
            "Please complete all required booking fields.",
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            "Please complete all required booking fields."
          )
      );
    }

    /*
     * Date validation.
     */
    const dateValidation =
      validateBookingDates(
        checkinValue,
        checkoutValue
      );

    if (!dateValidation.valid) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_DATES",
          message:
            dateValidation.message,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            dateValidation.message
          )
      );
    }

    const {
      start,
      end,
    } = dateValidation;

    /*
     * Past date protection.
     */
    if (isDateInPast(start)) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "PAST_DATE",
          message:
            "Check-in cannot be in the past.",
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            "Check-in cannot be in the past."
          )
      );
    }

    /*
     * Contact validation.
     */
    if (contact.length < 3) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_CONTACT",
          message:
            "Please provide a valid contact number.",
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            "Please provide a valid contact number."
          )
      );
    }

    /*
     * Load the CURRENT active room from MongoDB.
     */
    const room =
      await findRoomBySelection(
        roomSelection
      );

    if (!room) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_ROOM",
          message:
            "The selected accommodation is not available.",
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            "The selected accommodation is not available."
          )
      );
    }

    /*
     * Guest capacity comes from Room.js.
     */
    const maxGuests =
      Math.floor(
        parseNumber(
          room.maxGuests,
          0
        )
      );

    if (
      maxGuests < 1 ||
      guests > maxGuests
    ) {
      const message =
        maxGuests > 0
          ? `The selected room allows a maximum of ${maxGuests} guests.`
          : "The selected room has an invalid guest capacity.";

      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_GUEST_COUNT",
          message,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(message)
      );
    }

    /*
     * Add-on selections from the new catalog.
     */
    const addOnSelections =
      normalizeAddOnSelections(
        req.body
      );

    /*
     * Legacy cottage checkbox compatibility.
     *
     * If the old form sends cottageAddon=true,
     * convert it into a real AddOn selection.
     */
    const legacyCottage =
      await resolveLegacyCottageAddon(
        req.body
      );

    if (
      legacyCottage &&
      !addOnSelections.some(
        (selection) =>
          selection ===
            String(
              legacyCottage._id
            ) ||
          selection.toLowerCase() ===
            String(
              legacyCottage.slug
            ).toLowerCase() ||
          selection.toLowerCase() ===
            String(
              legacyCottage.name
            ).toLowerCase()
      )
    ) {
      addOnSelections.push(
        String(legacyCottage._id)
      );
    }

    /*
     * Validate availability BEFORE creating
     * the appointment.
     */
    const conflict =
      await findConflictingBooking({
        room,

        checkin: start,

        checkout: end,
      });

    if (conflict) {
      console.warn(
        "User booking rejected because room is unavailable:",
        {
          roomId:
            room._id?.toString(),

          room:
            room.name,

          requestedCheckin:
            start,

          requestedCheckout:
            end,

          conflictingBooking:
            conflict._id,
        }
      );

      const message =
        "This accommodation is already reserved for your selected dates.";

      if (wantsJson(req)) {
        return res.status(409).json({
          success: false,
          code:
            "ROOM_ALREADY_BOOKED",
          message,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            message
          )
      );
    }

    /*
     * SERVER-SIDE PRICING
     *
     * Never use req.body.totalPrice.
     *
     * Current prices come from Room.js/AddOn.js.
     */
    const pricing =
      await calculateBookingPrice({
        room,

        addOnSelections,

        checkin: start,

        checkout: end,
      });

    if (!pricing.valid) {
      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "PRICING_ERROR",
          message:
            pricing.error,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            pricing.error
          )
      );
    }

    /*
     * Build the appointment.
     *
     * All pricing values below are snapshots.
     */
    const appointmentData = {
      userId,

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

      roomSubtotal:
        pricing.roomSubtotal,

      numberOfNights:
        pricing.nights,

      addOns:
        pricing.addOns,

      addOnSubtotal:
        pricing.addOnSubtotal,

      /*
       * Legacy field retained for compatibility.
       */
      cottageAddon:
        pricing.addOns.some(
          (addOn) =>
            /cottage/i.test(
              addOn.name
            )
        ),

      /*
       * These remain zero unless a legacy
       * cottage add-on was included.
       *
       * The new source of truth is addOns[].
       */
      cottagePrice:
        pricing.addOns.find(
          (addOn) =>
            /cottage/i.test(
              addOn.name
            )
        )?.price || 0,

      cottageSubtotal:
        pricing.addOns.find(
          (addOn) =>
            /cottage/i.test(
              addOn.name
            )
        )?.subtotal || 0,

      guests,

      contact,

      checkin:
        start,

      checkout:
        end,

      specialRequests,

      totalPrice:
        pricing.totalPrice,

      status:
        "pending",
    };

    const newAppointment =
      new Appointment(
        appointmentData
      );

    await newAppointment.save();

    /*
     * Notify the customer.
     */
    await createBookingNotification({
      userId,

      message:
        `Your booking request for ${room.name} ` +
        `from ${start.toLocaleDateString()} ` +
        `to ${end.toLocaleDateString()} ` +
        `has been submitted and is pending confirmation.`,
    });

    console.log(
      "Appointment created:",
      {
        id:
          newAppointment._id.toString(),

        userId:
          String(userId),

        room:
          newAppointment.room,

        roomId:
          newAppointment.roomId,

        checkin:
          newAppointment.checkin,

        checkout:
          newAppointment.checkout,

        guests:
          newAppointment.guests,

        totalPrice:
          newAppointment.totalPrice,

        status:
          newAppointment.status,
      }
    );

    /*
     * JSON response for AJAX clients.
     */
    if (wantsJson(req)) {
      return res.status(201).json({
        success: true,

        message:
          "Booking request submitted successfully.",

        booking: {
          id:
            newAppointment._id,

          room:
            newAppointment.room,

          checkin:
            newAppointment.checkin,

          checkout:
            newAppointment.checkout,

          guests:
            newAppointment.guests,

          totalPrice:
            newAppointment.totalPrice,

          status:
            newAppointment.status,

          numberOfNights:
            newAppointment.numberOfNights,

          addOns:
            newAppointment.addOns,
        },
      });
    }

    return res.redirect(
      "/profile?success=" +
        encodeURIComponent(
          "Booking submitted successfully."
        )
    );
  } catch (error) {
    console.error(
      "Appointment Submission Error:",
      error
    );

    /*
     * Mongoose validation.
     */
    if (
      error?.name ===
      "ValidationError"
    ) {
      const message =
        Object.values(
          error.errors || {}
        )
          .map(
            (entry) =>
              entry.message
          )
          .join(" ") ||
        "Some booking information is invalid.";

      if (wantsJson(req)) {
        return res.status(400).json({
          success: false,
          code:
            "VALIDATION_ERROR",
          message,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            message
          )
      );
    }

    /*
     * Duplicate/index conflict.
     */
    if (
      error?.code === 11000
    ) {
      const message =
        "This booking conflicts with an existing reservation.";

      if (wantsJson(req)) {
        return res.status(409).json({
          success: false,
          code:
            "BOOKING_CONFLICT",
          message,
        });
      }

      return res.redirect(
        "/booking?error=" +
          encodeURIComponent(
            message
          )
      );
    }

    if (wantsJson(req)) {
      return res.status(500).json({
        success: false,
        message:
          "Failed to submit your booking. Please try again.",
      });
    }

    return res.redirect(
      "/booking?error=" +
        encodeURIComponent(
          "Failed to submit your booking. Please try again."
        )
    );
  }
}

/*
 * Canonical booking endpoint.
 */
router.post(
  "/appointment/submit",
  requireLogin,
  submitBooking
);

/*
 * Compatibility endpoint for the current
 * appointments.ejs.
 */
router.post(
  "/booking/submit",
  requireLogin,
  submitBooking
);

/*
|--------------------------------------------------------------------------
| User Updates / Notifications
|--------------------------------------------------------------------------
*/

router.get(
  "/userUpdates/:userId",
  requireLogin,
  async (req, res) => {
    try {
      const requestedUserId =
        req.params.userId;

      const sessionUserId =
        getSessionUserId(req);

      if (
        !isValidObjectId(
          requestedUserId
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid user ID.",
        });
      }

      if (
        !sessionUserId ||
        String(sessionUserId) !==
          String(requestedUserId)
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Unauthorized access.",
        });
      }

      const [
        appointments,
        notifications,
      ] = await Promise.all([
        Appointment.find({
          userId:
            requestedUserId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),

        Notification.find({
          userId:
            requestedUserId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),
      ]);

      return res.json({
        success: true,

        appointments,

        notifications,
      });
    } catch (error) {
      console.error(
        "User Updates Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to fetch your latest updates.",
      });
    }
  }
);

router.get(
  "/userUpdates",
  requireLogin,
  async (req, res) => {
    try {
      const userId =
        getSessionUserId(req);

      if (
        !userId ||
        !isValidObjectId(userId)
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Your session has expired.",
        });
      }

      const [
        appointments,
        notifications,
      ] = await Promise.all([
        Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),

        Notification.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean(),
      ]);

      return res.json({
        success: true,

        appointments,

        notifications,
      });
    } catch (error) {
      console.error(
        "User Updates Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to fetch your latest updates.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| User Booking Cancellation
|--------------------------------------------------------------------------
|
| We DO NOT delete appointments.
|
| We mark them cancelled so the historical record remains intact.
|--------------------------------------------------------------------------
*/

router.post(
  "/appointment/cancel/:appointmentId",
  requireLogin,
  async (req, res) => {
    try {
      const appointmentId =
        normalizeString(
          req.params.appointmentId
        );

      const sessionUserId =
        getSessionUserId(req);

      if (
        !isValidObjectId(
          appointmentId
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid appointment ID.",
        });
      }

      const appointment =
        await Appointment.findById(
          appointmentId
        );

      if (!appointment) {
        return res.status(404).json({
          success: false,
          message:
            "Appointment not found.",
        });
      }

      if (
        !sessionUserId ||
        String(
          appointment.userId
        ) !==
          String(sessionUserId)
      ) {
        return res.status(403).json({
          success: false,
          message:
            "You are not authorized to cancel this booking.",
        });
      }

      const status =
        String(
          appointment.status ||
            "pending"
        ).toLowerCase();

      if (
        !CANCELLABLE_STATUSES.includes(
          status
        )
      ) {
        return res.status(400).json({
          success: false,

          code:
            "BOOKING_NOT_CANCELLABLE",

          message:
            `A booking with status "${appointment.status}" cannot be cancelled.`,
        });
      }

      appointment.status =
        "cancelled";

      appointment.cancelledAt =
        new Date();

      appointment.cancelledBy =
        "user";

      await appointment.save();

      await createBookingNotification({
        userId:
          appointment.userId,

        message:
          `Your ${appointment.room} booking ` +
          `has been cancelled successfully.`,
      });

      console.log(
        `Booking ${appointmentId} cancelled by user ${sessionUserId}.`
      );

      return res.json({
        success: true,

        message:
          "Appointment cancelled successfully.",

        appointment: {
          id:
            appointment._id,

          status:
            appointment.status,
        },
      });
    } catch (error) {
      console.error(
        "Appointment Cancellation Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Failed to cancel the appointment.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Customer Catalog API
|--------------------------------------------------------------------------
|
| Useful for future AJAX booking interfaces.
|
| GET /api/user-catalog
|--------------------------------------------------------------------------
*/

router.get(
  "/api/user-catalog",
  requireLogin,
  async (req, res) => {
    try {
      const [
        rooms,
        addOns,
      ] = await Promise.all([
        getActiveRooms(),
        getActiveAddOns(),
      ]);

      return res.json({
        success: true,

        rooms,

        addOns,
      });
    } catch (error) {
      console.error(
        "User catalog API error:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          "Unable to load the current accommodation catalog.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Export
|--------------------------------------------------------------------------
*/

module.exports = router;