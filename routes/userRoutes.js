// ============================================================
// Puffer Isle Resort | Isle RMS
// routes/userRoutes.js
//
// User-facing routes for:
// - Booking
// - Profile
// - Appointment history
// - Notifications
// - Live updates
// - Appointment cancellation
//
// IMPORTANT:
// This router uses the SAME session structure as server.js:
//
// req.session.user
//
// It does NOT use req.session.userId.
// ============================================================

const express = require("express");

const router = express.Router();

const mongoose = require("mongoose");

const Appointment = require("../models/Appointment");
const User = require("../models/User");
const Notification = require("../models/Notification");


// ============================================================
// CONSTANTS
// ============================================================

const ALLOWED_ROOMS = [
  "Aircon Room",
  "Fan Room",
  "Seaside Cottage",
];

const GUEST_LIMITS = {
  "Aircon Room": 8,
  "Fan Room": 6,
  "Seaside Cottage": 6,
};

const ACTIVE_BOOKING_STATUSES = [
  "pending",
  "accepted",
];

const CANCELLABLE_STATUSES = [
  "pending",
  "accepted",
];


// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function requireLogin(req, res, next) {
  if (!req.session?.user) {
    return res.redirect("/");
  }

  next();
}


// ============================================================
// OBJECT ID VALIDATION
// ============================================================

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}


// ============================================================
// SESSION USER ID
// ============================================================

function getSessionUserId(req) {
  return req.session?.user?._id || null;
}


// ============================================================
// DATE HELPERS
// ============================================================

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


// ============================================================
// DATE / PAST-BOOKING VALIDATION
// ============================================================

function isDateInPast(date) {
  const now = new Date();

  const todayStart = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate()
  );

  return date < todayStart;
}


// ============================================================
// GUEST VALIDATION
// ============================================================

function validateGuests(room, guests) {
  const guestCount = Number(guests);

  if (!Number.isInteger(guestCount)) {
    return {
      valid: false,
      message: "Guest count must be a whole number.",
    };
  }

  if (guestCount < 1) {
    return {
      valid: false,
      message: "At least one guest is required.",
    };
  }

  const maximumGuests = GUEST_LIMITS[room];

  if (!maximumGuests) {
    return {
      valid: false,
      message: "Invalid room selected.",
    };
  }

  if (guestCount > maximumGuests) {
    return {
      valid: false,
      message:
        `The ${room} allows a maximum of ${maximumGuests} guests.`,
    };
  }

  return {
    valid: true,
    guestCount,
  };
}


// ============================================================
// COTTAGE ADD-ON NORMALIZATION
// ============================================================

function normalizeCottageAddon(room, value) {
  const requestedAddon =
    value === true ||
    value === "true" ||
    value === "on" ||
    value === 1 ||
    value === "1";

  // Seaside Cottage already IS a cottage.
  // Never charge the add-on for it.
  if (room === "Seaside Cottage") {
    return false;
  }

  return requestedAddon;
}


// ============================================================
// ROOM AVAILABILITY
// ============================================================
//
// Booking overlap rule:
//
// existing.checkin < requested.checkout
// AND
// existing.checkout > requested.checkin
//
// Pending and accepted bookings reserve the room.
//
// Declined and cancelled bookings do not.
// ============================================================

async function findConflictingBooking({
  room,
  checkin,
  checkout,
  excludeId = null,
}) {
  const query = {
    room,

    status: {
      $in: ACTIVE_BOOKING_STATUSES,
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
// NOTIFICATION HELPER
// ============================================================
//
// The Notification model is used here if it exists.
//
// Booking status notifications are also generated from
// Appointment status by server.js.
//
// This helper therefore only creates an explicit booking
// notification where appropriate.
// ============================================================

async function createBookingNotification({
  userId,
  message,
  type = "booking",
}) {
  try {
    if (!userId || !message) {
      return null;
    }

    return await Notification.create({
      userId,
      message,
      type,
    });
  } catch (error) {
    // Notification failure should not destroy a successful
    // booking operation.
    console.error(
      "⚠️ Notification creation failed:",
      error
    );

    return null;
  }
}


// ============================================================
// 1. BOOKING PAGE
// ============================================================

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

      const user =
        await User.findById(userId)
          .lean();

      if (!user) {
        return req.session.destroy(
          () => res.redirect("/")
        );
      }

      const appointments =
        await Appointment.find({
          userId,
        })
          .sort({
            createdAt: -1,
          })
          .lean();

      return res.render(
        "appointments",
        {
          title:
            "Book Your Stay",

          user,

          appointments,

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
        "❌ Booking Page Error:",
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


// ============================================================
// 2. USER PROFILE
// ============================================================
//
// Supports:
// /profile/:id
//
// The main server.js also has:
//
// /profile
//
// We keep this route for compatibility with projects that
// mount userRoutes separately.
// ============================================================
// ============================================================
// PROFILE
// ============================================================

router.get(
  "/profile",
  requireLogin,
  async (req, res) => {
    try {
      const userId = getSessionUserId(req);

      if (!userId || !isValidObjectId(userId)) {
        return req.session.destroy(() =>
          res.redirect("/")
        );
      }

      const user = await User.findById(userId).lean();

      if (!user) {
        return req.session.destroy(() =>
          res.redirect("/")
        );
      }

      const [appointments, notifications] =
        await Promise.all([
          Appointment.find({ userId })
            .sort({ createdAt: -1 })
            .lean(),

          Notification.find({ userId })
            .sort({ createdAt: -1 })
            .lean(),
        ]);

      return res.render("profile", {
        title: `${user.fullname} | Isle RMS Profile`,
        user,
        appointments,
        notifications,
      });

    } catch (error) {
      console.error(
        "❌ Profile Error:",
        error
      );

      return res.status(500).render(
        "error",
        {
          title: "Profile Error",
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
        sessionUserId.toString() !==
          requestedUserId.toString()
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

      const user =
        await User.findById(
          requestedUserId
        ).lean();

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

      return res.render(
        "profile",
        {
          title:
            `${user.fullname} | Isle RMS Profile`,

          user,

          appointments,

          notifications,
        }
      );

    } catch (error) {
      console.error(
        "❌ User Profile Error:",
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


// ============================================================
// 3. SUBMIT BOOKING
// ============================================================
//
// IMPORTANT:
//
// The browser is NOT trusted.
//
// We validate:
// 1. Authentication
// 2. Required fields
// 3. Room
// 4. Guests
// 5. Dates
// 6. Past dates
// 7. Cottage add-on
// 8. Room availability
// 9. Server-side price
//
// req.body.totalPrice is deliberately ignored.
// ============================================================

router.post(
  "/appointment/submit",
  requireLogin,
  async (req, res) => {
    try {
      const {
        room,
        cottageAddon,
        guests,
        contact,
        checkin,
        checkout,
        specialRequests,
      } = req.body;

      const userId =
        getSessionUserId(req);


      // --------------------------------------------------------
      // SESSION VALIDATION
      // --------------------------------------------------------

      if (
        !userId ||
        !isValidObjectId(userId)
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Your session has expired. Please log in again.",
        });
      }


      // --------------------------------------------------------
      // REQUIRED FIELDS
      // --------------------------------------------------------

      if (
        !room ||
        !checkin ||
        !checkout ||
        guests === undefined ||
        guests === null ||
        !contact
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Please complete all required booking fields.",
        });
      }


      // --------------------------------------------------------
      // ROOM VALIDATION
      // --------------------------------------------------------

      if (
        !ALLOWED_ROOMS.includes(room)
      ) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_ROOM",
          message:
            "The selected accommodation is not available.",
        });
      }


      // --------------------------------------------------------
      // GUEST VALIDATION
      // --------------------------------------------------------

      const guestValidation =
        validateGuests(
          room,
          guests
        );

      if (
        !guestValidation.valid
      ) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_GUEST_COUNT",
          message:
            guestValidation.message,
        });
      }


      // --------------------------------------------------------
      // DATE VALIDATION
      // --------------------------------------------------------

      const dateValidation =
        validateBookingDates(
          checkin,
          checkout
        );

      if (
        !dateValidation.valid
      ) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_DATES",
          message:
            dateValidation.message,
        });
      }

      const {
        start,
        end,
      } = dateValidation;


      // --------------------------------------------------------
      // PAST DATE VALIDATION
      // --------------------------------------------------------

      if (
        isDateInPast(start)
      ) {
        return res.status(400).json({
          success: false,
          code:
            "PAST_DATE",
          message:
            "Check-in cannot be in the past.",
        });
      }


      // --------------------------------------------------------
      // CONTACT VALIDATION
      // --------------------------------------------------------

      const normalizedContact =
        String(contact)
          .trim();

      if (
        normalizedContact.length < 3
      ) {
        return res.status(400).json({
          success: false,
          code:
            "INVALID_CONTACT",
          message:
            "Please provide a valid contact number.",
        });
      }


      // --------------------------------------------------------
      // SPECIAL REQUESTS
      // --------------------------------------------------------

      const normalizedSpecialRequests =
        specialRequests
          ? String(
              specialRequests
            ).trim()
          : "";


      // --------------------------------------------------------
      // COTTAGE ADD-ON
      // --------------------------------------------------------

      const finalCottageAddon =
        normalizeCottageAddon(
          room,
          cottageAddon
        );


      // --------------------------------------------------------
      // DOUBLE-BOOKING CHECK
      // --------------------------------------------------------

      const conflict =
        await findConflictingBooking({
          room,

          checkin:
            start,

          checkout:
            end,
        });


      if (conflict) {
        console.warn(
          "⚠️ User booking rejected because room is unavailable:",
          {
            room,

            requestedCheckin:
              start,

            requestedCheckout:
              end,

            conflictingBooking:
              conflict._id,
          }
        );

        return res.status(409).json({
          success: false,

          code:
            "ROOM_ALREADY_BOOKED",

          message:
            "This accommodation is already reserved for part or all of your selected dates.",
        });
      }


      // --------------------------------------------------------
      // SERVER-SIDE PRICE CALCULATION
      // --------------------------------------------------------
      //
      // Appointment.js should expose calculatePrice().
      //
      // We intentionally do NOT trust req.body.totalPrice.
      // --------------------------------------------------------

      let pricing;

      if (
        typeof Appointment.calculatePrice ===
        "function"
      ) {
        pricing =
          Appointment.calculatePrice({
            room,

            cottageAddon:
              finalCottageAddon,

            checkin:
              start,

            checkout:
              end,
          });
      } else {
        return res.status(500).json({
          success: false,

          message:
            "Booking pricing service is not configured correctly.",
        });
      }


      // --------------------------------------------------------
      // CREATE APPOINTMENT
      // --------------------------------------------------------

      const newAppointment =
        new Appointment({
          userId,

          room,

          cottageAddon:
            finalCottageAddon,

          guests:
            guestValidation.guestCount,

          contact:
            normalizedContact,

          checkin:
            start,

          checkout:
            end,

          specialRequests:
            normalizedSpecialRequests,

          totalPrice:
            pricing.totalPrice,

          status:
            "pending",
        });


      await newAppointment.save();


      // --------------------------------------------------------
      // NOTIFICATION
      // --------------------------------------------------------

      await createBookingNotification({
        userId,

        message:
          `Your booking request for ${room} ` +
          `from ${start.toLocaleDateString()} ` +
          `to ${end.toLocaleDateString()} ` +
          `has been submitted and is pending confirmation.`,

        type:
          "booking",
      });


      console.log(
        "✅ Appointment created:",
        {
          id:
            newAppointment._id.toString(),

          userId:
            userId.toString(),

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
        }
      );


      // --------------------------------------------------------
      // RESPONSE
      // --------------------------------------------------------
      //
      // Supports AJAX/JSON clients.
      // --------------------------------------------------------

      if (
        req.headers.accept?.includes(
          "application/json"
        )
      ) {
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
          },
        });
      }


      return res.redirect(
        "/profile?success=booked"
      );

    } catch (error) {
      console.error(
        "❌ Appointment Submission Error:",
        error
      );


      // --------------------------------------------------------
      // MONGOOSE VALIDATION ERROR
      // --------------------------------------------------------

      if (
        error.name ===
        "ValidationError"
      ) {
        return res.status(400).json({
          success: false,

          code:
            "VALIDATION_ERROR",

          message:
            "Some booking information is invalid.",
        });
      }


      // --------------------------------------------------------
      // DUPLICATE / CONFLICT ERROR
      // --------------------------------------------------------

      if (
        error.code === 11000
      ) {
        return res.status(409).json({
          success: false,

          code:
            "BOOKING_CONFLICT",

          message:
            "This accommodation is no longer available for those dates. Please select different dates.",
        });
      }


      return res.status(500).json({
        success: false,

        message:
          "Failed to submit your booking. Please try again.",
      });
    }
  }
);


// ============================================================
// 4. LIVE USER UPDATES
// ============================================================

router.get(
  "/userUpdates/:userId",
  requireLogin,
  async (req, res) => {
    try {
      const requestedUserId =
        req.params.userId;

      const sessionUserId =
        getSessionUserId(req);


      // --------------------------------------------------------
      // VALIDATE ID
      // --------------------------------------------------------

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


      // --------------------------------------------------------
      // OWNERSHIP CHECK
      // --------------------------------------------------------

      if (
        !sessionUserId ||
        sessionUserId.toString() !==
          requestedUserId.toString()
      ) {
        return res.status(403).json({
          success: false,

          message:
            "Unauthorized access.",
        });
      }


      // --------------------------------------------------------
      // LOAD DATA IN PARALLEL
      // --------------------------------------------------------

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
        "❌ User Updates Error:",
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


// ============================================================
// 5. CANCEL APPOINTMENT
// ============================================================
//
// IMPORTANT:
//
// We DO NOT delete the booking.
//
// The booking is changed to:
//
// cancelled
//
// This preserves the booking history and makes the booking
// available again for future reservations.
// ============================================================

router.post(
  "/appointment/cancel/:appointmentId",
  requireLogin,
  async (req, res) => {
    try {
      const {
        appointmentId,
      } = req.params;

      const sessionUserId =
        getSessionUserId(req);


      // --------------------------------------------------------
      // VALIDATE APPOINTMENT ID
      // --------------------------------------------------------

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


      // --------------------------------------------------------
      // LOAD APPOINTMENT
      // --------------------------------------------------------

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


      // --------------------------------------------------------
      // OWNERSHIP CHECK
      // --------------------------------------------------------

      if (
        !sessionUserId ||
        appointment.userId.toString() !==
          sessionUserId.toString()
      ) {
        return res.status(403).json({
          success: false,

          message:
            "You are not authorized to cancel this booking.",
        });
      }


      // --------------------------------------------------------
      // STATUS VALIDATION
      // --------------------------------------------------------

      if (
        !CANCELLABLE_STATUSES.includes(
          appointment.status
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


      // --------------------------------------------------------
      // CANCEL BOOKING
      // --------------------------------------------------------

      appointment.status =
        "cancelled";


      await appointment.save();


      // --------------------------------------------------------
      // NOTIFICATION
      // --------------------------------------------------------

      await createBookingNotification({
        userId:
          appointment.userId,

        message:
          `Your ${appointment.room} booking ` +
          `has been cancelled successfully.`,

        type:
          "booking",
      });


      console.log(
        `🚫 Booking ${appointmentId} cancelled by user ${sessionUserId}.`
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
        "❌ Appointment Cancellation Error:",
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


// ============================================================
// EXPORT ROUTER
// ============================================================

module.exports = router;