  // ============================================================
  // Puffer Isle Resort | Isle RMS
  // Main Server
  // ============================================================

  const express = require("express");
  const path = require("path");
  const mongoose = require("mongoose");
  const session = require("express-session");
  const dotenv = require("dotenv");
  const MongoStore = require("connect-mongo");

  dotenv.config();

  // ============================================================
  // MODELS
  // ============================================================

  const Appointment = require("./models/Appointment");
  const User = require("./models/User");
  const Admin = require("./models/Admin");

  // ============================================================
  // APP CONFIGURATION
  // ============================================================

  const app = express();

  const PORT = Number(process.env.PORT) || 5000;

  const MONGODB_URI =
    process.env.MONGODB_URI ||
    "mongodb://localhost:27017/puffer_isle_resort";

  const SESSION_SECRET = process.env.SESSION_SECRET;

  if (!SESSION_SECRET) {
    console.warn(
      "⚠️ WARNING: SESSION_SECRET is not configured."
    );
  }

  // ============================================================
  // EXPRESS CONFIGURATION
  // ============================================================

  app.set("view engine", "ejs");

  app.set(
    "views",
    path.join(__dirname, "views")
  );

  // ============================================================
  // STATIC FILES
  // ============================================================

  app.use(
    express.static(
      path.join(__dirname, "public")
    )
  );

  // ============================================================
  // BODY PARSING
  // ============================================================

  app.use(
    express.urlencoded({
      extended: true,
      limit: "50kb",
    })
  );

  app.use(
    express.json({
      limit: "50kb",
    })
  );

  // ============================================================
  // SESSION
  // ============================================================

  app.use(
    session({
      secret:
        SESSION_SECRET ||
        "CHANGE_THIS_SESSION_SECRET",

      resave: false,

      saveUninitialized: false,

      store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: "sessions",
        ttl: 60 * 60 * 24,
      }),

      cookie: {
        maxAge: 1000 * 60 * 60 * 24,

        httpOnly: true,

        sameSite: "lax",

        secure:
          process.env.NODE_ENV === "production",
      },
    })
  );

  // ============================================================
  // ID VALIDATION
  // ============================================================

  function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
  }

  // ============================================================
  // GLOBAL TEMPLATE VARIABLES
  // ============================================================

  app.use(async (req, res, next) => {
    try {
      // These variables are available to every EJS template.
      res.locals.user = null;

      res.locals.admin =
        req.session?.admin || null;

      // FIX: navadmin.ejs uses currentPath to highlight
      // the active admin navigation item.
      res.locals.currentPath = req.path;

      res.locals.title =
        "Puffer Isle Resort";

      // --------------------------------------------------------
      // Load authenticated user
      // --------------------------------------------------------

      if (
        req.session?.userId &&
        isValidObjectId(req.session.userId)
      ) {
        const user = await User.findById(
          req.session.userId
        ).lean();

        if (user) {
          res.locals.user = user;
        }
      }

      next();

    } catch (error) {
      console.error(
        "Global Session User Error:",
        error
      );

      // Keep all template globals defined even if the user
      // lookup fails. This prevents secondary EJS errors.
      res.locals.user = null;
      res.locals.admin =
        req.session?.admin || null;
      res.locals.currentPath = req.path;
      res.locals.title =
        "Puffer Isle Resort";

      next();
    }
  });

  // ============================================================
  // AUTHENTICATION HELPERS
  // ============================================================

  async function requireUser(req, res, next) {
    try {
      const userId =
        req.session?.userId;

      if (
        !userId ||
        !isValidObjectId(userId)
      ) {
        return res.redirect("/");
      }

      const user =
        await User.findById(userId).lean();

      if (!user) {
        return req.session.destroy(() => {
          res.redirect("/");
        });
      }

      req.currentUser = user;

      res.locals.user = user;

      next();

    } catch (error) {
      console.error(
        "Require User Middleware Error:",
        error
      );

      return res.status(500).render(
        "error",
        {
          title:
            "Authentication Error",

          message:
            "Unable to verify your account. Please log in again.",
        }
      );
    }
  }

  function requireAdmin(req, res, next) {
    if (!req.session?.admin) {
      return res.redirect("/adminlogin");
    }

    next();
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

  function validateBookingDates(
    checkin,
    checkout
  ) {
    const start =
      parseBookingDate(checkin);

    const end =
      parseBookingDate(checkout);

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

  // ============================================================
  // DOUBLE-BOOKING DETECTION
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
        $in: [
          "pending",
          "accepted",
        ],
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
  // SERVER-SIDE PRICE CALCULATION
  // ============================================================

  function calculateBookingPrice({
    room,
    cottageAddon,
    checkin,
    checkout,
  }) {
    return Appointment.calculatePrice({
      room,
      cottageAddon,
      checkin,
      checkout,
    });
  }

  // ============================================================
  // NOTIFICATION GENERATOR
  // ============================================================

  function generateNotifications(
    appointments
  ) {
    if (
      !Array.isArray(appointments) ||
      appointments.length === 0
    ) {
      return [];
    }

    const notifications = [];

    for (const appointment of appointments) {
      const roomName =
        appointment.roomDisplayName ||
        appointment.room ||
        "your selected accommodation";

      const checkin =
        appointment.checkin
          ? new Date(
              appointment.checkin
            ).toLocaleDateString(
              "en-US",
              {
                year: "numeric",
                month: "long",
                day: "numeric",
              }
            )
          : "your selected date";

      const checkout =
        appointment.checkout
          ? new Date(
              appointment.checkout
            ).toLocaleDateString(
              "en-US",
              {
                year: "numeric",
                month: "long",
                day: "numeric",
              }
            )
          : "your selected date";

      if (
        appointment.status ===
        "pending"
      ) {
        notifications.push({
          id:
            `${appointment._id}-pending`,

          type:
            "pending",

          icon:
            "🕐",

          title:
            "Booking Request Received",

          message:
            `Your ${roomName} booking request ` +
            `for ${checkin} to ${checkout} ` +
            `is currently waiting for confirmation.`,

          bookingId:
            appointment._id,

          createdAt:
            appointment.createdAt ||
            new Date(),
        });
      }

      if (
        appointment.status ===
        "accepted"
      ) {
        notifications.push({
          id:
            `${appointment._id}-accepted`,

          type:
            "accepted",

          icon:
            "✅",

          title:
            "Booking Confirmed!",

          message:
            `Great news! Your ${roomName} booking ` +
            `for ${checkin} to ${checkout} ` +
            `has been accepted. Your stay is confirmed.`,

          bookingId:
            appointment._id,

          createdAt:
            appointment.updatedAt ||
            appointment.createdAt ||
            new Date(),
        });
      }

      if (
        appointment.status ===
        "declined"
      ) {
        notifications.push({
          id:
            `${appointment._id}-declined`,

          type:
            "declined",

          icon:
            "❌",

          title:
            "Booking Declined",

          message:
            `Unfortunately, your ${roomName} booking ` +
            `for ${checkin} to ${checkout} ` +
            `has been declined. Please contact ` +
            `the resort if you need assistance.`,

          bookingId:
            appointment._id,

          createdAt:
            appointment.updatedAt ||
            appointment.createdAt ||
            new Date(),
        });
      }

      if (
        appointment.status ===
        "cancelled"
      ) {
        notifications.push({
          id:
            `${appointment._id}-cancelled`,

          type:
            "cancelled",

          icon:
            "🚫",

          title:
            "Booking Cancelled",

          message:
            `Your ${roomName} booking for ` +
            `${checkin} to ${checkout} ` +
            `has been cancelled.`,

          bookingId:
            appointment._id,

          createdAt:
            appointment.updatedAt ||
            appointment.createdAt ||
            new Date(),
        });
      }
    }

    notifications.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() -
        new Date(a.createdAt).getTime()
    );

    return notifications;
  }

  // ============================================================
  // DATABASE
  // ============================================================

  async function connectDB() {
    try {
      await mongoose.connect(
        MONGODB_URI
      );

      console.log(
        "✅ Database: Puffer Isle Resort Linked"
      );

      await createDefaultAdmin();

    } catch (error) {
      console.error(
        "❌ Database connection failed:",
        error
      );

      process.exit(1);
    }
  }

  // ============================================================
  // DEFAULT ADMIN
  // ============================================================
async function createDefaultAdmin() {
  try {
    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (!adminUsername || !adminPassword) {
      console.warn(
        "⚠️ ADMIN_USERNAME / ADMIN_PASSWORD not configured."
      );
      return;
    }

    const username = String(adminUsername)
      .trim()
      .toLowerCase();

    const password = String(adminPassword);

    let admin = await Admin.findOne({
      username,
    }).select("+password");

    if (!admin) {
      admin = new Admin({
        username,
        password,
      });

      await admin.save();

      console.log(
        `✅ Default admin created: ${username}`
      );
    } else {
      // Keep the .env password synchronized with MongoDB.
      admin.password = password;
      await admin.save();

      console.log(
        `✅ Admin credentials synchronized: ${username}`
      );
    }
  } catch (error) {
    console.error("❌ Admin setup error:", error);
  }
}

  // ============================================================
  // ADMIN LOGIN PAGE
  // ============================================================

  app.get(
    "/adminlogin",
    (req, res) => {
      if (req.session?.admin) {
        return res.redirect(
          "/admin/dashboard"
        );
      }

      res.render(
        "admin/adminlogin",
        {
          title:
            "Admin Portal",

          error:
            null,
        }
      );
    }
  );

  // ============================================================
  // ADMIN LOGIN
  // ============================================================

  app.post(
    "/admin/login",
    async (req, res) => {
      try {
        const {
          email,
          password,
        } = req.body;

        if (
          !email ||
          !password
        ) {
          return res.status(400).render(
            "admin/adminlogin",
            {
              title:
                "Admin Portal",

              error:
                "Username and password are required.",
            }
          );
        }

        const username =
          String(email)
            .trim()
            .toLowerCase();

        const admin =
  await Admin.findOne({
    username,
  }).select("+password");

        if (
          !admin ||
          !(await admin.comparePassword(
            password
          ))
        ) {
          return res.status(401).render(
            "admin/adminlogin",
            {
              title:
                "Admin Portal",

              error:
                "Access Denied. Invalid Credentials.",
            }
          );
        }

        req.session.regenerate(
          (sessionError) => {
            if (sessionError) {
              console.error(
                "Admin Session Error:",
                sessionError
              );

              return res.status(500).render(
                "admin/adminlogin",
                {
                  title:
                    "Admin Portal",

                  error:
                    "Unable to create secure session.",
                }
              );
            }

            req.session.admin = {
              id:
                admin._id.toString(),

              username:
                admin.username,

              role:
                "admin",
            };

            req.session.save(
              (saveError) => {
                if (saveError) {
                  console.error(
                    "Admin Session Save Error:",
                    saveError
                  );

                  return res.status(500).render(
                    "admin/adminlogin",
                    {
                      title:
                        "Admin Portal",

                      error:
                        "Unable to save secure session.",
                    }
                  );
                }

                return res.redirect(
                  "/admin/dashboard"
                );
              }
            );
          }
        );

      } catch (error) {
        console.error(
          "Admin Login Error:",
          error
        );

        return res.status(500).render(
          "admin/adminlogin",
          {
            title:
              "Admin Portal",

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

  app.get(
    "/admin/dashboard",
    requireAdmin,
    async (req, res) => {
      try {
        const [
          totalBookings,
          totalUsers,
          inHouseCount,
          recentBookings,
        ] = await Promise.all([
          Appointment.countDocuments(),

          User.countDocuments(),

          Appointment.countDocuments({
            checkedIn: true,
          }),

          Appointment.find()
            .populate(
              "userId",
              "fullname email"
            )
            .sort({
              createdAt: -1,
            })
            .limit(5)
            .lean(),
        ]);

        res.render(
          "admin/dashboard",
          {
            title:
              "Isle Command",

            totalBookings,

            totalUsers,

            inHouseCount,

            recentBookings,
          }
        );

      } catch (error) {
        console.error(
          "Dashboard Error:",
          error
        );

        res.status(500).send(
          "Error loading dashboard."
        );
      }
    }
  );

  // ============================================================
  // ADMIN HISTORY
  // ============================================================

  app.get(
    "/admin/history",
    requireAdmin,
    async (req, res) => {
      try {
        const allBookings =
          await Appointment.find()
            .populate(
              "userId",
              "fullname email"
            )
            .sort({
              createdAt: -1,
            })
            .lean();

        res.render(
          "admin/history",
          {
            title:
              "Isle Archive",

            allBookings,
          }
        );

      } catch (error) {
        console.error(
          "History Page Error:",
          error
        );

        res.status(500).send(
          "Error loading archive data."
        );
      }
    }
  );

  // ============================================================
  // FRONT DESK CHECK-IN
  // ============================================================

  app.get(
    "/admin/checkin-manager",
    requireAdmin,
    async (req, res) => {
      try {
        const [
          arrivals,
          inHouse,
        ] = await Promise.all([
          Appointment.find({
            status:
              "accepted",

            checkedIn:
              false,
          })
            .populate(
              "userId"
            )
            .sort({
              checkin: 1,
            })
            .lean(),

          Appointment.find({
            checkedIn:
              true,
          })
            .populate(
              "userId"
            )
            .sort({
              checkInTime: -1,
            })
            .lean(),
        ]);

        res.render(
          "admin/checkin",
          {
            arrivals,

            inHouse,

            title:
              "Front Desk Operations",
          }
        );

      } catch (error) {
        console.error(
          "Front Desk Error:",
          error
        );

        res.status(500).send(
          "Mainframe Error Loading Front Desk."
        );
      }
    }
  );

  // ============================================================
  // ADMIN CHECK-IN UPDATE
  // ============================================================

  app.post(
    "/admin/update-checkin",
    requireAdmin,
    async (req, res) => {
      try {
        const {
          bookingId,
          checkedIn,
        } = req.body;

        if (
          !isValidObjectId(
            bookingId
          )
        ) {
          return res.status(400).json({
            success: false,

            message:
              "Invalid booking ID.",
          });
        }

        const isCheckedIn =
          checkedIn === true ||
          checkedIn === "true" ||
          checkedIn === "on";

        const updatedBooking =
          await Appointment.findByIdAndUpdate(
            bookingId,
            {
              $set: {
                checkedIn:
                  isCheckedIn,

                checkInTime:
                  isCheckedIn
                    ? new Date()
                    : null,
              },
            },
            {
              new: true,

              runValidators:
                true,
            }
          );

        if (!updatedBooking) {
          return res.status(404).json({
            success: false,

            message:
              "Booking not found.",
          });
        }

        res.json({
          success: true,

          booking: {
            id:
              updatedBooking._id,

            checkedIn:
              updatedBooking.checkedIn,
          },
        });

      } catch (error) {
        console.error(
          "Check-in Update Error:",
          error
        );

        res.status(500).json({
          success: false,

          message:
            "Failed to update check-in status.",
        });
      }
    }
  );

  // ============================================================
  // ADMIN BOOKING STATUS UPDATE
  // ============================================================

  app.post(
    "/admin/booking/update-status",
    requireAdmin,
    async (req, res) => {
      try {
        const {
          bookingId,
          status,
        } = req.body;

        const allowedStatuses = [
          "pending",
          "accepted",
          "declined",
          "cancelled",
        ];

        if (
          !isValidObjectId(
            bookingId
          )
        ) {
          return res.status(400).json({
            success: false,

            message:
              "Invalid booking ID.",
          });
        }

        if (
          !allowedStatuses.includes(
            status
          )
        ) {
          return res.status(400).json({
            success: false,

            message:
              "Invalid booking status.",
          });
        }

        const booking =
          await Appointment.findById(
            bookingId
          );

        if (!booking) {
          return res.status(404).json({
            success: false,

            message:
              "Booking not found.",
          });
        }

        // ------------------------------------------------------
        // Validate status transitions
        // ------------------------------------------------------

        if (
          booking.status ===
          "cancelled"
        ) {
          return res.status(400).json({
            success: false,

            message:
              "A cancelled booking cannot be changed.",
          });
        }

        if (
          booking.status ===
          "declined" &&
          status === "accepted"
        ) {
          return res.status(400).json({
            success: false,

            message:
              "A declined booking cannot be accepted.",
          });
        }

        // ------------------------------------------------------
        // Double-booking protection on acceptance
        // ------------------------------------------------------

        if (
          status ===
          "accepted"
        ) {
          const conflict =
            await findConflictingBooking({
              room:
                booking.room,

              checkin:
                booking.checkin,

              checkout:
                booking.checkout,

              excludeId:
                booking._id,
            });

          if (conflict) {
            return res.status(409).json({
              success: false,

              code:
                "ROOM_ALREADY_BOOKED",

              message:
                "This room is already booked for part or all of these dates. The booking cannot be accepted.",

              conflictingBookingId:
                conflict._id,
            });
          }
        }

        booking.status =
          status;

        await booking.save();

        console.log(
          `🔔 Booking ${bookingId} ` +
          `status changed to ${status}`
        );

        res.json({
          success: true,

          message:
            `Booking status updated to ${status}.`,

          booking: {
            id:
              booking._id,

            status:
              booking.status,
          },
        });

      } catch (error) {
        console.error(
          "Booking Status Update Error:",
          error
        );

        res.status(500).json({
          success: false,

          message:
            "Booking status update failed.",
        });
      }
    }
  );

  // ============================================================
  // ADMIN LOGOUT
  // ============================================================

  app.get(
    "/admin/logout",
    (req, res) => {
      req.session.destroy(
        (error) => {
          if (error) {
            console.error(
              "Admin Logout Error:",
              error
            );

            return res.status(500).send(
              "Unable to log out."
            );
          }

          res.clearCookie(
            "connect.sid"
          );

          return res.redirect(
            "/adminlogin"
          );
        }
      );
    }
  );

  // ============================================================
  // USER SIGNUP
  // ============================================================

  app.post(
    "/signup",
    async (req, res) => {
      try {
        const {
          fullname,
          email,
          password,
          phone,
        } = req.body;

        if (
          !fullname ||
          !email ||
          !password
        ) {
          return res.status(400).send(
            "Full name, email and password are required."
          );
        }

        const normalizedEmail =
          String(email)
            .trim()
            .toLowerCase();

        const existingUser =
          await User.findOne({
            email:
              normalizedEmail,
          });

        if (existingUser) {
          return res.status(400).send(
            "Account already exists."
          );
        }

        const newUser =
          new User({
            fullname:
              String(fullname)
                .trim(),

            email:
              normalizedEmail,

            password,

            phone:
              phone
                ? String(phone).trim()
                : "",
          });

        await newUser.save();

        // ------------------------------------------------------
        // Create a fresh authenticated session
        // ------------------------------------------------------

        req.session.regenerate(
          (sessionError) => {
            if (sessionError) {
              console.error(
                "Signup Session Error:",
                sessionError
              );

              return res.status(500).send(
                "Account created, but login could not be established. Please log in."
              );
            }

            req.session.userId =
              newUser._id.toString();

            req.session.save(
              (saveError) => {
                if (saveError) {
                  console.error(
                    "Signup Session Save Error:",
                    saveError
                  );

                  return res.status(500).send(
                    "Account created, but login could not be established. Please log in."
                  );
                }

                return res.redirect(
                  "/profile"
                );
              }
            );
          }
        );

      } catch (error) {
        console.error(
          "Signup Error:",
          error
        );

        res.status(500).send(
          "Signup error."
        );
      }
    }
  );

  // ============================================================
  // USER LOGIN
  // ============================================================

  app.post(
    "/login",
    async (req, res) => {
      try {
        const {
          username,
          password,
        } = req.body;

        if (
          !username ||
          !password
        ) {
          return res.status(400).send(
            "Email and password are required."
          );
        }

        const email =
          String(username)
            .trim()
            .toLowerCase();

        const user =
          await User.findOne({
            email,
          });

        if (
          !user ||
          !(await user.comparePassword(
            password
          ))
        ) {
          return res.status(401).send(
            "Invalid credentials."
          );
        }

        // ------------------------------------------------------
        // Prevent session fixation
        // ------------------------------------------------------

        req.session.regenerate(
          (sessionError) => {
            if (sessionError) {
              console.error(
                "Session Regeneration Error:",
                sessionError
              );

              return res.status(500).send(
                "Login failed. Please try again."
              );
            }

            req.session.userId =
              user._id.toString();

            req.session.save(
              (saveError) => {
                if (saveError) {
                  console.error(
                    "Session Save Error:",
                    saveError
                  );

                  return res.status(500).send(
                    "Login failed. Please try again."
                  );
                }

                console.log(
                  `✅ User logged in: ${user.email}`
                );

                return res.redirect(
                  "/profile"
                );
              }
            );
          }
        );

      } catch (error) {
        console.error(
          "Login Error:",
          error
        );

        res.status(500).send(
          "Login error."
        );
      }
    }
  );

  // ============================================================
  // USER LOGOUT
  // ============================================================

  app.get(
    "/logout",
    (req, res) => {
      req.session.destroy(
        (error) => {
          if (error) {
            console.error(
              "Logout Error:",
              error
            );

            return res.status(500).send(
              "Unable to log out."
            );
          }

          res.clearCookie(
            "connect.sid"
          );

          return res.redirect("/");
        }
      );
    }
  );

  // ============================================================
  // PROFILE
  // ============================================================

  app.get(
    "/profile",
    requireUser,
    async (req, res) => {
      try {
        const user =
          req.currentUser;

        const appointments =
          await Appointment.find({
            userId:
              user._id,
          })
            .sort({
              createdAt: -1,
            })
            .lean();

        const notifications =
          generateNotifications(
            appointments
          );

        return res.render(
          "profile",
          {
            title:
              "My Dashboard",

            user,

            appointments,

            notifications,
          }
        );

      } catch (error) {
        console.error(
          "Profile Load Error:",
          error
        );

        return res.status(500).render(
          "error",
          {
            title:
              "Profile Error",

            message:
              "Unable to load your profile. Please try again.",
          }
        );
      }
    }
  );

  // ============================================================
  // LIVE USER UPDATES
  // ============================================================

  app.get(
    "/userUpdates/:id",
    requireUser,
    async (req, res) => {
      try {
        const requestedUserId =
          req.params.id;

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

        const loggedInUserId =
          req.session.userId.toString();

        if (
          loggedInUserId !==
          requestedUserId.toString()
        ) {
          return res.status(403).json({
            success: false,

            message:
              "Unauthorized.",
          });
        }

        const appointments =
          await Appointment.find({
            userId:
              requestedUserId,
          })
            .sort({
              createdAt: -1,
            })
            .lean();

        const notifications =
          generateNotifications(
            appointments
          );

        res.json({
          success: true,

          appointments,

          notifications,
        });

      } catch (error) {
        console.error(
          "User Updates Error:",
          error
        );

        res.status(500).json({
          success: false,

          message:
            "Unable to fetch updates.",
        });
      }
    }
  );

  // ============================================================
  // BOOKING PAGE
  // ============================================================

  app.get(
    "/booking",
    requireUser,
    (req, res) => {
      res.render(
        "appointments",
        {
          title:
            "Book Your Stay",

          error:
            req.query.error ||
            null,

          success:
            req.query.success ||
            null,
        }
      );
    }
  );

  // ============================================================
  // BOOKING SUBMISSION
  // ============================================================

  app.post(
    "/booking/submit",
    requireUser,
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
          req.session.userId;

        // ------------------------------------------------------
        // Required fields
        // ------------------------------------------------------

        if (
          !room ||
          !checkin ||
          !checkout ||
          !guests ||
          !contact
        ) {
          return res.redirect(
            "/booking?error=missing_fields"
          );
        }

        // ------------------------------------------------------
        // Room validation
        // ------------------------------------------------------

        const allowedRooms = [
          "Aircon Room",
          "Fan Room",
          "Seaside Cottage",
        ];

        if (
          !allowedRooms.includes(
            room
          )
        ) {
          return res.redirect(
            "/booking?error=invalid_room"
          );
        }

        // ------------------------------------------------------
        // Guest validation
        // ------------------------------------------------------

        const guestCount =
          Number(guests);

        const guestLimits = {
          "Aircon Room": 8,
          "Fan Room": 6,
          "Seaside Cottage": 6,
        };

        const maximumGuests =
          guestLimits[room];

        if (
          !Number.isInteger(
            guestCount
          ) ||
          guestCount < 1 ||
          guestCount > maximumGuests
        ) {
          return res.redirect(
            "/booking?error=invalid_guests"
          );
        }

        // ------------------------------------------------------
        // Date validation
        // ------------------------------------------------------

        const dateValidation =
          validateBookingDates(
            checkin,
            checkout
          );

        if (
          !dateValidation.valid
        ) {
          return res.redirect(
            "/booking?error=invalid_dates"
          );
        }

        const {
          start,
          end,
        } = dateValidation;

        // ------------------------------------------------------
        // Prevent past bookings
        // ------------------------------------------------------

        const now =
          new Date();

        const todayStart =
          new Date(
            now.getFullYear(),
            now.getMonth(),
            now.getDate()
          );

        if (
          start < todayStart
        ) {
          return res.redirect(
            "/booking?error=past_date"
          );
        }

        // ------------------------------------------------------
        // Cottage add-on
        // ------------------------------------------------------

        const hasCottageAddon =
          cottageAddon === "on" ||
          cottageAddon === true ||
          cottageAddon === "true";

        const finalCottageAddon =
          room === "Seaside Cottage"
            ? false
            : hasCottageAddon;

        // ------------------------------------------------------
        // Double-booking detection
        // ------------------------------------------------------

        const conflictingBooking =
          await findConflictingBooking({
            room,

            checkin:
              start,

            checkout:
              end,
          });

        if (
          conflictingBooking
        ) {
          console.warn(
            "⚠️ Double booking prevented:",
            {
              room,

              requestedCheckin:
                start,

              requestedCheckout:
                end,

              conflictingBooking:
                conflictingBooking._id,
            }
          );

          return res.redirect(
            "/booking?error=room_unavailable"
          );
        }

        // ------------------------------------------------------
        // Server-side price calculation
        // ------------------------------------------------------

        const pricing =
          calculateBookingPrice({
            room,

            cottageAddon:
              finalCottageAddon,

            checkin:
              start,

            checkout:
              end,
          });

        // ------------------------------------------------------
        // Create booking
        // ------------------------------------------------------

        const newBooking =
          new Appointment({
            userId,

            room,

            cottageAddon:
              finalCottageAddon,

            guests:
              guestCount,

            contact:
              String(contact).trim(),

            checkin:
              start,

            checkout:
              end,

            specialRequests:
              specialRequests
                ? String(
                    specialRequests
                  ).trim()
                : "",

            totalPrice:
              pricing.totalPrice,

            status:
              "pending",
          });

        await newBooking.save();

        console.log(
          "✅ New booking created:",
          {
            id:
              newBooking._id.toString(),

            room:
              newBooking.room,

            checkin:
              newBooking.checkin,

            checkout:
              newBooking.checkout,

            nights:
              pricing.nights,

            totalPrice:
              pricing.totalPrice,
          }
        );

        return res.redirect(
          "/profile?success=booked"
        );

      } catch (error) {
        console.error(
          "❌ Booking Submission Error:",
          error
        );

        if (
          error.name ===
          "ValidationError"
        ) {
          return res.redirect(
            "/booking?error=invalid_booking"
          );
        }

        return res.redirect(
          "/booking?error=failed"
        );
      }
    }
  );

  // ============================================================
  // USER APPOINTMENT CANCELLATION
  // ============================================================

  app.post(
    "/appointment/cancel/:appointmentId",
    requireUser,
    async (req, res) => {
      try {
        const {
          appointmentId,
        } = req.params;

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

        // ------------------------------------------------------
        // Ownership check
        // ------------------------------------------------------

        if (
          appointment.userId.toString() !==
          req.session.userId.toString()
        ) {
          return res.status(403).json({
            success: false,

            message:
              "Unauthorized action.",
          });
        }

        // ------------------------------------------------------
        // Status validation
        // ------------------------------------------------------

        if (
          appointment.status ===
          "declined"
        ) {
          return res.status(400).json({
            success: false,

            message:
              "A declined booking cannot be cancelled.",
          });
        }

        if (
          appointment.status ===
          "cancelled"
        ) {
          return res.status(400).json({
            success: false,

            message:
              "This booking has already been cancelled.",
          });
        }

        // ------------------------------------------------------
        // Preserve booking history
        // ------------------------------------------------------

        appointment.status =
          "cancelled";

        await appointment.save();

        console.log(
          `🗑️ Booking ${appointmentId} cancelled by user.`
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
            "Failed to cancel appointment.",
        });
      }
    }
  );

  // ============================================================
  // PUBLIC PAGES
  // ============================================================

  app.get(
    "/",
    (req, res) => {
      res.render(
        "index",
        {
          title:
            "Puffer Isle Resort",
        }
      );
    }
  );

  app.get(
    "/gallery",
    (req, res) => {
      res.render(
        "gallery",
        {
          title:
            "Explore Resort",
        }
      );
    }
  );

  app.get(
    "/rules",
    (req, res) => {
      res.render(
        "rules",
        {
          title:
            "Island Rules",
        }
      );
    }
  );

  // ============================================================
  // 404
  // ============================================================

  app.use(
    (req, res) => {
      // Prefer the custom EJS page when it exists.
      // If views/404.ejs is missing, return a simple HTML
      // fallback instead of throwing another view-lookup error.
      res.status(404).render(
        "404",
        {
          title:
            "404 - Lost in Paradise",
        },
        (renderError, html) => {
          if (renderError) {
            console.error(
              "404 View Error:",
              renderError
            );

            return res.status(404).send(`
              <!DOCTYPE html>
              <html lang="en">
              <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>404 - Lost in Paradise</title>
                <style>
                  body {
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    background: #003f3f;
                    color: #fff;
                  }
                  main {
                    padding: 40px;
                  }
                  h1 {
                    margin: 0 0 12px;
                    font-size: 72px;
                  }
                  p {
                    margin: 0 0 24px;
                    opacity: 0.8;
                  }
                  a {
                    display: inline-block;
                    padding: 12px 20px;
                    border-radius: 10px;
                    background: #ffd700;
                    color: #111;
                    text-decoration: none;
                    font-weight: 700;
                  }
                </style>
              </head>
              <body>
                <main>
                  <h1>404</h1>
                  <p>The page you're looking for could not be found.</p>
                  <a href="/">Return to Puffer Isle</a>
                </main>
              </body>
              </html>
            `);
          }

          return res.send(html);
        }
      );
    }
  );

  // ============================================================
  // GLOBAL ERROR HANDLER
  // ============================================================

  app.use(
    (error, req, res, next) => {
      console.error(
        "Unhandled Server Error:",
        error
      );

      if (res.headersSent) {
        return next(error);
      }

      // Prefer the custom error EJS page. If it is missing,
      // provide a plain HTML fallback instead of throwing a
      // second "Failed to lookup view" error.
      res.status(500).render(
        "error",
        {
          title:
            "Server Error",

          message:
            "Something went wrong. Please try again later.",
        },
        (renderError, html) => {
          if (renderError) {
            console.error(
              "Error View Error:",
              renderError
            );

            return res.status(500).send(`
              <!DOCTYPE html>
              <html lang="en">
              <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Error</title>
                <style>
                  body {
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    background: #003f3f;
                    color: #fff;
                  }
                  main {
                    padding: 40px;
                  }
                  h1 {
                    margin: 0 0 12px;
                  }
                  p {
                    margin: 0;
                    opacity: 0.8;
                  }
                </style>
              </head>
              <body>
                <main>
                  <h1>Something went wrong</h1>
                  <p>Please try again later.</p>
                </main>
              </body>
              </html>
            `);
          }

          return res.send(html);
        }
      );
    }
  );

  // ============================================================
  // START SERVER
  // ============================================================

  async function startServer() {
    await connectDB();

    app.listen(
      PORT,
      () => {
        console.log(
          `🚀 Isle RMS Active: http://localhost:${PORT}`
        );

        console.log(
          "🏝️ Puffer Isle Resort System Ready"
        );
      }
    );
  }

  startServer()
    .catch((error) => {
      console.error(
        "❌ Failed to start server:",
        error
      );

      process.exit(1);
    });

  // ============================================================
  // EXPORT APP
  // ============================================================

  module.exports = app;