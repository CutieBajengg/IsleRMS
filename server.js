"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * server.js
 *
 * Main application/bootstrap server.
 * ============================================================
 */

const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const dotenv = require("dotenv");
const MongoStore = require("connect-mongo");

const User = require("./models/User");
const Admin = require("./models/Admin");

const userRoutes = require("./routes/userRoutes");
const adminRoutes = require("./routes/adminRoutes");

dotenv.config();

/* ============================================================
   APPLICATION
   ============================================================ */

const app = express();

/* ============================================================
   ENVIRONMENT
   ============================================================ */

const NODE_ENV = String(
  process.env.NODE_ENV || "development"
)
  .trim()
  .toLowerCase();

const IS_PRODUCTION =
  NODE_ENV === "production";

const PORT = Number(
  process.env.PORT || 5000
);

const HOST =
  process.env.HOST ||
  (IS_PRODUCTION
    ? "0.0.0.0"
    : "127.0.0.1");

/* ------------------------------------------------------------
   MongoDB
------------------------------------------------------------ */

const DEFAULT_LOCAL_MONGO_URI =
  "mongodb://localhost:27017/puffer_isle_resort";

const RAW_MONGO_URI = String(
  process.env.MONGO_URI ||
    process.env.MONGODB_URI ||
    ""
).trim();

/*
 * Treat placeholder values as missing configuration.
 */
const PLACEHOLDER_MONGO_VALUES = [
  "your_existing_mongodb_connection",
  "your_mongodb_connection_string",
  "mongodb_connection_string",
  "your_existing_mongodb_uri"
];

const MONGO_URI =
  PLACEHOLDER_MONGO_VALUES.includes(
    RAW_MONGO_URI
  )
    ? ""
    : RAW_MONGO_URI;

const SESSION_SECRET =
  String(
    process.env.SESSION_SECRET || ""
  ).trim();

const SESSION_NAME =
  String(
    process.env.SESSION_NAME ||
      "islerms.sid"
  ).trim();

const ADMIN_USERNAME =
  String(
    process.env.ADMIN_USERNAME || ""
  ).trim();

const ADMIN_PASSWORD =
  String(
    process.env.ADMIN_PASSWORD || ""
  );

/* ============================================================
   CONSTANTS
   ============================================================ */

const EFFECTIVE_MONGO_URI =
  MONGO_URI ||
  DEFAULT_LOCAL_MONGO_URI;

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 8;

const JSON_LIMIT =
  process.env.JSON_LIMIT ||
  "1mb";

const URLENCODED_LIMIT =
  process.env.URLENCODED_LIMIT ||
  "1mb";

/* ============================================================
   ENVIRONMENT VALIDATION
   ============================================================ */

function validateEnvironment() {
  const errors = [];

  if (
    !Number.isInteger(PORT) ||
    PORT < 1 ||
    PORT > 65535
  ) {
    errors.push(
      "PORT must be a valid TCP port."
    );
  }

  if (!MONGO_URI) {
    if (IS_PRODUCTION) {
      errors.push(
        "MONGO_URI is required in production."
      );
    }
  } else if (
    !MONGO_URI.startsWith(
      "mongodb://"
    ) &&
    !MONGO_URI.startsWith(
      "mongodb+srv://"
    )
  ) {
    errors.push(
      "MONGO_URI must start with mongodb:// or mongodb+srv://."
    );
  }

  if (!SESSION_SECRET) {
    if (IS_PRODUCTION) {
      errors.push(
        "SESSION_SECRET is required in production."
      );
    }
  } else if (
    IS_PRODUCTION &&
    SESSION_SECRET.length < 32
  ) {
    errors.push(
      "SESSION_SECRET should contain at least 32 characters in production."
    );
  }

  if (
    IS_PRODUCTION &&
    !ADMIN_USERNAME
  ) {
    console.warn(
      "⚠️ ADMIN_USERNAME is not configured. Default admin creation will be skipped."
    );
  }

  if (
    IS_PRODUCTION &&
    !ADMIN_PASSWORD
  ) {
    console.warn(
      "⚠️ ADMIN_PASSWORD is not configured. Default admin creation will be skipped."
    );
  }

  if (
    RAW_MONGO_URI &&
    !MONGO_URI
  ) {
    console.warn(
      "⚠️ Placeholder MongoDB URI detected. Using local MongoDB instead."
    );
  }

  if (errors.length > 0) {
    const message = [
      "Environment validation failed:",
      ...errors.map(
        (error) =>
          `- ${error}`
      )
    ].join("\n");

    throw new Error(
      message
    );
  }
}

validateEnvironment();

/* ============================================================
   DATABASE FALLBACK
   ============================================================ */

if (!MONGO_URI) {
  console.warn(
    "ℹ️ MONGO_URI was not provided. Using local MongoDB:",
    DEFAULT_LOCAL_MONGO_URI
  );
}

/* ============================================================
   SESSION SECRET
   ============================================================ */

const EFFECTIVE_SESSION_SECRET =
  SESSION_SECRET ||
  "dev-only-puffer-isle-session-secret-change-me";

/* ============================================================
   EXPRESS HARDENING
   ============================================================ */

app.disable(
  "x-powered-by"
);

if (IS_PRODUCTION) {
  app.set(
    "trust proxy",
    1
  );
}

/* ============================================================
   VIEW ENGINE
   ============================================================ */

app.set(
  "view engine",
  "ejs"
);

app.set(
  "views",
  path.join(
    __dirname,
    "views"
  )
);

/* ============================================================
   BODY PARSING
   ============================================================ */

app.use(
  express.urlencoded({
    extended: true,
    limit:
      URLENCODED_LIMIT
  })
);

app.use(
  express.json({
    limit:
      JSON_LIMIT
  })
);

/* ============================================================
   STATIC FILES
   ============================================================ */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    ),
    {
      index: false,
      redirect: false,
      maxAge:
        IS_PRODUCTION
          ? "7d"
          : 0
    }
  )
);

/* ============================================================
   REQUEST METADATA
   ============================================================ */

app.use(
  (req, res, next) => {
    res.locals.requestMethod =
      req.method;

    res.locals.requestPath =
      req.path;

    next();
  }
);

/* ============================================================
   SESSION
   ============================================================ */

app.use(
  session({
    name:
      SESSION_NAME,

    secret:
      EFFECTIVE_SESSION_SECRET,

    resave: false,

    saveUninitialized:
      false,

    rolling:
      true,

    store:
      MongoStore.create({
        mongoUrl:
          EFFECTIVE_MONGO_URI,

        collectionName:
          "sessions",

        ttl:
          Math.floor(
            SESSION_MAX_AGE /
              1000
          ),

        autoRemove:
          "native",

        touchAfter:
          60 * 5,

        stringify:
          false
      }),

    cookie: {
      httpOnly:
        true,

      secure:
        IS_PRODUCTION,

      sameSite:
        "lax",

      maxAge:
        SESSION_MAX_AGE,

      path:
        "/"
    }
  })
);

/* ============================================================
   SESSION HELPERS
   ============================================================ */

function createUserSessionData(
  user
) {
  if (!user) {
    return null;
  }

  const id =
    user._id
      ? String(
          user._id
        )
      : String(
          user.id || ""
        );

  const fullname =
    String(
      user.fullname ||
        user.name ||
        ""
    ).trim();

  const username =
    String(
      user.username ||
        user.email ||
        ""
    )
      .trim()
      .toLowerCase();

  const email =
    String(
      user.email || ""
    )
      .trim()
      .toLowerCase();

  const phone =
    String(
      user.phone || ""
    ).trim();

  return {
    id,
    _id: id,
    username,
    email,
    fullname,
    phone,
    name: fullname
  };
}

function createAdminSessionData(
  admin
) {
  if (!admin) {
    return null;
  }

  const id =
    admin._id
      ? String(
          admin._id
        )
      : String(
          admin.id || ""
        );

  return {
    id,
    _id: id,

    username:
      String(
        admin.username ||
          ""
      )
        .trim()
        .toLowerCase(),

    role:
      admin.role ||
      "admin"
  };
}

/* ============================================================
   SESSION PROMISE HELPERS
   ============================================================ */

function regenerateSession(
  req
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
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

function saveSession(
  req
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
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

function destroySession(
  req
) {
  return new Promise(
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
}

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */

function requireUser(
  req,
  res,
  next
) {
  if (!req.session?.user) {
    return res.redirect(
      "/?auth=login&error=" +
        encodeURIComponent(
          "Please log in to continue."
        )
    );
  }

  next();
}

function requireAdmin(
  req,
  res,
  next
) {
  if (!req.session?.admin) {
    return res.redirect(
      "/admin/login?error=" +
        encodeURIComponent(
          "Administrator login required."
        )
    );
  }

  next();
}

/* ============================================================
   GLOBAL EJS LOCALS
   ============================================================ */

app.use(
  (req, res, next) => {
    const currentUser =
      req.session?.user ||
      null;

    const currentAdmin =
      req.session?.admin ||
      null;

    res.locals.currentUser =
      currentUser;

    res.locals.currentAdmin =
      currentAdmin;

    res.locals.user =
      currentUser;

    res.locals.admin =
      currentAdmin;

    res.locals.isAuthenticated =
      Boolean(
        currentUser
      );

    res.locals.isAdmin =
      Boolean(
        currentAdmin
      );

    res.locals.currentPath =
      req.path;

    res.locals.error =
      req.query?.error ||
      null;

    res.locals.success =
      req.query?.success ||
      null;

    res.locals.authMode =
      req.query?.auth ||
      null;

    next();
  }
);

/* ============================================================
   HEALTH CHECK
   ============================================================ */

app.get(
  "/health",
  (req, res) => {
    const mongoReady =
      mongoose.connection
        .readyState === 1;

    return res
      .status(
        mongoReady
          ? 200
          : 503
      )
      .json({
        success:
          mongoReady,

        status:
          mongoReady
            ? "ok"
            : "degraded",

        server:
          "online",

        database:
          mongoReady
            ? "connected"
            : "disconnected",

        environment:
          NODE_ENV,

        uptimeSeconds:
          Math.floor(
            process.uptime()
          ),

        timestamp:
          new Date().toISOString()
      });
  }
);

/* ============================================================
   READINESS CHECK
   ============================================================ */

app.get(
  "/ready",
  (req, res) => {
    const mongoReady =
      mongoose.connection
        .readyState === 1;

    if (!mongoReady) {
      return res
        .status(503)
        .json({
          success: false,
          ready: false,
          database:
            "disconnected"
        });
    }

    return res.json({
      success: true,
      ready: true,
      database:
        "connected"
    });
  }
);

/* ============================================================
   USER LOGIN PAGE
   ============================================================ */

app.get(
  "/login",
  (req, res) => {
    if (req.session?.user) {
      return res.redirect(
        "/profile"
      );
    }

    const query =
      new URLSearchParams();

    query.set(
      "auth",
      "login"
    );

    if (req.query?.error) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    if (req.query?.success) {
      query.set(
        "success",
        String(
          req.query.success
        )
      );
    }

    return res.redirect(
      `/?${query.toString()}`
    );
  }
);

/* ============================================================
   USER LOGIN
   ============================================================ */

app.post(
  "/login",
  async (req, res) => {
    try {
      const identifier =
        String(
          req.body?.username ||
            req.body?.email ||
            ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password ||
            ""
        );

      if (
        !identifier ||
        !password
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Username/email and password are required."
            )
        );
      }

      const user =
        await User.findOne({
          $or: [
            {
              username:
                identifier
            },
            {
              email:
                identifier
            }
          ]
        }).select(
          "+password"
        );

      if (!user) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Invalid username/email or password."
            )
        );
      }

      let passwordValid =
        false;

      if (
        typeof user.comparePassword ===
        "function"
      ) {
        passwordValid =
          await user.comparePassword(
            password
          );
      } else {
        passwordValid =
          user.password ===
          password;
      }

      if (!passwordValid) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Invalid username/email or password."
            )
        );
      }

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      req.session.admin =
        null;

      await saveSession(
        req
      );

      return res.redirect(
        "/profile"
      );
    } catch (error) {
      console.error(
        "USER LOGIN ERROR:",
        error
      );

      return res.redirect(
        "/?auth=login&error=" +
          encodeURIComponent(
            "Unable to process login. Please try again."
          )
      );
    }
  }
);

/* ============================================================
   USER SIGNUP PAGE
   ============================================================ */

app.get(
  "/signup",
  (req, res) => {
    if (req.session?.user) {
      return res.redirect(
        "/profile"
      );
    }

    const query =
      new URLSearchParams();

    query.set(
      "auth",
      "signup"
    );

    if (req.query?.error) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    if (req.query?.success) {
      query.set(
        "success",
        String(
          req.query.success
        )
      );
    }

    return res.redirect(
      `/?${query.toString()}`
    );
  }
);

/* ============================================================
   USER SIGNUP
   ============================================================ */

app.post(
  "/signup",
  async (req, res) => {
    try {
      const fullname =
        String(
          req.body?.fullname ||
            req.body?.fullName ||
            req.body?.name ||
            ""
        ).trim();

      const email =
        String(
          req.body?.email ||
            ""
        )
          .trim()
          .toLowerCase();

      const username =
        String(
          req.body?.username ||
            email ||
            ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password ||
            ""
        );

      const confirmPassword =
        String(
          req.body?.confirmPassword ||
            ""
        );

      const phone =
        String(
          req.body?.phone ||
            ""
        ).trim();

      if (
        !fullname ||
        !email ||
        !password
      ) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "Full name, email and password are required."
            )
        );
      }

      if (
        password.length < 6
      ) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "Password must be at least 6 characters."
            )
        );
      }

      if (
        confirmPassword &&
        password !==
          confirmPassword
      ) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "Passwords do not match."
            )
        );
      }

      if (
        phone &&
        !/^\d{11}$/.test(
          phone
        )
      ) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "Contact number must contain exactly 11 digits."
            )
        );
      }

      const existingUser =
        await User.findOne({
          $or: [
            {
              email
            },
            {
              username
            }
          ]
        });

      if (existingUser) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "An account with that email or username already exists."
            )
        );
      }

      const user =
        new User({
          fullname,
          username,
          email,
          phone:
            phone || undefined
        });

      if (
        typeof user.setPassword ===
        "function"
      ) {
        await user.setPassword(
          password
        );
      } else {
        user.password =
          password;
      }

      await user.save();

      return res.redirect(
        "/?auth=login&success=" +
          encodeURIComponent(
            "Account created successfully. Please sign in."
          )
      );
    } catch (error) {
      console.error(
        "USER SIGNUP ERROR:",
        error
      );

      if (
        error?.code === 11000
      ) {
        return res.redirect(
          "/?auth=signup&error=" +
            encodeURIComponent(
              "An account with that email or username already exists."
            )
        );
      }

      return res.redirect(
        "/?auth=signup&error=" +
          encodeURIComponent(
            "Unable to create your account. Please try again."
          )
      );
    }
  }
);

/* ============================================================
   USER LOGOUT
   ============================================================ */

app.get(
  "/logout",
  async (req, res) => {
    try {
      await destroySession(
        req
      );

      res.clearCookie(
        SESSION_NAME,
        {
          httpOnly: true,
          sameSite: "lax",
          secure:
            IS_PRODUCTION,
          path: "/"
        }
      );

      return res.redirect(
        "/?auth=login&success=" +
          encodeURIComponent(
            "You have been logged out."
          )
      );
    } catch (error) {
      console.error(
        "USER LOGOUT ERROR:",
        error
      );

      return res.redirect(
        "/"
      );
    }
  }
);

/* ============================================================
   ADMIN LOGIN COMPATIBILITY
   ============================================================ */

app.get(
  "/adminlogin",
  (req, res) => {
    const query =
      new URLSearchParams();

    if (req.query?.error) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    const suffix =
      query.toString()
        ? `?${query.toString()}`
        : "";

    return res.redirect(
      `/admin/login${suffix}`
    );
  }
);

/* ============================================================
   ADMIN LOGOUT COMPATIBILITY
   ============================================================ */

app.get(
  "/admin-logout",
  async (req, res) => {
    try {
      await destroySession(
        req
      );

      res.clearCookie(
        SESSION_NAME,
        {
          httpOnly: true,
          sameSite: "lax",
          secure:
            IS_PRODUCTION,
          path: "/"
        }
      );

      return res.redirect(
        "/admin/login"
      );
    } catch (error) {
      console.error(
        "ADMIN LOGOUT ERROR:",
        error
      );

      return res.redirect(
        "/admin/login"
      );
    }
  }
);

/* ============================================================
   LEGACY BOOKING URL
   ============================================================ */

app.use(
  (req, res, next) => {
    if (
      req.method ===
        "POST" &&
      req.path ===
        "/booking/submit"
    ) {
      req.url =
        "/appointment/submit";

      return next();
    }

    next();
  }
);

/* ============================================================
   ROUTES
   ============================================================ */

app.use(
  "/",
  userRoutes
);

app.use(
  "/admin",
  adminRoutes
);

/* ============================================================
   PUBLIC PAGES
   ============================================================ */

app.get(
  "/",
  (req, res) => {
    return res.render(
      "index",
      {
        title:
          "Puffer Isle Resort"
      }
    );
  }
);

app.get(
  "/gallery",
  (req, res) => {
    return res.render(
      "gallery",
      {
        title:
          "Gallery | Puffer Isle Resort"
      }
    );
  }
);

app.get(
  "/rules",
  (req, res) => {
    return res.render(
      "rules",
      {
        title:
          "Resort Rules | Puffer Isle Resort"
      }
    );
  }
);

/* ============================================================
   404
   ============================================================ */

app.use(
  (req, res) => {
    const isApi =
      req.path.startsWith(
        "/admin/api/"
      ) ||
      req.path ===
        "/health" ||
      req.path ===
        "/ready";

    if (isApi) {
      return res
        .status(404)
        .json({
          success:
            false,

          message:
            "Resource not found."
        });
    }

    return res
      .status(404)
      .render(
        "error",
        {
          title:
            "Page Not Found | Puffer Isle Resort",

          statusCode:
            404,

          error:
            "The page you requested could not be found."
        }
      );
  }
);

/* ============================================================
   GLOBAL ERROR HANDLER
   ============================================================ */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "UNHANDLED APPLICATION ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    const isApi =
      req.path.startsWith(
        "/admin/api/"
      ) ||
      req.path ===
        "/health" ||
      req.path ===
        "/ready";

    if (isApi) {
      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Internal server error."
        });
    }

    return res
      .status(500)
      .render(
        "error",
        {
          title:
            "Server Error | Puffer Isle Resort",

          statusCode:
            500,

          error:
            IS_PRODUCTION
              ? "Something went wrong while processing your request."
              : error.message ||
                "Something went wrong."
        }
      );
  }
);

/* ============================================================
   DATABASE
   ============================================================ */

async function connectDatabase() {
  console.log(
    "🔌 Connecting to MongoDB..."
  );

  await mongoose.connect(
    EFFECTIVE_MONGO_URI,
    {
      serverSelectionTimeoutMS:
        10000,

      connectTimeoutMS:
        10000,

      socketTimeoutMS:
        45000,

      maxPoolSize:
        IS_PRODUCTION
          ? 20
          : 10,

      minPoolSize:
        IS_PRODUCTION
          ? 2
          : 0,

      autoIndex:
        !IS_PRODUCTION
    }
  );

  console.log(
    `✅ MongoDB connected: ${mongoose.connection.name}`
  );
}

/* ============================================================
   DATABASE EVENTS
   ============================================================ */

mongoose.connection.on(
  "connected",
  () => {
    console.log(
      "🟢 Mongoose connection established."
    );
  }
);

mongoose.connection.on(
  "error",
  (error) => {
    console.error(
      "🔴 MongoDB connection error:",
      error
    );
  }
);

mongoose.connection.on(
  "disconnected",
  () => {
    console.warn(
      "🟡 MongoDB disconnected."
    );
  }
);

/* ============================================================
   DEFAULT ADMIN
   ============================================================ */

async function ensureDefaultAdmin() {
  if (
    !ADMIN_USERNAME ||
    !ADMIN_PASSWORD
  ) {
    console.warn(
      "⚠️ ADMIN_USERNAME / ADMIN_PASSWORD not configured. Default admin creation skipped."
    );

    return;
  }

  const normalizedUsername =
    ADMIN_USERNAME
      .trim()
      .toLowerCase();

  try {
    let admin =
      await Admin.findOne({
        username:
          normalizedUsername
      }).select(
        "+password"
      );

    if (!admin) {
      admin =
        new Admin({
          username:
            normalizedUsername
        });

      if (
        typeof admin.setPassword ===
        "function"
      ) {
        await admin.setPassword(
          ADMIN_PASSWORD
        );
      } else {
        admin.password =
          ADMIN_PASSWORD;
      }

      await admin.save();

      console.log(
        `✅ Default admin created: ${normalizedUsername}`
      );

      return;
    }

    console.log(
      `ℹ️ Admin account already exists: ${normalizedUsername}`
    );
  } catch (error) {
    console.error(
      "❌ Unable to ensure default admin:",
      error
    );

    if (IS_PRODUCTION) {
      throw error;
    }
  }
}

/* ============================================================
   START SERVER
   ============================================================ */

let httpServer =
  null;

async function startServer() {
  try {
    console.log("");

    console.log(
      "=============================================="
    );

    console.log(
      "🏝️  PUFFER ISLE RESORT | IsleRMS"
    );

    console.log(
      "=============================================="
    );

    console.log(
      `🧭 Environment: ${NODE_ENV}`
    );

    console.log(
      `📡 Host: ${HOST}`
    );

    console.log(
      `🔌 Port: ${PORT}`
    );

    await connectDatabase();

    await ensureDefaultAdmin();

    httpServer =
      app.listen(
        PORT,
        HOST,
        () => {
          console.log("");

          console.log(
            "✅ SERVER STARTED"
          );

          console.log(
            "----------------------------------------------"
          );

          if (
            HOST ===
            "127.0.0.1"
          ) {
            console.log(
              `🌐 Local: http://localhost:${PORT}`
            );
          } else {
            console.log(
              `🌐 Listening on ${HOST}:${PORT}`
            );
          }

          console.log(
            "🔐 Admin: /admin/login"
          );

          console.log(
            "❤️  Health: /health"
          );

          console.log(
            "✅ Ready: /ready"
          );

          console.log(
            `🗄️ MongoDB: ${mongoose.connection.name}`
          );

          console.log(
            "=============================================="
          );

          console.log("");
        }
      );
  } catch (error) {
    console.error("");

    console.error(
      "❌ SERVER STARTUP FAILED"
    );

    console.error(
      "----------------------------------------------"
    );

    console.error(
      error.message
    );

    console.error(
      "----------------------------------------------"
    );

    if (
      String(
        error.message
      ).includes(
        "ECONNREFUSED"
      )
    ) {
      console.error(
        "💡 Make sure MongoDB is running."
      );
    }

    if (
      String(
        error.message
      )
        .toLowerCase()
        .includes(
          "authentication failed"
        )
    ) {
      console.error(
        "💡 Check your MongoDB credentials."
      );
    }

    process.exit(1);
  }
}

/* ============================================================
   GRACEFUL SHUTDOWN
   ============================================================ */

let shuttingDown =
  false;

async function gracefulShutdown(
  signal
) {
  if (shuttingDown) {
    return;
  }

  shuttingDown =
    true;

  console.log("");

  console.log(
    `🛑 ${signal} received. Starting graceful shutdown...`
  );

  if (httpServer) {
    await new Promise(
      (resolve) => {
        httpServer.close(
          () => {
            console.log(
              "🌐 HTTP server closed."
            );

            resolve();
          }
        );
      }
    );
  }

  try {
    await mongoose.connection.close(
      false
    );

    console.log(
      "🗄️ MongoDB connection closed."
    );
  } catch (error) {
    console.error(
      "Error closing MongoDB:",
      error
    );
  }

  console.log(
    "✅ Shutdown complete."
  );

  process.exit(0);
}

/* ============================================================
   PROCESS SIGNALS
   ============================================================ */

process.on(
  "SIGINT",
  () => {
    gracefulShutdown(
      "SIGINT"
    );
  }
);

process.on(
  "SIGTERM",
  () => {
    gracefulShutdown(
      "SIGTERM"
    );
  }
);

process.on(
  "unhandledRejection",
  (reason) => {
    console.error(
      "UNHANDLED PROMISE REJECTION:",
      reason
    );
  }
);

process.on(
  "uncaughtException",
  (error) => {
    console.error(
      "UNCAUGHT EXCEPTION:",
      error
    );

    gracefulShutdown(
      "UNCAUGHT_EXCEPTION"
    ).catch(
      () =>
        process.exit(1)
    );
  }
);

/* ============================================================
   EXPORTS
   ============================================================ */

module.exports = {
  app,
  startServer,
  requireUser,
  requireAdmin,
  createUserSessionData,
  createAdminSessionData,
  regenerateSession,
  saveSession,
  destroySession
};

/* ============================================================
   START
   ============================================================ */

if (
  require.main ===
  module
) {
  startServer();
}