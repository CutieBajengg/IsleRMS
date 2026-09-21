"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * server.js
 *
 * Main application/bootstrap server.
 *
 * AUTHENTICATION STEP 2
 * ------------------------------------------------------------
 * Customer authentication improvements:
 *
 * - Passwords are loaded explicitly with .select("+password")
 * - Account status is checked during login
 * - Failed-login lockout is enforced
 * - Expired login locks are cleared
 * - Successful login resets login-security counters
 * - Sessions are regenerated after authentication
 * - Customer username is optional
 * - Email remains the primary customer login identifier
 * - Server-side password confirmation is required
 * - Password minimum matches User.js
 * - Philippine phone numbers are normalized
 * - Plain-text password fallback removed
 * - POST /logout is canonical
 * - Temporary GET /logout compatibility retained
 *
 * STEP 3 CSRF PROTECTION
 * ------------------------------------------------------------
 * - CSRF token generated per session
 * - Token exposed to all EJS views as csrfToken
 * - Customer authentication POSTs are CSRF protected
 * - POST /login protected
 * - POST /signup protected
 * - POST /logout protected
 *
 * NOT YET INCLUDED:
 * - CSRF protection for booking/customer update actions
 * - CSRF protection for admin actions
 * - Login/signup rate limiting
 *
 * Those are handled in later steps so each security change
 * can be tested separately.
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

const {
  attachCsrfToken,
  verifyCsrfToken,
} = require("./middleware/csrf");

/* ============================================================
   ENVIRONMENT
   ============================================================ */

dotenv.config();

/* ============================================================
   APPLICATION
   ============================================================ */

const app = express();

/* ============================================================
   ENVIRONMENT CONFIGURATION
   ============================================================ */

const NODE_ENV = String(
  process.env.NODE_ENV || "development"
)
  .trim()
  .toLowerCase();

const IS_PRODUCTION = NODE_ENV === "production";

const PORT = Number(process.env.PORT || 5000);

const HOST =
  String(process.env.HOST || "").trim() ||
  (IS_PRODUCTION ? "0.0.0.0" : "127.0.0.1");

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

const PLACEHOLDER_MONGO_VALUES = [
  "your_existing_mongodb_connection",
  "your_mongodb_connection_string",
  "mongodb_connection_string",
  "your_existing_mongodb_uri",
];

const MONGO_URI =
  PLACEHOLDER_MONGO_VALUES.includes(RAW_MONGO_URI)
    ? ""
    : RAW_MONGO_URI;

/* ------------------------------------------------------------
   Session
   ------------------------------------------------------------ */

const SESSION_SECRET = String(
  process.env.SESSION_SECRET || ""
).trim();

const SESSION_NAME =
  String(
    process.env.SESSION_NAME || "islerms.sid"
  ).trim() || "islerms.sid";

/* ------------------------------------------------------------
   Default admin
   ------------------------------------------------------------ */

const ADMIN_USERNAME = String(
  process.env.ADMIN_USERNAME || ""
).trim();

const ADMIN_PASSWORD = String(
  process.env.ADMIN_PASSWORD || ""
);

/* ============================================================
   CONSTANTS
   ============================================================ */

const EFFECTIVE_MONGO_URI =
  MONGO_URI || DEFAULT_LOCAL_MONGO_URI;

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 8; // 8 hours

const PASSWORD_MIN_LENGTH = 10;

const JSON_LIMIT =
  process.env.JSON_LIMIT || "1mb";

const URLENCODED_LIMIT =
  process.env.URLENCODED_LIMIT || "1mb";
  const USER_IDLE_TIMEOUT_MINUTES = Math.max(
  1,
  Number(process.env.USER_IDLE_TIMEOUT_MINUTES || 30)
);

const USER_IDLE_TIMEOUT_MS =
  USER_IDLE_TIMEOUT_MINUTES * 60 * 1000;

const USER_ACTIVITY_WRITE_INTERVAL_MS =
  60 * 1000;

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
    !MONGO_URI.startsWith("mongodb://") &&
    !MONGO_URI.startsWith("mongodb+srv://")
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
      "SESSION_SECRET must contain at least 32 characters in production."
    );
  }

  if (IS_PRODUCTION && !ADMIN_USERNAME) {
    console.warn(
      "⚠️ ADMIN_USERNAME is not configured. Default admin creation will be skipped."
    );
  }

  if (IS_PRODUCTION && !ADMIN_PASSWORD) {
    console.warn(
      "⚠️ ADMIN_PASSWORD is not configured. Default admin creation will be skipped."
    );
  }

  if (RAW_MONGO_URI && !MONGO_URI) {
    console.warn(
      "⚠️ Placeholder MongoDB URI detected. Using local MongoDB instead."
    );
  }

  if (errors.length > 0) {
    const message = [
      "Environment validation failed:",
      ...errors.map(
        (error) => `- ${error}`
      ),
    ].join("\n");

    throw new Error(message);
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

/**
 * Development fallback only.
 *
 * Production requires SESSION_SECRET.
 */

const EFFECTIVE_SESSION_SECRET =
  SESSION_SECRET ||
  "dev-only-puffer-isle-session-secret-change-me";

/* ============================================================
   EXPRESS HARDENING
   ============================================================ */

app.disable("x-powered-by");

if (IS_PRODUCTION) {
  /**
   * IsleRMS is expected to run behind a reverse proxy
   * such as DigitalOcean's deployment stack / Nginx.
   */
  app.set("trust proxy", 1);
}

/* ============================================================
   VIEW ENGINE
   ============================================================ */

app.set("view engine", "ejs");

app.set(
  "views",
  path.join(__dirname, "views")
);

/* ============================================================
   BODY PARSING
   ============================================================ */

app.use(
  express.urlencoded({
    extended: true,
    limit: URLENCODED_LIMIT,
  })
);

app.use(
  express.json({
    limit: JSON_LIMIT,
  })
);

/* ============================================================
   STATIC FILES
   ============================================================ */

app.use(
  express.static(
    path.join(__dirname, "public"),
    {
      index: false,
      redirect: false,
      maxAge: IS_PRODUCTION ? "7d" : 0,
    }
  )
);

/* ============================================================
   REQUEST METADATA
   ============================================================ */

app.use((req, res, next) => {
  res.locals.requestMethod = req.method;
  res.locals.requestPath = req.path;

  next();
});

/* ============================================================
   SESSION
   ============================================================ */

app.use(
  session({
    name: SESSION_NAME,

    secret: EFFECTIVE_SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    rolling: true,

    store: MongoStore.create({
      mongoUrl: EFFECTIVE_MONGO_URI,
      collectionName: "sessions",

      ttl: Math.floor(
        SESSION_MAX_AGE / 1000
      ),

      autoRemove: "native",

      touchAfter: 60 * 5,

      stringify: false,
    }),

    cookie: {
      httpOnly: true,

      secure: IS_PRODUCTION,

      sameSite: "lax",

      maxAge: SESSION_MAX_AGE,

      path: "/",
    },
  })
);

/* ============================================================
   CSRF TOKEN
   ============================================================ */

/**
 * CSRF is being introduced in two stages.
 *
 * Stage 1:
 * - Generate one random token per session.
 * - Expose it to every EJS view as `csrfToken`.
 *
 * Stage 2:
 * - Verify the token for the customer authentication
 *   POST requests that already include CSRF fields.
 *
 * Booking and admin actions will be protected separately
 * after their forms are updated.
 */

app.use(
  attachCsrfToken
);

/* ============================================================
   CSRF VERIFICATION - CUSTOMER AUTHENTICATION
   ============================================================ */

/**
 * Protect only the customer authentication endpoints
 * that already contain CSRF fields in navbar.ejs.
 *
 * Protected:
 * - POST /login
 * - POST /signup
 * - POST /logout
 *
 * Other POST requests remain untouched for now so we
 * do not break the older booking/admin forms.
 */

app.use(
  (req, res, next) => {
    if (
      req.method === "POST" &&
      (
        req.path === "/login" ||
        req.path === "/signup" ||
        req.path === "/logout"
      )
    ) {
      return verifyCsrfToken(
        req,
        res,
        next
      );
    }

    next();
  }
);

/* ============================================================
   USER SESSION DATA
   ============================================================ */

/**
 * Only safe customer information belongs in the session.
 *
 * NEVER store:
 * - password
 * - password reset tokens
 * - email verification tokens
 * - failed-login counters
 * - lockedUntil
 */

function createUserSessionData(user) {
  if (!user) {
    return null;
  }

  const id = user._id
    ? String(user._id)
    : String(user.id || "");

  const fullname = String(
    user.fullname ||
      user.name ||
      ""
  ).trim();

  const username = String(
    user.username || ""
  )
    .trim()
    .toLowerCase();

  const email = String(
    user.email || ""
  )
    .trim()
    .toLowerCase();

  const phone = String(
    user.phone || ""
  ).trim();

  return {
    id,
    _id: id,

    fullname,
    name: fullname,

    username,

    email,

    phone,

    status:
      user.status || "active",

    emailVerified:
      Boolean(user.emailVerified),
  };
}

/* ============================================================
   ADMIN SESSION DATA
   ============================================================ */

function createAdminSessionData(admin) {
  if (!admin) {
    return null;
  }

  const id = admin._id
    ? String(admin._id)
    : String(admin.id || "");

  return {
    id,
    _id: id,

    username: String(
      admin.username || ""
    )
      .trim()
      .toLowerCase(),

    role:
      admin.role || "admin",
  };
}

/* ============================================================
   SESSION PROMISE HELPERS
   ============================================================ */

function regenerateSession(req) {
  return new Promise(
    (resolve, reject) => {
      req.session.regenerate(
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

function destroySession(req) {
  return new Promise(
    (resolve, reject) => {
      if (!req.session) {
        return resolve();
      }

      req.session.destroy(
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

/* ============================================================
   AUTH HELPERS
   ============================================================ */

function getSessionUserId(req) {
  return (
    req.session?.user?.id ||
    req.session?.user?._id ||
    null
  );
}

function clearSessionCookie(res) {
  res.clearCookie(
    SESSION_NAME,
    {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION,
      path: "/",
    }
  );
}

function redirectAuthError(
  res,
  mode,
  message
) {
  return res.redirect(
    303,
    `/?auth=${encodeURIComponent(
      mode
    )}&error=${encodeURIComponent(
      message
    )}`
  );
}

function redirectAuthSuccess(
  res,
  mode,
  message
) {
  return res.redirect(
    303,
    `/?auth=${encodeURIComponent(
      mode
    )}&success=${encodeURIComponent(
      message
    )}`
  );
}

/* ============================================================
   INPUT NORMALIZATION
   ============================================================ */

function normalizeString(value) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

function normalizeEmail(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function normalizeIdentifier(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function normalizeUsername(value) {
  const username = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "");

  return username || "";
}

/**
 * Normalize Philippine mobile numbers.
 *
 * Accepted:
 * - 09XXXXXXXXX
 * - 639XXXXXXXXX
 * - +639XXXXXXXXX
 */

function normalizePhone(value) {
  let phone = String(value ?? "")
    .trim()
    .replace(/[\s()-]/g, "");

  if (!phone) {
    return "";
  }

  if (/^\+639\d{9}$/.test(phone)) {
    return `0${phone.slice(3)}`;
  }

  if (/^639\d{9}$/.test(phone)) {
    return `0${phone.slice(2)}`;
  }

  return phone;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidUsername(username) {
  return /^[a-z0-9._-]+$/i.test(
    username
  );
}

function isDuplicateKeyError(error) {
  return Boolean(
    error && error.code === 11000
  );
}

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */

/**
 * Session-level customer authentication check.
 *
 * This currently validates the authenticated session itself.
 * Live account-state verification against MongoDB will be
 * centralized later when userRoutes.js is refactored.
 */

function requireUser(
  req,
  res,
  next
) {
  const sessionUser =
    req.session?.user;

  if (!sessionUser) {
    return res.redirect(
      "/?auth=login&error=" +
        encodeURIComponent(
          "Please log in to continue."
        )
    );
  }

  if (
    sessionUser.status &&
    sessionUser.status !== "active"
  ) {
    return destroySession(req)
      .catch((error) => {
        console.error(
          "SESSION CLEANUP ERROR:",
          error
        );
      })
      .finally(() => {
        clearSessionCookie(res);

        res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Your account is currently unavailable."
            )
        );
      });
  }

  next();
}

/**
 * Administrator session-level authentication.
 */

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
      req.session?.user || null;

    const currentAdmin =
      req.session?.admin || null;

    res.locals.currentUser =
      currentUser;

    res.locals.currentAdmin =
      currentAdmin;

    /**
     * Compatibility aliases for existing views.
     */
    res.locals.user =
      currentUser;

    res.locals.admin =
      currentAdmin;

    res.locals.isAuthenticated =
      Boolean(currentUser);

    res.locals.isAdmin =
      Boolean(currentAdmin);

    res.locals.currentPath =
      req.path;

    res.locals.error =
      req.query?.error || null;

    res.locals.success =
      req.query?.success || null;

    res.locals.authMode =
      req.query?.auth || null;

    /*
     * CSRF token generated by middleware/csrf.js.
     *
     * Keep this available to all EJS templates.
     */
    res.locals.csrfToken =
      res.locals.csrfToken ||
      req.session?.csrfToken ||
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
      mongoose.connection.readyState === 1;

    const payload = {
      success: mongoReady,

      status: mongoReady
        ? "ok"
        : "degraded",

      server: "online",

      database: mongoReady
        ? "connected"
        : "disconnected",

      uptimeSeconds:
        Math.floor(
          process.uptime()
        ),

      timestamp:
        new Date().toISOString(),
    };

    if (!IS_PRODUCTION) {
      payload.environment =
        NODE_ENV;
    }

    return res
      .status(
        mongoReady ? 200 : 503
      )
      .json(payload);
  }
);

/* ============================================================
   READINESS CHECK
   ============================================================ */

app.get(
  "/ready",
  (req, res) => {
    const mongoReady =
      mongoose.connection.readyState === 1;

    if (!mongoReady) {
      return res
        .status(503)
        .json({
          success: false,
          ready: false,
          database: "disconnected",
        });
    }

    return res.json({
      success: true,
      ready: true,
      database: "connected",
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
        String(req.query.error)
      );
    }

    if (req.query?.success) {
      query.set(
        "success",
        String(req.query.success)
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
      /**
       * Login accepts either:
       * - email
       * - username
       *
       * The new navbar uses "email" as its field name,
       * while legacy forms may still send "username".
       */

      const identifier =
        normalizeIdentifier(
          req.body?.email ||
            req.body?.username ||
            ""
        );

      const password =
        String(
          req.body?.password || ""
        );

      if (
        !identifier ||
        !password
      ) {
        return redirectAuthError(
          res,
          "login",
          "Email/username and password are required."
        );
      }

      /**
       * Find by email OR username.
       *
       * User.js intentionally hides password by default,
       * so select("+password") is required for comparison.
       */

      if (
        typeof User.findByIdentifier !==
        "function"
      ) {
        throw new Error(
          "User.findByIdentifier() is unavailable."
        );
      }

      const user =
        await User.findByIdentifier(
          identifier
        ).select("+password");

      /**
       * Generic authentication error.
       *
       * We do not expose whether an account exists.
       */

      if (!user) {
        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      /**
       * Clear an expired lockout.
       */

      if (
        user.lockedUntil &&
        user.lockedUntil instanceof Date &&
        user.lockedUntil.getTime() <=
          Date.now()
      ) {
        if (
          typeof user.clearExpiredLock ===
          "function"
        ) {
          await user.clearExpiredLock();
        } else {
          user.lockedUntil = null;
          user.failedLoginAttempts = 0;
          await user.save();
        }
      }

      /**
       * Enforce temporary account lockout.
       */

      if (
        typeof user.isCurrentlyLocked ===
        "function" &&
        user.isCurrentlyLocked()
      ) {
        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      /**
       * Account status check.
       *
       * Older accounts without a status field are still
       * treated as active for compatibility.
       */

      if (
        user.status &&
        user.status !== "active"
      ) {
        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      /**
       * Compare only against the bcrypt password hash.
       *
       * There is intentionally NO plaintext fallback.
       */

      const passwordValid =
        typeof user.comparePassword ===
        "function"
          ? await user.comparePassword(
              password
            )
          : false;

      if (!passwordValid) {
        /**
         * Failed login is recorded by User.js.
         */

        if (
          typeof user.recordFailedLogin ===
          "function"
        ) {
          await user.recordFailedLogin();
        }

        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      /**
       * Successful login.
       *
       * Reset failed-login counters and save
       * lastLoginAt.
       */

      if (
        typeof user.resetLoginSecurity ===
        "function"
      ) {
        await user.resetLoginSecurity();
      }

      /**
       * Regenerate the session after authentication.
       *
       * This prevents session fixation attacks.
       */

      await regenerateSession(req);

      req.session.user =
        createUserSessionData(
          user
        );

      /**
       * Customer sessions do not retain admin authentication.
       */

      delete req.session.admin;

      await saveSession(req);

      return res.redirect(
        303,
        "/profile"
      );
    } catch (error) {
      console.error(
        "USER LOGIN ERROR:",
        error
      );

      return redirectAuthError(
        res,
        "login",
        "Unable to process login. Please try again."
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
        String(req.query.error)
      );
    }

    if (req.query?.success) {
      query.set(
        "success",
        String(req.query.success)
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
        normalizeString(
          req.body?.fullname ||
            req.body?.fullName ||
            req.body?.name ||
            ""
        );

      const email =
        normalizeEmail(
          req.body?.email || ""
        );

      /**
       * Username is OPTIONAL.
       *
       * Email remains the primary customer identifier.
       */

      const username =
        normalizeUsername(
          req.body?.username || ""
        );

      const password =
        String(
          req.body?.password || ""
        );

      const confirmPassword =
        String(
          req.body?.confirmPassword || ""
        );

      const phone =
        normalizePhone(
          req.body?.phone || ""
        );

      /* --------------------------------------------------------
         REQUIRED FIELDS
         -------------------------------------------------------- */

      if (
        !fullname ||
        !email ||
        !password ||
        !confirmPassword
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Full name, email, password and password confirmation are required."
        );
      }

      /* --------------------------------------------------------
         FULL NAME
         -------------------------------------------------------- */

      /**
       * User.js currently defines maxlength: 50.
       * Keep server-side validation consistent.
       */

      if (
        fullname.length < 2 ||
        fullname.length > 50
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Full name must contain between 2 and 50 characters."
        );
      }

      /* --------------------------------------------------------
         EMAIL
         -------------------------------------------------------- */

      if (!isValidEmail(email)) {
        return redirectAuthError(
          res,
          "signup",
          "Please provide a valid email address."
        );
      }

      /* --------------------------------------------------------
         PASSWORD
         -------------------------------------------------------- */

      if (
        password.length <
        PASSWORD_MIN_LENGTH
      ) {
        return redirectAuthError(
          res,
          "signup",
          `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`
        );
      }

      /* --------------------------------------------------------
         PASSWORD CONFIRMATION
         -------------------------------------------------------- */

      if (
        password !==
        confirmPassword
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Passwords do not match."
        );
      }

      /* --------------------------------------------------------
         OPTIONAL USERNAME
         -------------------------------------------------------- */

      if (
        username &&
        !isValidUsername(username)
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Username may only contain letters, numbers, dots, underscores, and hyphens."
        );
      }

      if (
        username &&
        (
          username.length < 3 ||
          username.length > 50
        )
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Username must contain between 3 and 50 characters."
        );
      }

      /* --------------------------------------------------------
         PHONE
         -------------------------------------------------------- */

      /**
       * Phone remains optional at the model level.
       */

      if (
        phone &&
        !/^09\d{9}$/.test(phone)
      ) {
        return redirectAuthError(
          res,
          "signup",
          "Please provide a valid Philippine mobile number."
        );
      }

      /* --------------------------------------------------------
         DUPLICATE ACCOUNT CHECK
         -------------------------------------------------------- */

      const duplicateConditions = [
        { email },
      ];

      if (username) {
        duplicateConditions.push({
          username,
        });
      }

      const existingUser =
        await User.findOne({
          $or: duplicateConditions,
        });

      if (existingUser) {
        return redirectAuthError(
          res,
          "signup",
          "An account with that email or username already exists."
        );
      }

      /* --------------------------------------------------------
         CREATE USER
         -------------------------------------------------------- */

      const userData = {
        fullname,
        email,
        phone: phone || undefined,
      };

      if (username) {
        userData.username =
          username;
      }

      const user =
        new User(userData);

      /**
       * User.js setPassword() performs password validation.
       * Its pre-save hook handles bcrypt hashing.
       */

      if (
        typeof user.setPassword !==
        "function"
      ) {
        throw new Error(
          "User password service is unavailable."
        );
      }

      await user.setPassword(
        password
      );

      await user.save();

      return redirectAuthSuccess(
        res,
        "login",
        "Account created successfully. Please sign in."
      );
    } catch (error) {
      console.error(
        "USER SIGNUP ERROR:",
        error
      );

      if (
        isDuplicateKeyError(error)
      ) {
        return redirectAuthError(
          res,
          "signup",
          "An account with that email or username already exists."
        );
      }

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
          "Some account information is invalid.";

        return redirectAuthError(
          res,
          "signup",
          message
        );
      }

      return redirectAuthError(
        res,
        "signup",
        "Unable to create your account. Please try again."
      );
    }
  }
);

/* ============================================================
   USER LOGOUT
   ============================================================ */

/**
 * Canonical logout endpoint.
 *
 * The upgraded navbar submits:
 *
 *     POST /logout
 */

app.post(
  "/logout",
  async (req, res) => {
    try {
      await destroySession(req);

      clearSessionCookie(res);

      return res.redirect(
        303,
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

      clearSessionCookie(res);

      return res.redirect(
        303,
        "/"
      );
    }
  }
);

/* ============================================================
   TEMPORARY GET LOGOUT COMPATIBILITY
   ============================================================ */

/**
 * Temporary compatibility only.
 *
 * The upgraded navbar no longer uses GET /logout.
 *
 * This route can be removed after we confirm that no
 * remaining view depends on it.
 */

app.get(
  "/logout",
  async (req, res) => {
    try {
      await destroySession(req);

      clearSessionCookie(res);

      return res.redirect(
        303,
        "/?auth=login&success=" +
          encodeURIComponent(
            "You have been logged out."
          )
      );
    } catch (error) {
      console.error(
        "USER GET LOGOUT ERROR:",
        error
      );

      clearSessionCookie(res);

      return res.redirect(
        303,
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
        String(req.query.error)
      );
    }

    if (req.query?.success) {
      query.set(
        "success",
        String(req.query.success)
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

/**
 * The administrator authentication system is being
 * upgraded separately.
 *
 * This route remains for compatibility with current
 * administrator templates.
 */

app.get(
  "/admin-logout",
  async (req, res) => {
    try {
      await destroySession(req);

      clearSessionCookie(res);

      return res.redirect(
        303,
        "/admin/login"
      );
    } catch (error) {
      console.error(
        "ADMIN LOGOUT ERROR:",
        error
      );

      clearSessionCookie(res);

      return res.redirect(
        303,
        "/admin/login"
      );
    }
  }
);

/* ============================================================
   LEGACY BOOKING URL
   ============================================================ */

/**
 * Compatibility bridge:
 *
 * POST /booking/submit
 *       ↓
 * POST /appointment/submit
 *
 * This can be removed later when all frontend forms use the
 * canonical endpoint.
 */

app.use(
  (req, res, next) => {
    if (
      req.method === "POST" &&
      req.path === "/booking/submit"
    ) {
      req.url =
        "/appointment/submit";

      return next();
    }

    next();
  }
);

/* ============================================================
   CUSTOMER ROUTES
   ============================================================ */

app.use(
  "/",
  userRoutes
);

/* ============================================================
   ADMIN ROUTES
   ============================================================ */

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
          "Puffer Isle Resort",
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
          "Gallery | Puffer Isle Resort",
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
          "Resort Rules | Puffer Isle Resort",
      }
    );
  }
);

/* ============================================================
   REQUEST TYPE HELPER
   ============================================================ */

function isApiRequest(req) {
  return (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/admin/api/") ||
    req.path === "/health" ||
    req.path === "/ready"
  );
}

/* ============================================================
   404
   ============================================================ */

app.use(
  (req, res) => {
    if (isApiRequest(req)) {
      return res
        .status(404)
        .json({
          success: false,
          message:
            "Resource not found.",
        });
    }

    return res
      .status(404)
      .render(
        "error",
        {
          title:
            "Page Not Found | Puffer Isle Resort",

          statusCode: 404,

          error:
            "The page you requested could not be found.",
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

    if (res.headersSent) {
      return next(error);
    }

    if (isApiRequest(req)) {
      return res
        .status(500)
        .json({
          success: false,
          message:
            "Internal server error.",
        });
    }

    return res
      .status(500)
      .render(
        "error",
        {
          title:
            "Server Error | Puffer Isle Resort",

          statusCode: 500,

          error:
            IS_PRODUCTION
              ? "Something went wrong while processing your request."
              : error.message ||
                "Something went wrong.",
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
      serverSelectionTimeoutMS: 10000,

      connectTimeoutMS: 10000,

      socketTimeoutMS: 45000,

      maxPoolSize:
        IS_PRODUCTION ? 20 : 10,

      minPoolSize:
        IS_PRODUCTION ? 2 : 0,

      /**
       * Development:
       * Mongoose may automatically build indexes.
       *
       * Production:
       * use controlled index deployment.
       */

      autoIndex:
        !IS_PRODUCTION,
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
          normalizedUsername,
      }).select("+password");

    if (!admin) {
      admin =
        new Admin({
          username:
            normalizedUsername,
        });

      /**
       * Prefer the model's setPassword() method when
       * available.
       */

      if (
        typeof admin.setPassword ===
        "function"
      ) {
        await admin.setPassword(
          ADMIN_PASSWORD
        );
      } else {
        /**
         * Admin.js should normally hash the password
         * through its pre-save hook.
         */
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

let httpServer = null;

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
            HOST === "127.0.0.1"
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
            "🔐 User Login: /login"
          );

          console.log(
            "🔐 Admin Login: /admin/login"
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

    const errorMessage =
      String(
        error.message || ""
      );

    if (
      errorMessage.includes(
        "ECONNREFUSED"
      )
    ) {
      console.error(
        "💡 Make sure MongoDB is running."
      );
    }

    if (
      errorMessage
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

let shuttingDown = false;

async function gracefulShutdown(
  signal
) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

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
      () => process.exit(1)
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

  destroySession,

  getSessionUserId,
};

/* ============================================================
   START
   ============================================================ */

if (
  require.main === module
) {
  startServer();
}