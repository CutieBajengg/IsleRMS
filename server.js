"use strict";

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const dotenv = require("dotenv");
const MongoStore = require("connect-mongo");
const nodemailer = require("nodemailer");

dotenv.config();

const User = require("./models/User");
const Admin = require("./models/Admin");

const userRoutes = require("./routes/userRoutes");
const adminRoutes = require("./routes/adminRoutes");
const galleryRoutes = require("./routes/galleryRoutes");

const {
  attachCsrfToken,
  verifyCsrfToken,
} = require("./middleware/csrf");

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

const PORT =
  Number(process.env.PORT || 5000);

const HOST =
  String(process.env.HOST || "").trim() ||
  (IS_PRODUCTION
    ? "0.0.0.0"
    : "127.0.0.1");

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
  PLACEHOLDER_MONGO_VALUES.includes(
    RAW_MONGO_URI
  )
    ? ""
    : RAW_MONGO_URI;

const EFFECTIVE_MONGO_URI =
  MONGO_URI ||
  DEFAULT_LOCAL_MONGO_URI;

const SESSION_SECRET = String(
  process.env.SESSION_SECRET || ""
).trim();

const EFFECTIVE_SESSION_SECRET =
  SESSION_SECRET ||
  "dev-only-puffer-isle-session-secret-change-me";

const SESSION_NAME =
  String(
    process.env.SESSION_NAME ||
      "islerms.sid"
  ).trim() ||
  "islerms.sid";

const ADMIN_SESSION_NAME =
  String(
    process.env.ADMIN_SESSION_NAME ||
      "islerms.admin.sid"
  ).trim() ||
  "islerms.admin.sid";

const ADMIN_USERNAME = String(
  process.env.ADMIN_USERNAME || ""
).trim();

const ADMIN_PASSWORD = String(
  process.env.ADMIN_PASSWORD || ""
);

const MAIL_USER = String(
  process.env.MAIL_USER ||
    process.env.GMAIL_USER ||
    ""
)
  .trim()
  .toLowerCase();

const MAIL_APP_PASSWORD = String(
  process.env.MAIL_APP_PASSWORD ||
    process.env.GMAIL_APP_PASSWORD ||
    ""
)
  .trim()
  .replace(/\s+/g, "");

const MAIL_FROM_NAME = String(
  process.env.MAIL_FROM_NAME ||
    "Puffer Isle Resort"
).trim();

const EMAIL_OTP_ENABLED =
  String(
    process.env.EMAIL_OTP_ENABLED ?? "true"
  )
    .trim()
    .toLowerCase() !== "false";

const GOOGLE_CLIENT_ID = String(
  process.env.GOOGLE_CLIENT_ID || ""
).trim();

const GOOGLE_CLIENT_SECRET = String(
  process.env.GOOGLE_CLIENT_SECRET || ""
).trim();

const GOOGLE_CALLBACK_URL = String(
  process.env.GOOGLE_CALLBACK_URL || ""
).trim();

const TURNSTILE_SITE_KEY = String(
  process.env.TURNSTILE_SITE_KEY || ""
).trim();

const TURNSTILE_SECRET_KEY = String(
  process.env.TURNSTILE_SECRET_KEY || ""
).trim();

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 8;

const PASSWORD_MIN_LENGTH = 10;

const JSON_LIMIT =
  process.env.JSON_LIMIT || "1mb";

const URLENCODED_LIMIT =
  process.env.URLENCODED_LIMIT || "1mb";

/* ============================================================
   SECURITY / AUTH CONSTANTS
============================================================ */

const USER_IDLE_TIMEOUT_MINUTES =
  Math.max(
    1,
    Number(
      process.env.USER_IDLE_TIMEOUT_MINUTES ||
        30
    )
  );

const USER_IDLE_TIMEOUT_MS =
  USER_IDLE_TIMEOUT_MINUTES *
  60 *
  1000;

const USER_ACTIVITY_WRITE_INTERVAL_MS =
  60 * 1000;

const ADMIN_IDLE_TIMEOUT_MINUTES =
  Math.max(
    1,
    Number(
      process.env.ADMIN_IDLE_TIMEOUT_MINUTES ||
        30
    )
  );

const ADMIN_IDLE_TIMEOUT_MS =
  ADMIN_IDLE_TIMEOUT_MINUTES *
  60 *
  1000;

const ADMIN_ACTIVITY_WRITE_INTERVAL_MS =
  60 * 1000;

const ADMIN_SESSION_SECRET =
  String(
    process.env.ADMIN_SESSION_SECRET ||
      ""
  ).trim() ||
  crypto
    .createHash("sha256")
    .update(
      `${EFFECTIVE_SESSION_SECRET}:admin`
    )
    .digest("hex");

const OTP_REQUEST_WINDOW_MS =
  15 * 60 * 1000;

const OTP_MAX_REQUESTS_PER_WINDOW = 5;

const GOOGLE_OAUTH_STATE_MAX_AGE_MS =
  10 * 60 * 1000;

const GOOGLE_PROFILE_COMPLETION_MAX_AGE_MS =
  10 * 60 * 1000;

const PASSWORD_RESET_TOKEN_TTL_MS =
  30 * 60 * 1000;

const PASSWORD_RESET_REQUEST_WINDOW_MS =
  60 * 60 * 1000;

const PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW =
  5;

const otpRequestTracker =
  new Map();

const passwordResetRequestTracker =
  new Map();

let mailTransporter = null;

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

  if (
    !MONGO_URI &&
    IS_PRODUCTION
  ) {
    errors.push(
      "MONGO_URI is required in production."
    );
  } else if (
    MONGO_URI &&
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

  if (
    !SESSION_SECRET &&
    IS_PRODUCTION
  ) {
    errors.push(
      "SESSION_SECRET is required in production."
    );
  } else if (
    IS_PRODUCTION &&
    SESSION_SECRET.length < 32
  ) {
    errors.push(
      "SESSION_SECRET must contain at least 32 characters in production."
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

  if (
    IS_PRODUCTION &&
    GOOGLE_CALLBACK_URL.includes(
      "localhost"
    )
  ) {
    console.warn(
      "⚠️ GOOGLE_CALLBACK_URL points to localhost while NODE_ENV=production."
    );
  }

  if (
    TURNSTILE_SITE_KEY &&
    !TURNSTILE_SECRET_KEY
  ) {
    console.warn(
      "⚠️ TURNSTILE_SITE_KEY is configured but TURNSTILE_SECRET_KEY is missing. Server-side CAPTCHA verification is disabled."
    );
  }

  if (errors.length) {
    throw new Error(
      [
        "Environment validation failed:",
        ...errors.map(
          (error) => `- ${error}`
        ),
      ].join("\n")
    );
  }
}

validateEnvironment();

if (!MONGO_URI) {
  console.warn(
    "ℹ️ MONGO_URI was not provided. Using local MongoDB:",
    DEFAULT_LOCAL_MONGO_URI
  );
}

/* ============================================================
   EXPRESS CONFIGURATION
============================================================ */

app.disable(
  "x-powered-by"
);

app.set(
  "trust proxy",
  IS_PRODUCTION ? 1 : false
);

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
   REQUEST / SECURITY HELPERS
============================================================ */

function isAdminPath(req) {
  const pathname = String(
    req.path || ""
  );

  return (
    pathname === "/admin" ||
    pathname.startsWith(
      "/admin/"
    )
  );
}

function createRequestId() {
  return crypto
    .randomBytes(12)
    .toString("hex");
}

function sanitizeRequestId(value) {
  const candidate = String(
    value || ""
  )
    .trim()
    .slice(0, 100);

  return /^[A-Za-z0-9._:-]+$/.test(
    candidate
  )
    ? candidate
    : null;
}

app.use(
  (
    req,
    res,
    next
  ) => {
    req.requestId =
      sanitizeRequestId(
        req.get(
          "X-Request-ID"
        )
      ) ||
      createRequestId();

    res.setHeader(
      "X-Request-ID",
      req.requestId
    );

    res.setHeader(
      "X-Content-Type-Options",
      "nosniff"
    );

    res.setHeader(
      "Referrer-Policy",
      "strict-origin-when-cross-origin"
    );

    res.setHeader(
      "X-Frame-Options",
      "SAMEORIGIN"
    );

    if (IS_PRODUCTION) {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains"
      );
    }

    next();
  }
);

/* ============================================================
   BODY PARSERS
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
          : 0,
    }
  )
);

app.use(
  (
    req,
    res,
    next
  ) => {
    res.locals.requestMethod =
      req.method;

    res.locals.requestPath =
      req.path;

    next();
  }
);

/* ============================================================
   SESSION STORES
============================================================ */

const userSessionStore =
  MongoStore.create({
    mongoUrl:
      EFFECTIVE_MONGO_URI,

    collectionName:
      "sessions",

    ttl:
      Math.floor(
        SESSION_MAX_AGE / 1000
      ),

    autoRemove:
      "native",

    touchAfter:
      60 * 5,

    stringify:
      false,
  });

const adminSessionStore =
  MongoStore.create({
    mongoUrl:
      EFFECTIVE_MONGO_URI,

    collectionName:
      "admin_sessions",

    ttl:
      Math.floor(
        SESSION_MAX_AGE / 1000
      ),

    autoRemove:
      "native",

    touchAfter:
      60 * 5,

    stringify:
      false,
  });

/* ============================================================
   SESSION MIDDLEWARE
============================================================ */

const userSessionMiddleware =
  session({
    name:
      SESSION_NAME,

    secret:
      EFFECTIVE_SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    rolling:
      true,

    store:
      userSessionStore,

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
        "/",
    },
  });

const adminSessionMiddleware =
  session({
    name:
      ADMIN_SESSION_NAME,

    secret:
      ADMIN_SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    rolling:
      true,

    store:
      adminSessionStore,

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
        "/admin",
    },
  });

/* ============================================================
   SESSION HELPERS
============================================================ */

function regenerateSession(req) {
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

function destroySession(req) {
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

function clearSessionCookie(
  res
) {
  res.clearCookie(
    SESSION_NAME,
    {
      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        IS_PRODUCTION,

      path:
        "/",
    }
  );
}

function clearAdminSessionCookie(
  res
) {
  res.clearCookie(
    ADMIN_SESSION_NAME,
    {
      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        IS_PRODUCTION,

      path:
        "/admin",
    }
  );
}

function getSessionUserId(
  req
) {
  return (
    req.session?.user?.id ||
    req.session?.user?._id ||
    null
  );
}

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
        ""
    )
      .trim()
      .toLowerCase();

  const email =
    String(
      user.email ||
        ""
    )
      .trim()
      .toLowerCase();

  const phone =
    String(
      user.phone ||
        ""
    ).trim();

  return {
    id,

    _id:
      id,

    fullname,

    name:
      fullname,

    username,

    email,

    phone,

    status:
      user.status ||
      "active",

    emailVerified:
      Boolean(
        user.emailVerified
      ),

    authProvider:
      user.authProvider ||
      "local",
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

    _id:
      id,

    username:
      String(
        admin.username ||
          ""
      )
        .trim()
        .toLowerCase(),

    role:
      String(
        admin.role ||
          "admin"
      )
        .trim()
        .toLowerCase(),
  };
}

/* ============================================================
   USER SESSION MOUNTING
============================================================ */

/*
 * Admin paths never enter the customer session middleware.
 */
app.use(
  (
    req,
    res,
    next
  ) => {
    if (
      isAdminPath(req)
    ) {
      return next();
    }

    return userSessionMiddleware(
      req,
      res,
      next
    );
  }
);

/* ============================================================
   ADMIN SESSION ACTIVITY
============================================================ */

function adminActivityMiddleware(
  req,
  res,
  next
) {
  const admin =
    req.session?.admin;

  if (!admin) {
    return next();
  }

  const now =
    Date.now();

  const lastActivity =
    Number(
      req.session
        .adminLastActivityAt ||
        0
    );

  if (
    lastActivity &&
    now -
      lastActivity >
      ADMIN_IDLE_TIMEOUT_MS
  ) {
    return destroySession(
      req
    )
      .catch(
        (error) =>
          console.error(
            "ADMIN IDLE SESSION DESTROY ERROR:",
            error
          )
      )
      .finally(
        () => {
          clearAdminSessionCookie(
            res
          );

          if (
            res.headersSent
          ) {
            return;
          }

          const wantsJson =
            req.path.startsWith(
              "/api/"
            ) ||
            req.xhr ||
            String(
              req.headers.accept ||
                ""
            ).includes(
              "application/json"
            );

          if (
            wantsJson
          ) {
            return res
              .status(401)
              .json({
                success:
                  false,

                code:
                  "ADMIN_SESSION_IDLE_TIMEOUT",

                message:
                  "Your administrator session expired due to inactivity. Please log in again.",

                requestId:
                  req.requestId,
              });
          }

          return res.redirect(
            303,
            "/admin/login?error=" +
              encodeURIComponent(
                "Your administrator session expired due to inactivity."
              )
          );
        }
      );
  }

  if (
    !lastActivity ||
    now -
      lastActivity >=
      ADMIN_ACTIVITY_WRITE_INTERVAL_MS
  ) {
    req.session.adminLastActivityAt =
      now;
  }

  next();
}

app.get(
  "/admin-logout",
  (
    req,
    res
  ) =>
    res.redirect(
      303,
      "/admin/logout"
    )
);

/* ============================================================
   ADMIN ROUTER MOUNT
============================================================ */

app.use(
  "/admin",
  adminSessionMiddleware,
  attachCsrfToken,
  adminActivityMiddleware,
  (
    req,
    res,
    next
  ) => {
    const currentAdmin =
      req.session?.admin ||
      null;

    res.locals.currentAdmin =
      currentAdmin;

    res.locals.admin =
      currentAdmin;

    res.locals.isAdmin =
      Boolean(
        currentAdmin
      );

    res.locals.csrfToken =
      req.session?.csrfToken ||
      null;

    res.locals.captchaSiteKey =
      TURNSTILE_SITE_KEY;

    next();
  },
  galleryRoutes,
  adminRoutes
);

/* ============================================================
   CUSTOMER CSRF TOKEN
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    if (
      isAdminPath(req)
    ) {
      return next();
    }

    return attachCsrfToken(
      req,
      res,
      next
    );
  }
);

/* ============================================================
   CUSTOMER IDLE SESSION
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    if (
      isAdminPath(req)
    ) {
      return next();
    }

    const user =
      req.session?.user;

    if (!user) {
      return next();
    }

    const now =
      Date.now();

    const lastActivity =
      Number(
        req.session
          .lastActivityAt ||
          0
      );

    if (
      lastActivity &&
      now -
        lastActivity >
        USER_IDLE_TIMEOUT_MS
    ) {
      return destroySession(
        req
      )
        .catch(
          (error) =>
            console.error(
              "USER IDLE SESSION DESTROY ERROR:",
              error
            )
        )
        .finally(
          () => {
            clearSessionCookie(
              res
            );

            if (
              res.headersSent
            ) {
              return;
            }

            const wantsJson =
              req.path.startsWith(
                "/api/"
              ) ||
              req.xhr ||
              String(
                req.headers.accept ||
                  ""
              ).includes(
                "application/json"
              );

            if (
              wantsJson
            ) {
              return res
                .status(401)
                .json({
                  success:
                    false,

                  code:
                    "SESSION_IDLE_TIMEOUT",

                  message:
                    "Your session expired due to inactivity. Please log in again.",

                  requestId:
                    req.requestId,
                });
            }

            return res.redirect(
              303,
              "/?auth=login&error=" +
                encodeURIComponent(
                  "Your session expired due to inactivity. Please log in again."
                )
            );
          }
        );
    }

    if (
      !lastActivity ||
      now -
        lastActivity >=
        USER_ACTIVITY_WRITE_INTERVAL_MS
    ) {
      req.session.lastActivityAt =
        now;
    }

    next();
  }
);

/* ============================================================
   CSRF PROTECTION
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    if (
      isAdminPath(req)
    ) {
      return next();
    }

    if (
      ![
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
      ].includes(
        req.method
      )
    ) {
      return next();
    }

    return verifyCsrfToken(
      req,
      res,
      next
    );
  }
);

/* ============================================================
   GLOBAL VIEW LOCALS
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    const currentUser =
      isAdminPath(req)
        ? null
        : req.session?.user ||
          null;

    const currentAdmin =
      isAdminPath(req)
        ? req.session?.admin ||
          null
        : null;

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

    res.locals.authResetToken =
      req.query?.token ||
      req.query?.resetToken ||
      null;

    res.locals.captchaSiteKey =
      TURNSTILE_SITE_KEY;

    res.locals.csrfToken =
      res.locals.csrfToken ||
      req.session?.csrfToken ||
      null;

    next();
  }
);

/* ============================================================
   NORMALIZATION / AUTH HELPERS
============================================================ */

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

function normalizeString(
  value
) {
  return String(
    value ?? ""
  )
    .trim()
    .replace(
      /\s+/g,
      " "
    );
}

function normalizeEmail(
  value
) {
  return String(
    value ?? ""
  )
    .trim()
    .toLowerCase();
}

function normalizeIdentifier(
  value
) {
  return String(
    value ?? ""
  )
    .trim()
    .toLowerCase();
}

function normalizeUsername(
  value
) {
  return (
    String(
      value ?? ""
    )
      .trim()
      .toLowerCase()
      .replace(
        /\s+/g,
        ""
      ) || ""
  );
}

function normalizePhone(
  value
) {
  const phone =
    String(
      value ?? ""
    )
      .trim()
      .replace(
        /[\s()-]/g,
        ""
      );

  if (!phone) {
    return "";
  }

  if (
    /^\+639\d{9}$/.test(
      phone
    )
  ) {
    return `0${phone.slice(
      3
    )}`;
  }

  if (
    /^639\d{9}$/.test(
      phone
    )
  ) {
    return `0${phone.slice(
      2
    )}`;
  }

  return phone;
}

function isValidEmail(
  email
) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidUsername(
  username
) {
  return /^[a-z0-9._-]+$/i.test(
    username
  );
}

function isDuplicateKeyError(
  error
) {
  return Boolean(
    error &&
      error.code === 11000
  );
}

function sanitizeReturnTo(
  value
) {
  const input =
    String(
      value || ""
    ).trim();

  if (!input) {
    return "/";
  }

  if (
    !input.startsWith(
      "/"
    ) ||
    input.startsWith(
      "//"
    )
  ) {
    return "/";
  }

  return input;
}

function getPublicBaseUrl(
  req
) {
  const configured =
    String(
      process.env.APP_BASE_URL ||
        process.env.PUBLIC_APP_URL ||
        ""
    )
      .trim()
      .replace(
        /\/+$/,
        ""
      );

  if (configured) {
    return configured;
  }

  const protocol =
    IS_PRODUCTION
      ? "https"
      : req.protocol;

  return `${protocol}://${String(
    req.get("host") ||
      ""
  ).trim()}`;
}

/* ============================================================
   OPTIONAL TURNSTILE VERIFICATION
============================================================ */

async function verifyTurnstile(
  req
) {
  if (
    !TURNSTILE_SECRET_KEY
  ) {
    return {
      success:
        true,

      skipped:
        true,
    };
  }

  const token =
    String(
      req.body?.captchaToken ||
        req.body?.[
          "cf-turnstile-response"
        ] ||
        req.headers[
          "x-turnstile-token"
        ] ||
        ""
    ).trim();

  if (!token) {
    return {
      success:
        false,

      message:
        "Please complete the security verification and try again.",
    };
  }

  const form =
    new URLSearchParams({
      secret:
        TURNSTILE_SECRET_KEY,

      response:
        token,
    });

  if (req.ip) {
    form.set(
      "remoteip",
      req.ip
    );
  }

  try {
    const response =
      await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        {
          method:
            "POST",

          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded",
          },

          body:
            form,

          signal:
            AbortSignal.timeout(
              10000
            ),
        }
      );

    if (
      !response.ok
    ) {
      return {
        success:
          false,

        message:
          "Security verification is temporarily unavailable. Please try again.",
      };
    }

    const payload =
      await response.json();

    if (
      !payload.success
    ) {
      return {
        success:
          false,

        message:
          "Security verification failed. Please try again.",
      };
    }

    return {
      success:
        true,

      skipped:
        false,
    };
  } catch (
    error
  ) {
    console.error(
      "TURNSTILE VERIFY ERROR:",
      error
    );

    return {
      success:
        false,

      message:
        "Security verification is temporarily unavailable. Please try again.",
    };
  }
}

/* ============================================================
   SIGNUP VALIDATION
============================================================ */

function validateSignupInput(
  body
) {
  const fullname =
    normalizeString(
      body?.fullname ||
        body?.fullName ||
        body?.name ||
        ""
    );

  const email =
    normalizeEmail(
      body?.email ||
        ""
    );

  const username =
    normalizeUsername(
      body?.username ||
        ""
    );

  const password =
    String(
      body?.password ||
        ""
    );

  const confirmPassword =
    String(
      body?.confirmPassword ||
        ""
    );

  const phone =
    normalizePhone(
      body?.phone ||
        ""
    );

  if (
    !fullname ||
    !email ||
    !password ||
    !confirmPassword
  ) {
    return {
      valid:
        false,

      message:
        "Full name, email, password and password confirmation are required.",
    };
  }

  if (
    fullname.length <
      2 ||
    fullname.length >
      100
  ) {
    return {
      valid:
        false,

      message:
        "Full name must contain between 2 and 100 characters.",
    };
  }

  if (
    !isValidEmail(
      email
    )
  ) {
    return {
      valid:
        false,

      message:
        "Please provide a valid email address.",
    };
  }

  if (
    password.length <
    PASSWORD_MIN_LENGTH
  ) {
    return {
      valid:
        false,

      message:
        `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`,
    };
  }

  if (
    password.length >
    128
  ) {
    return {
      valid:
        false,

      message:
        "Password cannot exceed 128 characters.",
    };
  }

  if (
    password !==
    confirmPassword
  ) {
    return {
      valid:
        false,

      message:
        "Passwords do not match.",
    };
  }

  if (
    username
  ) {
    if (
      username.length <
        3 ||
      username.length >
        50
    ) {
      return {
        valid:
          false,

        message:
          "Username must contain between 3 and 50 characters.",
      };
    }

    if (
      !isValidUsername(
        username
      )
    ) {
      return {
        valid:
          false,

        message:
          "Username may only contain letters, numbers, dots, underscores, and hyphens.",
      };
    }
  }

  if (
    phone &&
    !/^09\d{9}$/.test(
      phone
    )
  ) {
    return {
      valid:
        false,

      message:
        "Please provide a valid Philippine mobile number.",
    };
  }

  return {
    valid:
      true,

    data: {
      fullname,

      email,

      username,

      password,

      confirmPassword,

      phone,
    },
  };
}

/* ============================================================
   OTP HELPERS
============================================================ */

function checkOtpRequestRateLimit(
  req,
  email
) {
  const ip =
    String(
      req.ip ||
        "unknown"
    );

  const key =
    `${ip}|${email}`;

  const now =
    Date.now();

  const existing =
    otpRequestTracker.get(
      key
    );

  if (
    !existing ||
    now -
      existing.windowStartedAt >
      OTP_REQUEST_WINDOW_MS
  ) {
    otpRequestTracker.set(
      key,
      {
        windowStartedAt:
          now,

        count:
          1,
      }
    );

    return {
      allowed:
        true,

      retryAfter:
        0,
    };
  }

  if (
    existing.count >=
    OTP_MAX_REQUESTS_PER_WINDOW
  ) {
    return {
      allowed:
        false,

      retryAfter:
        Math.ceil(
          (
            OTP_REQUEST_WINDOW_MS -
            (
              now -
              existing.windowStartedAt
            )
          ) /
            1000
        ),
    };
  }

  existing.count +=
    1;

  return {
    allowed:
      true,

    retryAfter:
      0,
  };
}

async function prepareSignupVerification(
  signupData
) {
  const {
    fullname,
    email,
    username,
    password,
    phone,
  } =
    signupData;

  let user =
    await User.findByEmail(
      email
    );

  if (
    user &&
    user.emailVerified ===
      true
  ) {
    throw new Error(
      "An account with that email already exists."
    );
  }

  if (
    username
  ) {
    const usernameUser =
      await User.findOne({
        username,
      });

    if (
      usernameUser &&
      (
        !user ||
        !usernameUser._id.equals(
          user._id
        )
      )
    ) {
      throw new Error(
        "That username is already in use."
      );
    }
  }

  const createdNewUser =
    !user;

  if (!user) {
    user =
      new User({
        fullname,

        email,

        phone:
          phone ||
          undefined,

        authProvider:
          "local",

        emailVerified:
          false,
      });
  } else {
    user.fullname =
      fullname;

    user.phone =
      phone ||
      undefined;

    user.authProvider =
      "local";

    user.emailVerified =
      false;
  }

  user.username =
    username ||
    undefined;

  await user.setPassword(
    password
  );

  const verificationCode =
    await user.createEmailVerificationCode();

  await user.save();

  return {
    user,

    verificationCode,

    createdNewUser,
  };
}

/* ============================================================
   MAIL
============================================================ */

function getMailTransporter() {
  if (
    !MAIL_USER ||
    !MAIL_APP_PASSWORD
  ) {
    return null;
  }

  if (
    mailTransporter
  ) {
    return mailTransporter;
  }

  mailTransporter =
    nodemailer.createTransport(
      {
        service:
          "gmail",

        auth: {
          user:
            MAIL_USER,

          pass:
            MAIL_APP_PASSWORD,
        },
      }
    );

  return mailTransporter;
}

function buildVerificationEmail(
  code,
  expiresInSeconds
) {
  const minutes =
    Math.max(
      1,
      Math.ceil(
        Number(
          expiresInSeconds ||
            600
        ) /
          60
      )
    );

  const safeCode =
    String(
      code ||
        ""
    );

  return {
    subject:
      `${MAIL_FROM_NAME} - Email Verification Code`,

    text:
      [
        "Puffer Isle Resort",
        "",
        "Welcome to IsleRMS.",
        "",
        `Your email verification code is: ${safeCode}`,
        "",
        `This code expires in ${minutes} minutes.`,
        "",
        "If you did not create this account, you can safely ignore this email.",
      ].join(
        "\n"
      ),

    html:
      `
      <!doctype html>
      <html>
      <body
        style="
          font-family:Arial,Helvetica,sans-serif;
          color:#222;
        "
      >
        <h2>Puffer Isle Resort</h2>

        <p>
          Welcome to IsleRMS.
        </p>

        <p>
          Your email verification code is:
        </p>

        <p
          style="
            font-size:32px;
            font-weight:800;
            letter-spacing:8px;
          "
        >
          ${safeCode}
        </p>

        <p>
          This code expires in ${minutes} minutes.
        </p>

        <p
          style="
            color:#777;
            font-size:12px;
          "
        >
          If you did not create this account,
          you can safely ignore this email.
        </p>
      </body>
      </html>
      `,
  };
}

async function sendVerificationEmail(
  email,
  code,
  expiresInSeconds
) {
  const transporter =
    getMailTransporter();

  if (!transporter) {
    throw new Error(
      "Gmail email delivery is not configured. Set MAIL_USER and MAIL_APP_PASSWORD in your environment."
    );
  }

  const message =
    buildVerificationEmail(
      code,
      expiresInSeconds
    );

  return transporter.sendMail({
    from:
      `"${MAIL_FROM_NAME}" <${MAIL_USER}>`,

    to:
      email,

    subject:
      message.subject,

    text:
      message.text,

    html:
      message.html,
  });
}

setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        key,
        entry,
      ] of otpRequestTracker.entries()
    ) {
      if (
        now -
          entry.windowStartedAt >
          OTP_REQUEST_WINDOW_MS
      ) {
        otpRequestTracker.delete(
          key
        );
      }
    }
  },
  10 * 60 * 1000
).unref();

/* ============================================================
   PASSWORD RESET HELPERS
============================================================ */

function hashPasswordResetToken(
  token
) {
  return crypto
    .createHash("sha256")
    .update(
      String(
        token ||
          ""
      )
    )
    .digest("hex");
}

function generatePasswordResetToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function checkPasswordResetRateLimit(
  req,
  email
) {
  const ip =
    String(
      req.ip ||
        "unknown"
    );

  const key =
    `${ip}|${email}`;

  const now =
    Date.now();

  const existing =
    passwordResetRequestTracker.get(
      key
    );

  if (
    !existing ||
    now -
      existing.windowStartedAt >
      PASSWORD_RESET_REQUEST_WINDOW_MS
  ) {
    passwordResetRequestTracker.set(
      key,
      {
        windowStartedAt:
          now,

        count:
          1,
      }
    );

    return {
      allowed:
        true,

      retryAfter:
        0,
    };
  }

  if (
    existing.count >=
    PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW
  ) {
    return {
      allowed:
        false,

      retryAfter:
        Math.ceil(
          (
            PASSWORD_RESET_REQUEST_WINDOW_MS -
            (
              now -
              existing.windowStartedAt
            )
          ) /
            1000
        ),
    };
  }

  existing.count +=
    1;

  return {
    allowed:
      true,

    retryAfter:
      0,
  };
}

function buildPasswordResetEmail(
  resetUrl,
  expiresInMinutes
) {
  return {
    subject:
      `${MAIL_FROM_NAME} - Password Reset`,

    text:
      [
        "Puffer Isle Resort",
        "",
        "A request was made to reset your IsleRMS password.",
        "",
        `Reset your password here: ${resetUrl}`,
        "",
        `This link expires in ${expiresInMinutes} minutes.`,
        "",
        "If you did not request a password reset, you can safely ignore this email.",
      ].join(
        "\n"
      ),

    html:
      `
      <!doctype html>
      <html>
      <body
        style="
          font-family:Arial,Helvetica,sans-serif;
          color:#222;
        "
      >
        <h2>
          Puffer Isle Resort
        </h2>

        <p>
          A request was made to reset your
          IsleRMS password.
        </p>

        <p>
          <a href="${resetUrl}">
            Reset Password
          </a>
        </p>

        <p>
          This link expires in
          ${expiresInMinutes} minutes.
        </p>

        <p
          style="
            color:#777;
            font-size:12px;
          "
        >
          If you did not request a password
          reset, you can safely ignore this email.
        </p>
      </body>
      </html>
      `,
  };
}

async function sendPasswordResetEmail(
  email,
  resetUrl
) {
  const transporter =
    getMailTransporter();

  if (!transporter) {
    throw new Error(
      "Gmail email delivery is not configured. Set MAIL_USER and MAIL_APP_PASSWORD in your environment."
    );
  }

  const message =
    buildPasswordResetEmail(
      resetUrl,
      Math.ceil(
        PASSWORD_RESET_TOKEN_TTL_MS /
          60000
      )
    );

  return transporter.sendMail({
    from:
      `"${MAIL_FROM_NAME}" <${MAIL_USER}>`,

    to:
      email,

    subject:
      message.subject,

    text:
      message.text,

    html:
      message.html,
  });
}

setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        key,
        entry,
      ] of passwordResetRequestTracker.entries()
    ) {
      if (
        now -
          entry.windowStartedAt >
          PASSWORD_RESET_REQUEST_WINDOW_MS
      ) {
        passwordResetRequestTracker.delete(
          key
        );
      }
    }
  },
  10 * 60 * 1000
).unref();

/* ============================================================
   USER LOGIN
============================================================ */

app.get(
  "/login",
  (
    req,
    res
  ) => {
    if (
      req.session?.user
    ) {
      return res.redirect(
        "/profile"
      );
    }

    const query =
      new URLSearchParams({
        auth:
          "login",
      });

    if (
      req.query?.error
    ) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    if (
      req.query?.success
    ) {
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

app.post(
  "/login",
  async (
    req,
    res
  ) => {
    try {
      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return redirectAuthError(
          res,
          "login",
          captcha.message
        );
      }

      const identifier =
        normalizeIdentifier(
          req.body?.email ||
            req.body?.username ||
            ""
        );

      const password =
        String(
          req.body?.password ||
            ""
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

      const user =
        await User.findByIdentifier(
          identifier
        ).select(
          "+password +googleId"
        );

      if (!user) {
        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      if (
        user.lockedUntil instanceof
          Date &&
        user.lockedUntil.getTime() <=
          Date.now()
      ) {
        if (
          typeof user.clearExpiredLock ===
          "function"
        ) {
          await user.clearExpiredLock();
        } else {
          user.lockedUntil =
            null;

          user.failedLoginAttempts =
            0;

          await user.save();
        }
      }

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

      if (
        user.status &&
        user.status !==
          "active"
      ) {
        return redirectAuthError(
          res,
          "login",
          "Invalid username/email or password."
        );
      }

      if (
        user.authProvider ===
          "google" &&
        !user.password
      ) {
        return redirectAuthError(
          res,
          "login",
          "This account uses Google Sign-In. Please continue with Google."
        );
      }

      const passwordValid =
        typeof user.comparePassword ===
        "function"
          ? await user.comparePassword(
              password
            )
          : false;

      if (
        !passwordValid
      ) {
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

      if (
        user.authProvider !==
          "google" &&
        user.emailVerified ===
          false
      ) {
        return redirectAuthError(
          res,
          "login",
          "Please verify your email address before signing in."
        );
      }

      if (
        typeof user.resetLoginSecurity ===
        "function"
      ) {
        await user.resetLoginSecurity();
      }

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      req.session.lastActivityAt =
        Date.now();

      await saveSession(
        req
      );

      return res.redirect(
        303,
        "/profile"
      );
    } catch (
      error
    ) {
      console.error(
        `USER LOGIN ERROR requestId=${req.requestId}:`,
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
   USER SIGNUP
============================================================ */

app.get(
  "/signup",
  (
    req,
    res
  ) => {
    if (
      req.session?.user
    ) {
      return res.redirect(
        "/profile"
      );
    }

    const query =
      new URLSearchParams({
        auth:
          "signup",
      });

    if (
      req.query?.error
    ) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    if (
      req.query?.success
    ) {
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

app.post(
  "/signup/request-otp",
  async (
    req,
    res
  ) => {
    try {
      if (
        !EMAIL_OTP_ENABLED
      ) {
        return res
          .status(503)
          .json({
            success:
              false,

            message:
              "Email verification is currently unavailable.",
          });
      }

      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              captcha.message,
          });
      }

      const validation =
        validateSignupInput(
          req.body
        );

      if (
        !validation.valid
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              validation.message,
          });
      }

      const rateLimit =
        checkOtpRequestRateLimit(
          req,
          validation.data.email
        );

      if (
        !rateLimit.allowed
      ) {
        return res
          .status(429)
          .json({
            success:
              false,

            message:
              "Too many verification requests. Please try again later.",

            retryAfter:
              rateLimit.retryAfter,
          });
      }

      const prepared =
        await prepareSignupVerification(
          validation.data
        );

      const expiresIn =
        (
          typeof prepared.user
            .getEmailVerificationRemaining ===
          "function"
            ? prepared.user.getEmailVerificationRemaining()
            : 600
        ) || 600;

      try {
        await sendVerificationEmail(
          validation.data.email,
          prepared.verificationCode,
          expiresIn
        );
      } catch (
        mailError
      ) {
        console.error(
          "VERIFICATION EMAIL SEND ERROR:",
          mailError
        );

        prepared.user.clearEmailVerification();

        await prepared.user
          .save()
          .catch(
            (
              cleanupError
            ) =>
              console.error(
                "OTP CLEANUP ERROR:",
                cleanupError
              )
          );

        return res
          .status(503)
          .json({
            success:
              false,

            message:
              "We could not send the verification email. Please check the email service configuration and try again.",
          });
      }

      return res.json({
        success:
          true,

        message:
          "Verification code sent. Please check your email.",

        resendAfter:
          60,

        expiresIn,
      });
    } catch (
      error
    ) {
      console.error(
        "SIGNUP OTP REQUEST ERROR:",
        error
      );

      if (
        isDuplicateKeyError(
          error
        )
      ) {
        return res
          .status(409)
          .json({
            success:
              false,

            message:
              "An account with that email or username already exists.",
          });
      }

      return res
        .status(400)
        .json({
          success:
            false,

          message:
            error.message ||
            "Unable to send a verification code.",
        });
    }
  }
);

app.post(
  "/signup/verify-otp",
  async (
    req,
    res
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email ||
            ""
        );

      const otp =
        String(
          req.body?.otp ||
            ""
        ).trim();

      if (
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Please provide a valid email address.",
          });
      }

      if (
        !/^\d{6}$/.test(
          otp
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Please enter the 6-digit verification code.",
          });
      }

      const user =
        await User.findByEmail(
          email
        ).select(
          "+emailVerificationCodeHash " +
            "+emailVerificationCodeExpiresAt " +
            "+emailVerificationAttempts " +
            "+emailVerificationResendAt"
        );

      if (!user) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "The verification code is invalid or expired.",
          });
      }

      if (
        user.emailVerified ===
        true
      ) {
        return res.json({
          success:
            true,

          message:
            "This email address is already verified.",

          redirect:
            "/profile",
        });
      }

      if (
        typeof user.verifyEmailVerificationCode !==
        "function"
      ) {
        throw new Error(
          "User email verification service is unavailable."
        );
      }

      const result =
        await user.verifyEmailVerificationCode(
          otp
        );

      if (
        !result.success
      ) {
        await user.save();

        let message =
          "The verification code is invalid.";

        if (
          result.reason ===
          "expired"
        ) {
          message =
            "The verification code has expired. Please request a new code.";
        } else if (
          result.reason ===
          "attempts"
        ) {
          message =
            "Too many verification attempts. Please request a new code.";
        }

        return res
          .status(400)
          .json({
            success:
              false,

            message,
          });
      }

      await user.save();

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      req.session.lastActivityAt =
        Date.now();

      await saveSession(
        req
      );

      return res.json({
        success:
          true,

        message:
          "Your email has been verified and your account is ready.",

        redirect:
          "/profile",
      });
    } catch (
      error
    ) {
      console.error(
        "SIGNUP OTP VERIFY ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Unable to verify your email right now. Please try again.",
        });
    }
  }
);

app.post(
  "/signup/resend-otp",
  async (
    req,
    res
  ) => {
    try {
      if (
        !EMAIL_OTP_ENABLED
      ) {
        return res
          .status(503)
          .json({
            success:
              false,

            message:
              "Email verification is currently unavailable.",
          });
      }

      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              captcha.message,
          });
      }

      const email =
        normalizeEmail(
          req.body?.email ||
            ""
        );

      if (
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Please provide a valid email address.",
          });
      }

      const rateLimit =
        checkOtpRequestRateLimit(
          req,
          email
        );

      if (
        !rateLimit.allowed
      ) {
        return res
          .status(429)
          .json({
            success:
              false,

            message:
              "Too many verification requests. Please try again later.",

            retryAfter:
              rateLimit.retryAfter,
          });
      }

      const user =
        await User.findByEmail(
          email
        ).select(
          "+emailVerificationCodeHash " +
            "+emailVerificationCodeExpiresAt " +
            "+emailVerificationAttempts " +
            "+emailVerificationResendAt"
        );

      if (
        !user ||
        user.emailVerified ===
          true
      ) {
        return res.json({
          success:
            true,

          message:
            "If an unverified account exists for this email, a new verification code will be sent.",

          resendAfter:
            60,
        });
      }

      let verificationCode;

      try {
        verificationCode =
          await user.createEmailVerificationCode();
      } catch (
        cooldownError
      ) {
        return res
          .status(429)
          .json({
            success:
              false,

            message:
              cooldownError.message ||
              "Please wait before requesting another code.",
          });
      }

      await user.save();

      const expiresIn =
        (
          typeof user.getEmailVerificationRemaining ===
          "function"
            ? user.getEmailVerificationRemaining()
            : 600
        ) || 600;

      try {
        await sendVerificationEmail(
          email,
          verificationCode,
          expiresIn
        );
      } catch (
        mailError
      ) {
        console.error(
          "RESEND VERIFICATION EMAIL ERROR:",
          mailError
        );

        user.clearEmailVerification();

        await user.save();

        return res
          .status(503)
          .json({
            success:
              false,

            message:
              "We could not send the verification email right now.",
          });
      }

      return res.json({
        success:
          true,

        message:
          "A new verification code has been sent to your email.",

        resendAfter:
          60,

        expiresIn,
      });
    } catch (
      error
    ) {
      console.error(
        "RESEND OTP ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Unable to resend the verification code.",
        });
    }
  }
);

app.post(
  "/signup",
  async (
    req,
    res
  ) => {
    try {
      const validation =
        validateSignupInput(
          req.body
        );

      if (
        !validation.valid
      ) {
        return redirectAuthError(
          res,
          "signup",
          validation.message
        );
      }

      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return redirectAuthError(
          res,
          "signup",
          captcha.message
        );
      }

      const prepared =
        await prepareSignupVerification(
          validation.data
        );

      const expiresIn =
        (
          typeof prepared.user
            .getEmailVerificationRemaining ===
          "function"
            ? prepared.user.getEmailVerificationRemaining()
            : 600
        ) || 600;

      try {
        await sendVerificationEmail(
          validation.data.email,
          prepared.verificationCode,
          expiresIn
        );
      } catch (
        mailError
      ) {
        console.error(
          "LEGACY SIGNUP EMAIL ERROR:",
          mailError
        );

        prepared.user.clearEmailVerification();

        await prepared.user.save();

        return redirectAuthError(
          res,
          "signup",
          "Unable to send your verification email right now."
        );
      }

      return redirectAuthSuccess(
        res,
        "signup",
        "Verification code sent. Please complete email verification."
      );
    } catch (
      error
    ) {
      console.error(
        "USER SIGNUP ERROR:",
        error
      );

      if (
        isDuplicateKeyError(
          error
        )
      ) {
        return redirectAuthError(
          res,
          "signup",
          "An account with that email or username already exists."
        );
      }

      return redirectAuthError(
        res,
        "signup",
        error.message ||
          "Unable to create your account."
      );
    }
  }
);

/* ============================================================
   GOOGLE OAUTH
============================================================ */

function isGoogleOAuthConfigured() {
  return Boolean(
    GOOGLE_CLIENT_ID &&
      GOOGLE_CLIENT_SECRET &&
      GOOGLE_CALLBACK_URL
  );
}

function safeCompareStrings(
  left,
  right
) {
  const a =
    Buffer.from(
      String(
        left ||
          ""
      )
    );

  const b =
    Buffer.from(
      String(
        right ||
          ""
      )
    );

  if (
    a.length !==
    b.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    a,
    b
  );
}

async function startGoogleOAuth(
  req,
  res
) {
  try {
    if (
      !isGoogleOAuthConfigured()
    ) {
      return res.redirect(
        "/?auth=login&error=" +
          encodeURIComponent(
            "Google Sign-In is not configured yet."
          )
      );
    }

    if (
      req.method ===
      "POST"
    ) {
      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              captcha.message
            )
        );
      }
    }

    const state =
      crypto
        .randomBytes(32)
        .toString(
          "hex"
        );

    const returnTo =
      sanitizeReturnTo(
        req.body?.returnTo ||
          req.query?.returnTo ||
          "/"
      );

    req.session.googleOAuthState =
      state;

    req.session.googleOAuthStateCreatedAt =
      Date.now();

    req.session.googleOAuthReturnTo =
      returnTo;

    await saveSession(
      req
    );

    const params =
      new URLSearchParams({
        client_id:
          GOOGLE_CLIENT_ID,

        redirect_uri:
          GOOGLE_CALLBACK_URL,

        response_type:
          "code",

        scope:
          "openid email profile",

        state,

        access_type:
          "online",

        prompt:
          "select_account",
      });

    return res.redirect(
      302,
      `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
    );
  } catch (
    error
  ) {
    console.error(
      "GOOGLE AUTH START ERROR:",
      error
    );

    return res.redirect(
      "/?auth=login&error=" +
        encodeURIComponent(
          "Unable to start Google Sign-In."
        )
    );
  }
}

app.post(
  "/auth/google/start",
  startGoogleOAuth
);

app.get(
  "/auth/google",
  startGoogleOAuth
);

app.get(
  "/auth/google/callback",
  async (
    req,
    res
  ) => {
    try {
      if (
        !isGoogleOAuthConfigured()
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google Sign-In is not configured."
            )
        );
      }

      const state =
        String(
          req.query?.state ||
            ""
        );

      const code =
        String(
          req.query?.code ||
            ""
        );

      const storedState =
        String(
          req.session
            ?.googleOAuthState ||
            ""
        );

      const createdAt =
        Number(
          req.session
            ?.googleOAuthStateCreatedAt ||
            0
        );

      const returnTo =
        sanitizeReturnTo(
          req.session
            ?.googleOAuthReturnTo
        );

      delete req.session
        .googleOAuthState;

      delete req.session
        .googleOAuthStateCreatedAt;

      delete req.session
        .googleOAuthReturnTo;

      if (
        !state ||
        !storedState ||
        !safeCompareStrings(
          state,
          storedState
        ) ||
        (
          createdAt &&
          Date.now() -
            createdAt >
            GOOGLE_OAUTH_STATE_MAX_AGE_MS
        )
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google authentication could not be verified."
            )
        );
      }

      if (
        !code
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google authentication was cancelled or did not return a code."
            )
        );
      }

      const tokenResponse =
        await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
            },

            body:
              new URLSearchParams({
                code,

                client_id:
                  GOOGLE_CLIENT_ID,

                client_secret:
                  GOOGLE_CLIENT_SECRET,

                redirect_uri:
                  GOOGLE_CALLBACK_URL,

                grant_type:
                  "authorization_code",
              }),

            signal:
              AbortSignal.timeout(
                10000
              ),
          }
        );

      if (
        !tokenResponse.ok
      ) {
        console.error(
          "GOOGLE TOKEN ERROR:",
          await tokenResponse.text()
        );

        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google authentication could not be completed."
            )
        );
      }

      const tokenData =
        await tokenResponse.json();

      const accessToken =
        String(
          tokenData?.access_token ||
            ""
        );

      if (
        !accessToken
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google did not provide a valid authentication token."
            )
        );
      }

      const profileResponse =
        await fetch(
          "https://www.googleapis.com/oauth2/v3/userinfo",
          {
            headers: {
              Authorization:
                `Bearer ${accessToken}`,

              Accept:
                "application/json",
            },

            signal:
              AbortSignal.timeout(
                10000
              ),
          }
        );

      if (
        !profileResponse.ok
      ) {
        console.error(
          "GOOGLE PROFILE ERROR:",
          await profileResponse.text()
        );

        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Unable to retrieve your Google account information."
            )
        );
      }

      const googleProfile =
        await profileResponse.json();

      const googleId =
        String(
          googleProfile?.sub ||
            ""
        ).trim();

      const email =
        normalizeEmail(
          googleProfile?.email ||
            ""
        );

      const googleEmailVerified =
        googleProfile?.email_verified ===
        true;

      const fullname =
        normalizeString(
          googleProfile?.name ||
            googleProfile?.given_name ||
            "Google Guest"
        );

      const avatarUrl =
        String(
          googleProfile?.picture ||
            ""
        ).trim();

      if (
        !googleId ||
        !isValidEmail(
          email
        ) ||
        !googleEmailVerified
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Google could not verify this email address."
            )
        );
      }

      let user =
        await User.findByGoogleId(
          googleId
        );

      if (
        !user
      ) {
        user =
          await User.findByEmail(
            email
          );
      }

      if (
        !user
      ) {
        user =
          new User({
            fullname,

            email,

            authProvider:
              "google",

            googleId,

            avatarUrl:
              avatarUrl ||
              null,

            emailVerified:
              true,

            emailVerifiedAt:
              new Date(),

            status:
              "active",
          });

        await user.save();
      } else {
        user.googleId =
          googleId;

        user.avatarUrl =
          avatarUrl ||
          user.avatarUrl ||
          null;

        user.emailVerified =
          true;

        if (
          !user.emailVerifiedAt
        ) {
          user.emailVerifiedAt =
            new Date();
        }

        if (
          user.authProvider !==
          "google"
        ) {
          user.authProvider =
            "hybrid";
        }

        await user.save();
      }

      if (
        user.status &&
        user.status !==
          "active"
      ) {
        return res.redirect(
          "/?auth=login&error=" +
            encodeURIComponent(
              "Your account is currently unavailable."
            )
        );
      }

      if (
        !normalizePhone(
          user.phone ||
            ""
        )
      ) {
        await regenerateSession(
          req
        );

        req.session.googleProfileCompletion =
          {
            userId:
              String(
                user._id
              ),

            createdAt:
              Date.now(),

            returnTo,
          };

        await saveSession(
          req
        );

        return res.redirect(
          303,
          `/?auth=complete-phone&returnTo=${encodeURIComponent(
            returnTo
          )}`
        );
      }

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      req.session.lastActivityAt =
        Date.now();

      await saveSession(
        req
      );

      return res.redirect(
        303,
        returnTo ||
          "/profile"
      );
    } catch (
      error
    ) {
      console.error(
        "GOOGLE CALLBACK ERROR:",
        error
      );

      return res.redirect(
        "/?auth=login&error=" +
          encodeURIComponent(
            "Google Sign-In could not be completed. Please try again."
          )
      );
    }
  }
);

/* ============================================================
   GOOGLE PROFILE COMPLETION
============================================================ */

app.post(
  "/auth/google/complete-profile",
  async (
    req,
    res
  ) => {
    try {
      const completion =
        req.session
          ?.googleProfileCompletion;

      if (
        !completion
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Your Google profile completion session has expired. Please sign in with Google again.",
          });
      }

      const createdAt =
        Number(
          completion.createdAt ||
            0
        );

      if (
        !createdAt ||
        Date.now() -
          createdAt >
          GOOGLE_PROFILE_COMPLETION_MAX_AGE_MS
      ) {
        delete req.session
          .googleProfileCompletion;

        await saveSession(
          req
        );

        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Your Google profile completion session has expired. Please sign in with Google again.",
          });
      }

      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              captcha.message,
          });
      }

      const phone =
        normalizePhone(
          req.body?.phone ||
            ""
        );

      if (
        !/^09\d{9}$/.test(
          phone
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Please provide a valid Philippine mobile number.",
          });
      }

      if (
        !mongoose.Types.ObjectId.isValid(
          completion.userId
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Your Google profile could not be validated.",
          });
      }

      const user =
        await User.findById(
          completion.userId
        );

      if (
        !user
      ) {
        return res
          .status(404)
          .json({
            success:
              false,

            message:
              "Your Google account could not be found.",
          });
      }

      if (
        user.status &&
        user.status !==
          "active"
      ) {
        return res
          .status(403)
          .json({
            success:
              false,

            message:
              "Your account is currently unavailable.",
          });
      }

      user.phone =
        phone;

      await user.save();

      const returnTo =
        sanitizeReturnTo(
          completion.returnTo
        );

      delete req.session
        .googleProfileCompletion;

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      req.session.lastActivityAt =
        Date.now();

      await saveSession(
        req
      );

      return res.json({
        success:
          true,

        message:
          "Your phone number has been added and your Google account is ready.",

        redirect:
          returnTo ||
          "/profile",
      });
    } catch (
      error
    ) {
      console.error(
        "GOOGLE PROFILE COMPLETION ERROR:",
        error
      );

      if (
        isDuplicateKeyError(
          error
        )
      ) {
        return res
          .status(409)
          .json({
            success:
              false,

            message:
              "That phone number could not be saved.",
          });
      }

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Unable to complete your Google profile right now.",
        });
    }
  }
);

/* ============================================================
   FORGOT PASSWORD
============================================================ */

app.post(
  "/auth/forgot-password",
  async (
    req,
    res
  ) => {
    try {
      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              captcha.message,
          });
      }

      const email =
        normalizeEmail(
          req.body?.email ||
            ""
        );

      if (
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Please provide a valid email address.",
          });
      }

      const rateLimit =
        checkPasswordResetRateLimit(
          req,
          email
        );

      if (
        !rateLimit.allowed
      ) {
        return res
          .status(429)
          .json({
            success:
              false,

            message:
              "Too many password reset requests. Please try again later.",

            retryAfter:
              rateLimit.retryAfter,
          });
      }

      const user =
        await User.findByEmail(
          email
        ).select(
          "+passwordResetTokenHash +passwordResetExpiresAt"
        );

      if (
        !user ||
        (
          user.status &&
          user.status !==
            "active"
        )
      ) {
        return res.json({
          success:
            true,

          message:
            "If an account exists for that email address, a password reset link has been sent.",
        });
      }

      const rawToken =
        generatePasswordResetToken();

      user.passwordResetTokenHash =
        hashPasswordResetToken(
          rawToken
        );

      user.passwordResetExpiresAt =
        new Date(
          Date.now() +
            PASSWORD_RESET_TOKEN_TTL_MS
        );

      await user.save();

      const resetUrl =
        `${getPublicBaseUrl(
          req
        )}/?auth=reset&token=${encodeURIComponent(
          rawToken
        )}`;

      try {
        await sendPasswordResetEmail(
          email,
          resetUrl
        );
      } catch (
        mailError
      ) {
        console.error(
          "PASSWORD RESET EMAIL ERROR:",
          mailError
        );

        user.clearPasswordReset();

        await user.save();

        return res
          .status(503)
          .json({
            success:
              false,

            message:
              "We could not send the password reset email right now. Please try again later.",
          });
      }

      return res.json({
        success:
          true,

        message:
          "If an account exists for that email address, a password reset link has been sent.",
      });
    } catch (
      error
    ) {
      console.error(
        "FORGOT PASSWORD ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Unable to process the password reset request right now.",
        });
    }
  }
);

/* ============================================================
   RESET PASSWORD
============================================================ */

app.post(
  "/auth/reset-password",
  async (
    req,
    res
  ) => {
    try {
      const captcha =
        await verifyTurnstile(
          req
        );

      if (
        !captcha.success
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              captcha.message,
          });
      }

      const token =
        String(
          req.body?.token ||
            req.body?.resetToken ||
            req.query?.token ||
            ""
        ).trim();

      const password =
        String(
          req.body?.password ||
            ""
        );

      const confirmPassword =
        String(
          req.body?.confirmPassword ||
            req.body?.passwordConfirmation ||
            ""
        );

      if (
        !token
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "The password reset link is invalid or incomplete.",
          });
      }

      if (
        password.length <
        PASSWORD_MIN_LENGTH
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`,
          });
      }

      if (
        password.length >
        128
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Password cannot exceed 128 characters.",
          });
      }

      if (
        password !==
        confirmPassword
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "Passwords do not match.",
          });
      }

      const tokenHash =
        hashPasswordResetToken(
          token
        );

      const user =
        await User.findOne({
          passwordResetTokenHash:
            tokenHash,

          passwordResetExpiresAt:
            {
              $gt:
                new Date(),
            },
        }).select(
          "+passwordResetTokenHash " +
            "+passwordResetExpiresAt"
        );

      if (
        !user
      ) {
        return res
          .status(400)
          .json({
            success:
              false,

            message:
              "This password reset link is invalid or has expired. Please request a new one.",
          });
      }

      if (
        user.status &&
        user.status !==
          "active"
      ) {
        return res
          .status(403)
          .json({
            success:
              false,

            message:
              "Your account is currently unavailable.",
          });
      }

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

      user.clearPasswordReset();

      user.failedLoginAttempts =
        0;

      user.lockedUntil =
        null;

      await user.save();

      return res.json({
        success:
          true,

        message:
          "Your password has been reset successfully. You can now sign in.",

        redirect:
          "/?auth=login&success=" +
          encodeURIComponent(
            "Your password has been reset successfully."
          ),
      });
    } catch (
      error
    ) {
      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Unable to reset your password right now. Please try again.",
        });
    }
  }
);

/* ============================================================
   USER LOGOUT
============================================================ */

app.post(
  "/logout",
  async (
    req,
    res
  ) => {
    try {
      await destroySession(
        req
      );

      clearSessionCookie(
        res
      );

      return res.redirect(
        303,
        "/?auth=login&success=" +
          encodeURIComponent(
            "You have been logged out."
          )
      );
    } catch (
      error
    ) {
      console.error(
        `USER LOGOUT ERROR requestId=${req.requestId}:`,
        error
      );

      clearSessionCookie(
        res
      );

      return res.redirect(
        303,
        "/"
      );
    }
  }
);

/*
 * Legacy GET compatibility.
 */
app.get(
  "/logout",
  async (
    req,
    res
  ) => {
    try {
      await destroySession(
        req
      );

      clearSessionCookie(
        res
      );

      return res.redirect(
        303,
        "/?auth=login&success=" +
          encodeURIComponent(
            "You have been logged out."
          )
      );
    } catch (
      error
    ) {
      console.error(
        `USER GET LOGOUT ERROR requestId=${req.requestId}:`,
        error
      );

      clearSessionCookie(
        res
      );

      return res.redirect(
        303,
        "/"
      );
    }
  }
);

/* ============================================================
   ADMIN COMPATIBILITY
============================================================ */

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    const adminId =
      req.session?.admin?.id ||
      req.session?.admin?._id;

    if (
      !adminId ||
      !mongoose.Types.ObjectId.isValid(
        adminId
      )
    ) {
      clearAdminSessionCookie(
        res
      );

      return res.redirect(
        "/admin/login?error=" +
          encodeURIComponent(
            "Administrator login required."
          )
      );
    }

    const admin =
      await Admin.findById(
        adminId
      )
        .select(
          "username role status active"
        )
        .lean();

    if (
      !admin
    ) {
      await destroySession(
        req
      ).catch(
        () => {}
      );

      clearAdminSessionCookie(
        res
      );

      return res.redirect(
        "/admin/login?error=" +
          encodeURIComponent(
            "Your administrator session is no longer valid."
          )
      );
    }

    if (
      (
        admin.status &&
        String(
          admin.status
        )
          .toLowerCase() !==
          "active"
      ) ||
      admin.active ===
        false
    ) {
      await destroySession(
        req
      ).catch(
        () => {}
      );

      clearAdminSessionCookie(
        res
      );

      return res.redirect(
        "/admin/login?error=" +
          encodeURIComponent(
            "Your administrator account is currently unavailable."
          )
      );
    }

    req.session.admin =
      {
        ...req.session.admin,

        ...createAdminSessionData(
          admin
        ),
      };

    next();
  } catch (
    error
  ) {
    console.error(
      "SERVER requireAdmin ERROR:",
      error
    );

    return res
      .status(500)
      .send(
        "Unable to validate administrator access."
      );
  }
}

function requireUser(
  req,
  res,
  next
) {
  const sessionUser =
    req.session?.user;

  if (
    !sessionUser
  ) {
    return res.redirect(
      "/?auth=login&error=" +
        encodeURIComponent(
          "Please log in to continue."
        )
    );
  }

  if (
    sessionUser.status &&
    sessionUser.status !==
      "active"
  ) {
    return destroySession(
      req
    )
      .catch(
        (error) =>
          console.error(
            "SESSION CLEANUP ERROR:",
            error
          )
      )
      .finally(
        () => {
          clearSessionCookie(
            res
          );

          if (
            !res.headersSent
          ) {
            res.redirect(
              "/?auth=login&error=" +
                encodeURIComponent(
                  "Your account is currently unavailable."
                )
            );
          }
        }
      );
  }

  next();
}

/* ============================================================
   ADMIN LOGIN COMPATIBILITY
============================================================ */

app.get(
  "/adminlogin",
  (
    req,
    res
  ) => {
    const query =
      new URLSearchParams();

    if (
      req.query?.error
    ) {
      query.set(
        "error",
        String(
          req.query.error
        )
      );
    }

    if (
      req.query?.success
    ) {
      query.set(
        "success",
        String(
          req.query.success
        )
      );
    }

    return res.redirect(
      `/admin/login${
        query.toString()
          ? `?${query.toString()}`
          : ""
      }`
    );
  }
);

/* ============================================================
   HEALTH
============================================================ */

app.get(
  "/health",
  (
    req,
    res
  ) => {
    const mongoReady =
      mongoose.connection.readyState ===
      1;

    const payload = {
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

      uptimeSeconds:
        Math.floor(
          process.uptime()
        ),

      timestamp:
        new Date().toISOString(),
    };

    if (
      !IS_PRODUCTION
    ) {
      payload.environment =
        NODE_ENV;
    }

    return res
      .status(
        mongoReady
          ? 200
          : 503
      )
      .json(
        payload
      );
  }
);

app.get(
  "/ready",
  (
    req,
    res
  ) => {
    const mongoReady =
      mongoose.connection.readyState ===
      1;

    if (
      !mongoReady
    ) {
      return res
        .status(503)
        .json({
          success:
            false,

          ready:
            false,

          database:
            "disconnected",
        });
    }

    return res.json({
      success:
        true,

      ready:
        true,

      database:
        "connected",
    });
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
   HOME / STATIC PAGES
============================================================ */

app.get(
  "/",
  (
    req,
    res
  ) =>
    res.render(
      "index",
      {
        title:
          "Puffer Isle Resort",
      }
    )
);

app.get(
  "/rules",
  (
    req,
    res
  ) =>
    res.render(
      "rules",
      {
        title:
          "Resort Rules | Puffer Isle Resort",
      }
    )
);

/* ============================================================
   404 / ERROR HANDLING
============================================================ */

function isApiRequest(
  req
) {
  return (
    req.path.startsWith(
      "/api/"
    ) ||
    req.path.startsWith(
      "/admin/api/"
    ) ||
    req.path ===
      "/health" ||
    req.path ===
      "/ready"
  );
}

app.use(
  (
    req,
    res
  ) => {
    if (
      isApiRequest(
        req
      )
    ) {
      return res
        .status(404)
        .json({
          success:
            false,

          message:
            "Resource not found.",

          requestId:
            req.requestId,
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
            "The page you requested could not be found.",

          requestId:
            req.requestId,
        }
      );
  }
);

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      `UNHANDLED APPLICATION ERROR requestId=${
        req.requestId ||
        "none"
      }:`,
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    if (
      isApiRequest(
        req
      )
    ) {
      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Internal server error.",

          requestId:
            req.requestId,
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
                "Something went wrong.",

          requestId:
            req.requestId,
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
        !IS_PRODUCTION,
    }
  );

  console.log(
    `✅ MongoDB connected: ${mongoose.connection.name}`
  );
}

mongoose.connection.on(
  "connected",
  () =>
    console.log(
      "🟢 Mongoose connection established."
    )
);

mongoose.connection.on(
  "error",
  (
    error
  ) =>
    console.error(
      "🔴 MongoDB connection error:",
      error
    )
);

mongoose.connection.on(
  "disconnected",
  () =>
    console.warn(
      "🟡 MongoDB disconnected."
    )
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
      }).select(
        "+password"
      );

    if (
      !admin
    ) {
      admin =
        new Admin({
          username:
            normalizedUsername,
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
  } catch (
    error
  ) {
    console.error(
      "❌ Unable to ensure default admin:",
      error
    );

    if (
      IS_PRODUCTION
    ) {
      throw error;
    }
  }
}

/* ============================================================
   STARTUP
============================================================ */

let httpServer =
  null;

let shuttingDown =
  false;

async function startServer() {
  try {
    console.log(
      ""
    );

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

    console.log(
      `📧 Gmail OTP: ${
        EMAIL_OTP_ENABLED &&
        MAIL_USER &&
        MAIL_APP_PASSWORD
          ? "configured"
          : "not configured"
      }`
    );

    console.log(
      `🔐 Google OAuth: ${
        isGoogleOAuthConfigured()
          ? "configured"
          : "not configured"
      }`
    );

    console.log(
      `🛡️ Turnstile: ${
        TURNSTILE_SITE_KEY &&
        TURNSTILE_SECRET_KEY
          ? "configured"
          : "not configured"
      }`
    );

    console.log(
      `🛡️ User idle timeout: ${USER_IDLE_TIMEOUT_MINUTES} minutes`
    );

    console.log(
      `🛡️ Admin idle timeout: ${ADMIN_IDLE_TIMEOUT_MINUTES} minutes`
    );

    await connectDatabase();

    await ensureDefaultAdmin();

    httpServer =
      app.listen(
        PORT,
        HOST,
        () => {
          console.log(
            ""
          );

          console.log(
            "✅ SERVER STARTED"
          );

          console.log(
            "----------------------------------------------"
          );

          console.log(
            HOST ===
              "127.0.0.1"
              ? `🌐 Local: http://localhost:${PORT}`
              : `🌐 Listening on ${HOST}:${PORT}`
          );

          console.log(
            "🔐 User Login: /login"
          );

          console.log(
            "🔐 User Signup OTP: /signup/request-otp"
          );

          console.log(
            "🔐 Google Login: /auth/google"
          );

          console.log(
            "🔐 Google Start: /auth/google/start"
          );

          console.log(
            "🔐 Forgot Password: /auth/forgot-password"
          );

          console.log(
            "🔐 Reset Password: /auth/reset-password"
          );

          console.log(
            "🔐 Admin Login: /admin/login"
          );

          console.log(
            "❤️ Health: /health"
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

          console.log(
            ""
          );
        }
      );
  } catch (
    error
  ) {
    console.error(
      ""
    );

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
        error.message || ""
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
        error.message || ""
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

    process.exit(
      1
    );
  }
}

/* ============================================================
   GRACEFUL SHUTDOWN
============================================================ */

async function gracefulShutdown(
  signal
) {
  if (
    shuttingDown
  ) {
    return;
  }

  shuttingDown =
    true;

  console.log(
    ""
  );

  console.log(
    `🛑 ${signal} received. Starting graceful shutdown...`
  );

  if (
    httpServer
  ) {
    await new Promise(
      (
        resolve
      ) => {
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
  } catch (
    error
  ) {
    console.error(
      "Error closing MongoDB:",
      error
    );
  }

  console.log(
    "✅ Shutdown complete."
  );

  process.exit(
    0
  );
}

process.on(
  "SIGINT",
  () =>
    gracefulShutdown(
      "SIGINT"
    )
);

process.on(
  "SIGTERM",
  () =>
    gracefulShutdown(
      "SIGTERM"
    )
);

process.on(
  "unhandledRejection",
  (
    reason
  ) =>
    console.error(
      "UNHANDLED PROMISE REJECTION:",
      reason
    )
);

process.on(
  "uncaughtException",
  (
    error
  ) => {
    console.error(
      "UNCAUGHT EXCEPTION:",
      error
    );

    gracefulShutdown(
      "UNCAUGHT_EXCEPTION"
    ).catch(
      () =>
        process.exit(
          1
        )
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

if (
  require.main ===
  module
) {
  startServer();
}