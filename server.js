"use strict";

const path = require("path");

const crypto = require("crypto");

const express = require("express");

const mongoose = require("mongoose");

const session = require("express-session");

const dotenv = require("dotenv");

const MongoStore = require("connect-mongo");

const nodemailer = require("nodemailer");

const User = require("./models/User");

const Admin = require("./models/Admin");

// ✅ GALLERY CHANGE: SiteSettings is no longer used by the gallery system.

const userRoutes =
  require("./routes/userRoutes");

const adminRoutes =
  require("./routes/adminRoutes");

const galleryRoutes =
  require("./routes/galleryRoutes");

const {
  attachCsrfToken,
  verifyCsrfToken,
} = require("./middleware/csrf");

dotenv.config();

const app = express();

const NODE_ENV =
  String(
    process.env.NODE_ENV ||
      "development"
  )
    .trim()
    .toLowerCase();

const IS_PRODUCTION =
  NODE_ENV === "production";

const PORT =
  Number(
    process.env.PORT ||
      5000
  );

const HOST =
  String(
    process.env.HOST ||
      ""
  ).trim() ||
  (
    IS_PRODUCTION
      ? "0.0.0.0"
      : "127.0.0.1"
  );

const DEFAULT_LOCAL_MONGO_URI =
  "mongodb://localhost:27017/puffer_isle_resort";

const RAW_MONGO_URI =
  String(
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

const SESSION_SECRET =
  String(
    process.env.SESSION_SECRET ||
      ""
  ).trim();

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

const ADMIN_USERNAME =
  String(
    process.env.ADMIN_USERNAME ||
      ""
  ).trim();

const ADMIN_PASSWORD =
  String(
    process.env.ADMIN_PASSWORD ||
      ""
  );

const MAIL_USER =
  String(
    process.env.MAIL_USER ||
      process.env.GMAIL_USER ||
      ""
  )
    .trim()
    .toLowerCase();

const MAIL_APP_PASSWORD =
  String(
    process.env.MAIL_APP_PASSWORD ||
      process.env.GMAIL_APP_PASSWORD ||
      ""
  )
    .trim()
    .replace(
      /\s+/g,
      ""
    );

const MAIL_FROM_NAME =
  String(
    process.env.MAIL_FROM_NAME ||
      "Puffer Isle Resort"
  ).trim();

const EMAIL_OTP_ENABLED =
  String(
    process.env.EMAIL_OTP_ENABLED ??
      "true"
  )
    .trim()
    .toLowerCase() !== "false";

const GOOGLE_CLIENT_ID =
  String(
    process.env.GOOGLE_CLIENT_ID ||
      ""
  ).trim();

const GOOGLE_CLIENT_SECRET =
  String(
    process.env.GOOGLE_CLIENT_SECRET ||
      ""
  ).trim();

const GOOGLE_CALLBACK_URL =
  String(
    process.env.GOOGLE_CALLBACK_URL ||
      ""
  ).trim();

const EFFECTIVE_MONGO_URI =
  MONGO_URI ||
  DEFAULT_LOCAL_MONGO_URI;

const SESSION_MAX_AGE =
  1000 *
  60 *
  60 *
  8;

const PASSWORD_MIN_LENGTH =
  10;

const JSON_LIMIT =
  process.env.JSON_LIMIT ||
  "1mb";

const URLENCODED_LIMIT =
  process.env.URLENCODED_LIMIT ||
  "1mb";

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
  60 *
  1000;

const OTP_REQUEST_WINDOW_MS =
  15 *
  60 *
  1000;

const OTP_MAX_REQUESTS_PER_WINDOW =
  5;

const otpRequestTracker =
  new Map();

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

  if (errors.length > 0) {

    const message =
      [

        "Environment validation failed:",

        ...errors.map(
          (error) =>
            `- ${error}`
        ),

      ].join("\n");

    throw new Error(
      message
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

const EFFECTIVE_SESSION_SECRET =
  SESSION_SECRET ||
  "dev-only-puffer-isle-session-secret-change-me";

app.disable(
  "x-powered-by"
);

if (IS_PRODUCTION) {

  app.set(
    "trust proxy",
    1
  );

}

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

app.use(
  express.urlencoded({

    extended:
      true,

    limit:
      URLENCODED_LIMIT,

  })
);

app.use(
  express.json({

    limit:
      JSON_LIMIT,

  })
);

app.use(
  express.static(

    path.join(
      __dirname,
      "public"
    ),

    {

      index:
        false,

      redirect:
        false,

      maxAge:
        IS_PRODUCTION
          ? "7d"
          : 0,

    }

  )
);

app.use(
  (req, res, next) => {

    res.locals.requestMethod =
      req.method;

    res.locals.requestPath =
      req.path;

    next();

  }
);

const sessionStore =
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
      false,

  });

app.get(
  "/admin-logout",
  (req, res) => {

    return res.redirect(
      303,
      "/admin/logout"
    );

  }
);

const adminSessionMiddleware =
  session({

    name:
      ADMIN_SESSION_NAME,

    secret:
      EFFECTIVE_SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    rolling:
      true,

    store:
      sessionStore,

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

app.use(
  "/admin",

  adminSessionMiddleware,

  attachCsrfToken,

  (req, res, next) => {

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

    next();

  },

  galleryRoutes,

  adminRoutes
);

app.use(
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
      sessionStore,

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

  })
);

app.use(
  attachCsrfToken
);

const csrfProtectedPostPaths =
  new Set([

    "/login",

    "/signup",

    "/signup/request-otp",

    "/signup/verify-otp",

    "/signup/resend-otp",

    "/logout",

  ]);

app.use(
  (req, res, next) => {

    if (
      req.method === "POST" &&
      csrfProtectedPostPaths.has(
        req.path
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

    res.locals.csrfToken =
      res.locals.csrfToken ||
      req.session?.csrfToken ||
      null;

    next();

  }
);

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
          user.id ||
            ""
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
          admin.id ||
            ""
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
      admin.role ||
      "admin",

  };

}

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

function getSessionUserId(
  req
) {

  return (

    req.session?.user?.id ||

    req.session?.user?._id ||

    null

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

  const username =
    String(
      value ?? ""
    )
      .trim()
      .toLowerCase()
      .replace(
        /\s+/g,
        ""
      );

  return username || "";

}

function normalizePhone(
  value
) {

  let phone =
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
    fullname.length < 2 ||
    fullname.length > 100
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

  if (username) {

    if (
      username.length < 3 ||
      username.length > 50
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

let mailTransporter =
  null;

function getMailTransporter() {

  if (
    !EMAIL_OTP_ENABLED
  ) {

    return null;

  }

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
    nodemailer.createTransport({

      service:
        "gmail",

      auth: {

        user:
          MAIL_USER,

        pass:
          MAIL_APP_PASSWORD,

      },

    });

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
        ) / 60
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

      <head>

        <meta
          charset="utf-8"
        >

        <meta
          name="viewport"
          content="width=device-width,initial-scale=1"
        >

        <title>
          Email Verification
        </title>

      </head>

      <body
        style="
          margin:0;
          padding:0;
          background:#f5f5f5;
          font-family:Arial,Helvetica,sans-serif;
          color:#222;
        "
      >

        <div
          style="
            max-width:620px;
            margin:40px auto;
            background:#ffffff;
            border-radius:20px;
            overflow:hidden;
            box-shadow:0 15px 45px rgba(0,0,0,.10);
          "
        >

          <div
            style="
              background:#151515;
              padding:28px 30px;
              text-align:center;
            "
          >

            <div
              style="
                color:#FFD700;
                font-size:12px;
                font-weight:bold;
                letter-spacing:3px;
                text-transform:uppercase;
              "
            >
              PUFFER ISLE RESORT
            </div>

            <div
              style="
                margin-top:8px;
                color:#ffffff;
                font-size:24px;
                font-weight:bold;
              "
            >
              Welcome to IsleRMS
            </div>

          </div>

          <div
            style="
              padding:38px 30px;
            "
          >

            <p
              style="
                margin:0 0 12px;
                font-size:16px;
                color:#333333;
              "
            >
              Please verify your email address.
            </p>

            <p
              style="
                margin:0 0 28px;
                font-size:14px;
                line-height:1.7;
                color:#666666;
              "
            >
              Enter the verification code below in your
              Puffer Isle Resort account.
            </p>

            <div
              style="
                text-align:center;
                margin:28px 0;
              "
            >

              <div
                style="
                  display:inline-block;
                  padding:18px 28px;
                  background:#fff9d6;
                  border:1px solid #f1dc58;
                  border-radius:14px;
                  color:#151515;
                  font-size:32px;
                  font-weight:800;
                  letter-spacing:10px;
                "
              >
                ${safeCode}
              </div>

            </div>

            <p
              style="
                text-align:center;
                margin:0 0 24px;
                color:#888888;
                font-size:13px;
              "
            >
              This code expires in
              <strong>
                ${minutes} minutes
              </strong>.
            </p>

            <div
              style="
                padding:16px;
                background:#f8f8f8;
                border-radius:12px;
                font-size:12px;
                line-height:1.6;
                color:#777777;
              "
            >
              For your security, never share this
              verification code with anyone.
            </div>

          </div>

          <div
            style="
              padding:20px 30px;
              background:#fafafa;
              border-top:1px solid #eeeeee;
              color:#999999;
              font-size:11px;
              line-height:1.6;
              text-align:center;
            "
          >
            © ${new Date().getFullYear()}
            Puffer Isle Resort.
            This is an automated email.
          </div>

        </div>

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

  const result =
    await transporter.sendMail({

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

  return result;

}

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

  existing.count += 1;

  return {

    allowed:
      true,

    retryAfter:
      0,

  };

}

setInterval(
  () => {

    const now =
      Date.now();

    for (
      const [
        key,
        entry
      ]
      of otpRequestTracker.entries()
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

  10 *
  60 *
  1000

).unref();

async function prepareSignupVerification(
  signupData
) {

  const {
    fullname,
    email,
    username,
    password,
    phone,
  } = signupData;

  let user =
    await User.findByEmail(
      email
    );

  if (
    user &&
    user.emailVerified === true
  ) {

    throw new Error(
      "An account with that email already exists."
    );

  }

  if (username) {

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

  let createdNewUser =
    false;

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

    createdNewUser =
      true;

  } else {

    user.fullname =
      fullname;

    if (phone) {

      user.phone =
        phone;

    } else {

      user.phone =
        undefined;

    }

    user.authProvider =
      "local";

    user.emailVerified =
      false;

  }

  if (username) {

    user.username =
      username;

  } else if (
    createdNewUser
  ) {

    user.username =
      undefined;

  }

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
    sessionUser.status !==
      "active"
  ) {

    return destroySession(
      req
    )
      .catch(
        (error) => {

          console.error(
            "SESSION CLEANUP ERROR:",
            error
          );

        }
      )
      .finally(
        () => {

          clearSessionCookie(
            res
          );

          res.redirect(

            "/?auth=login&error=" +

            encodeURIComponent(
              "Your account is currently unavailable."
            )

          );

        }
      );

  }

  next();

}

function requireAdmin(
  req,
  res,
  next
) {

  if (
    !req.session?.admin
  ) {

    return res.redirect(

      "/admin/login?error=" +

      encodeURIComponent(
        "Administrator login required."
      )

    );

  }

  next();

}

app.get(
  "/health",
  (req, res) => {

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

    if (!IS_PRODUCTION) {

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
  (req, res) => {

    const mongoReady =
      mongoose.connection.readyState ===
      1;

    if (!mongoReady) {

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

app.post(
  "/login",
  async (req, res) => {

    try {

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
        )
        .select(
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

      if (!passwordValid) {

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

      await saveSession(
        req
      );

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

app.post(
  "/signup/request-otp",
  async (req, res) => {

    try {

      if (!EMAIL_OTP_ENABLED) {

        return res
          .status(503)
          .json({

            success:
              false,

            message:
              "Email verification is currently unavailable.",

          });

      }

      const validation =
        validateSignupInput(
          req.body
        );

      if (!validation.valid) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              validation.message,

          });

      }

      const {
        fullname,
        email,
        username,
        password,
        confirmPassword,
        phone,
      } = validation.data;

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

      const prepared =
        await prepareSignupVerification({

          fullname,

          email,

          username,

          password,

          confirmPassword,

          phone,

        });

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

          email,

          prepared.verificationCode,

          expiresIn

        );

      } catch (mailError) {

        console.error(
          "VERIFICATION EMAIL SEND ERROR:",
          mailError
        );

        try {

          prepared.user.clearEmailVerification();

          await prepared.user.save();

        } catch (cleanupError) {

          console.error(
            "OTP CLEANUP ERROR:",
            cleanupError
          );

        }

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

    } catch (error) {

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
  async (req, res) => {

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

      if (!result.success) {

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

    } catch (error) {

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
  async (req, res) => {

    try {

      if (!EMAIL_OTP_ENABLED) {

        return res
          .status(503)
          .json({

            success:
              false,

            message:
              "Email verification is currently unavailable.",

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

      } catch (cooldownError) {

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

      } catch (mailError) {

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

    } catch (error) {

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
  async (req, res) => {

    try {

      const validation =
        validateSignupInput(
          req.body
        );

      if (!validation.valid) {

        return redirectAuthError(

          res,

          "signup",

          validation.message

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

      } catch (mailError) {

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

    } catch (error) {

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

function isGoogleOAuthConfigured() {

  return Boolean(

    GOOGLE_CLIENT_ID &&

    GOOGLE_CLIENT_SECRET &&

    GOOGLE_CALLBACK_URL

  );

}

function sanitizeReturnTo(
  value
) {

  const fallback =
    "/";

  const input =
    String(
      value ||
        ""
    ).trim();

  if (!input) {

    return fallback;

  }

  if (
    !input.startsWith("/") ||
    input.startsWith("//")
  ) {

    return fallback;

  }

  return input;

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

app.get(
  "/auth/google",
  async (req, res) => {

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

      const state =
        crypto
          .randomBytes(
            32
          )
          .toString(
            "hex"
          );

      const returnTo =
        sanitizeReturnTo(
          req.query?.returnTo
        );

      req.session.googleOAuthState =
        state;

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

    } catch (error) {

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
);

app.get(
  "/auth/google/callback",
  async (req, res) => {

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
          req.session?.googleOAuthState ||
            ""
        );

      const returnTo =
        sanitizeReturnTo(
          req.session?.googleOAuthReturnTo
        );

      delete req.session.googleOAuthState;

      delete req.session.googleOAuthReturnTo;

      if (
        !state ||
        !storedState ||
        !safeCompareStrings(
          state,
          storedState
        )
      ) {

        return res.redirect(

          "/?auth=login&error=" +

          encodeURIComponent(
            "Google authentication could not be verified."
          )

        );

      }

      if (!code) {

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

        const tokenText =
          await tokenResponse.text();

        console.error(
          "GOOGLE TOKEN ERROR:",
          tokenText
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

      if (!accessToken) {

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

            method:
              "GET",

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

        const profileText =
          await profileResponse.text();

        console.error(
          "GOOGLE PROFILE ERROR:",
          profileText
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
        !isValidEmail(email) ||
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

      if (!user) {

        user =
          await User.findByEmail(
            email
          );

      }

      if (!user) {

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

      await regenerateSession(
        req
      );

      req.session.user =
        createUserSessionData(
          user
        );

      await saveSession(
        req
      );

      return res.redirect(
        303,
        returnTo ||
        "/profile"
      );

    } catch (error) {

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

app.post(
  "/logout",
  async (req, res) => {

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

    } catch (error) {

      console.error(
        "USER LOGOUT ERROR:",
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

app.get(
  "/logout",
  async (req, res) => {

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

    } catch (error) {

      console.error(
        "USER GET LOGOUT ERROR:",
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

    if (req.query?.success) {

      query.set(
        "success",
        String(
          req.query.success
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

app.use(
  "/",
  userRoutes
);

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

// ✅ GALLERY CHANGE: Removed the old SiteSettings-based /gallery route.
// /gallery is now handled by routes/userRoutes.js using models/Gallery.js.

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
  (req, res) => {

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

        }

      );

  }
);

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

    if (!admin) {

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
            "🔐 User Login: /login"
          );

          console.log(
            "🔐 User Signup OTP: /signup/request-otp"
          );

          console.log(
            "🔐 Google Login: /auth/google"
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
        error.message ||
          ""
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