"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * middleware/csrf.js
 *
 * CSRF protection used by customer and administrator routes.
 *
 * Compatibility exports are intentionally preserved:
 * - ensureCsrfToken
 * - csrfMiddleware
 * - verifyCsrf
 *
 * Additional exports:
 * - attachCsrfToken
 * - verifyCsrfToken
 * - rotateCsrfToken
 * - getCsrfToken
 *
 * The token is stored server-side in the session and submitted by
 * the browser using either:
 *   _csrf form field
 *   X-CSRF-Token header
 *   X-XSRF-Token header
 * ============================================================
 */

const crypto = require("crypto");

const TOKEN_BYTES = 32;
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours

function createToken() {
  return crypto
    .randomBytes(TOKEN_BYTES)
    .toString("hex");
}

function ensureCsrfToken(req) {
  if (!req.session) {
    throw new Error(
      "CSRF middleware requires express-session to run first."
    );
  }

  const now = Date.now();
  const existingToken = req.session.csrfToken;
  const issuedAt = Number(
    req.session.csrfTokenIssuedAt || 0
  );

  const tokenExpired =
    !issuedAt ||
    !Number.isFinite(issuedAt) ||
    issuedAt <= 0 ||
    now - issuedAt > TOKEN_TTL_MS;

  if (
    !existingToken ||
    tokenExpired
  ) {
    req.session.csrfToken = createToken();
    req.session.csrfTokenIssuedAt = now;
  }

  return req.session.csrfToken;
}

function rotateCsrfToken(req) {
  if (!req.session) {
    throw new Error(
      "CSRF token rotation requires express-session to run first."
    );
  }

  req.session.csrfToken = createToken();
  req.session.csrfTokenIssuedAt = Date.now();

  return req.session.csrfToken;
}

function getCsrfToken(req) {
  return req.session?.csrfToken || null;
}

function attachCsrfToken(req, res, next) {
  try {
    const token = ensureCsrfToken(req);

    res.locals.csrfToken = token;

    return next();
  } catch (error) {
    return next(error);
  }
}

/*
 * Compare token buffers in constant time.
 */
function safeTokenEquals(expected, provided) {
  if (!expected || !provided) {
    return false;
  }

  const expectedBuffer = Buffer.from(
    String(expected),
    "utf8"
  );

  const providedBuffer = Buffer.from(
    String(provided),
    "utf8"
  );

  if (
    expectedBuffer.length !==
    providedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    expectedBuffer,
    providedBuffer
  );
}

function getProvidedToken(req) {
  return (
    req.body?._csrf ||
    req.get("x-csrf-token") ||
    req.get("x-xsrf-token") ||
    null
  );
}

function isJsonRequest(req) {
  const accept = String(
    req.headers?.accept || ""
  ).toLowerCase();

  return Boolean(
    req.xhr ||
    req.path.startsWith("/api/") ||
    req.path.startsWith("/admin/api/") ||
    accept.includes("application/json")
  );
}

function csrfFailure(res, req) {
  const requestId = req.requestId || null;

  if (isJsonRequest(req)) {
    return res.status(403).json({
      success: false,
      code: "CSRF_INVALID",
      message:
        "Your security token is invalid or expired. Refresh the page and try again.",
      ...(requestId
        ? { requestId }
        : {}),
    });
  }

  return res.status(403).render(
    "error",
    {
      title:
        "Security Check Failed | Puffer Isle Resort",
      statusCode: 403,
      error:
        "Your security token is invalid or expired. Please return to the previous page and try again.",
      requestId,
    }
  );
}

function verifyCsrf(req, res, next) {
  try {
    const expected =
      req.session?.csrfToken;

    /*
     * We also enforce token freshness when the issue timestamp exists.
     * Existing sessions that predate csrfTokenIssuedAt remain compatible.
     */
    const issuedAt = Number(
      req.session?.csrfTokenIssuedAt || 0
    );

    if (
      issuedAt &&
      (
        !Number.isFinite(issuedAt) ||
        Date.now() - issuedAt >
          TOKEN_TTL_MS
      )
    ) {
      return csrfFailure(
        res,
        req
      );
    }

    const provided =
      getProvidedToken(req);

    if (
      !safeTokenEquals(
        expected,
        provided
      )
    ) {
      return csrfFailure(
        res,
        req
      );
    }

    return next();
  } catch (error) {
    return next(error);
  }
}

/* ============================================================
   COMPATIBILITY ALIASES
   ============================================================ */

const csrfMiddleware =
  attachCsrfToken;

const verifyCsrfToken =
  verifyCsrf;

module.exports = {
  createToken,
  ensureCsrfToken,
  csrfMiddleware,
  attachCsrfToken,
  verifyCsrf,
  verifyCsrfToken,
  rotateCsrfToken,
  getCsrfToken,
  safeTokenEquals,
};