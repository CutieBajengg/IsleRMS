"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * services/bookingAvailability.js
 *
 * SINGLE SOURCE OF TRUTH for room availability and inventory
 * safety.
 *
 * Responsibilities:
 * - Standard date-overlap detection
 * - Room.quantity-aware occupancy calculation
 * - MongoDB-backed distributed room locking
 * - Shared availability logic for customer + admin workflows
 * - Future inventory validation before reducing room quantity
 *
 * IMPORTANT:
 * A normal MongoDB query cannot atomically protect an
 * overlapping date range.
 *
 * The room mutex closes that check-then-insert race by making
 * the final availability check + mutation execute exclusively
 * for the selected room.
 * ============================================================
 */

const crypto = require("crypto");
const mongoose = require("mongoose");

const Appointment = require("../models/Appointment");
const BookingMutex = require("../models/BookingMutex");

/* ============================================================
   CONSTANTS
============================================================ */

const BLOCKING_STATUSES =
  typeof Appointment.getBlockingStatuses === "function"
    ? Appointment.getBlockingStatuses()
    : [
        "pending",
        "accepted",
        "confirmed",
        "checked-in",
      ];

/*
 * Maximum time one request should own a room lock.
 *
 * Normal booking/status operations should finish far below
 * this value.
 */
const DEFAULT_LOCK_LEASE_MS =
  2 * 60 * 1000;

/*
 * Maximum amount of time a competing request will wait before
 * returning a controlled error instead of hanging forever.
 */
const DEFAULT_LOCK_WAIT_MS =
  15 * 1000;

/*
 * Small retry interval used while another request owns the
 * lock.
 */
const LOCK_RETRY_MS =
  60;

/* ============================================================
   BASIC HELPERS
============================================================ */

function isValidObjectId(value) {
  return mongoose.Types.ObjectId.isValid(
    value
  );
}

function normalizeRoomQuantity(room) {
  const raw =
    room?.quantity === undefined ||
    room?.quantity === null
      ? 1
      : Number(room.quantity);

  if (!Number.isFinite(raw)) {
    return 1;
  }

  return Math.max(
    0,
    Math.floor(raw)
  );
}

function escapeRegex(value) {
  return String(value || "").replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );
}

/* ============================================================
   ROOM LOCK RESOURCE
============================================================ */

/**
 * Converts a room document/ID into a stable lock key.
 *
 * Preferred:
 *   room:<MongoObjectId>
 *
 * Legacy fallback:
 *   room-name:<normalized-room-name>
 */
function getRoomResourceKey(
  roomOrId
) {
  const id =
    typeof roomOrId === "object"
      ? roomOrId?._id ||
        roomOrId?.id
      : roomOrId;

  if (
    isValidObjectId(id)
  ) {
    return `room:${String(id)}`;
  }

  const name =
    typeof roomOrId === "object"
      ? roomOrId?.name
      : roomOrId;

  const normalizedName =
    String(name || "")
      .trim()
      .replace(/\s+/g, " ")
      .toLowerCase();

  return normalizedName
    ? `room-name:${normalizedName}`
    : null;
}

function sleep(ms) {
  return new Promise(
    (resolve) =>
      setTimeout(resolve, ms)
  );
}

/* ============================================================
   DISTRIBUTED LOCK
============================================================ */

/**
 * Acquire an exclusive MongoDB-backed resource lock.
 *
 * The unique resourceKey index prevents two processes from
 * becoming owners simultaneously.
 *
 * Expired locks can be taken over safely.
 */
async function acquireResourceLock(
  resourceKey,
  {
    leaseMs =
      DEFAULT_LOCK_LEASE_MS,

    waitMs =
      DEFAULT_LOCK_WAIT_MS,
  } = {}
) {
  if (!resourceKey) {
    throw new Error(
      "A lock resource key is required."
    );
  }

  const ownerToken =
    crypto
      .randomBytes(24)
      .toString("hex");

  const startedAt =
    Date.now();

  while (
    Date.now() - startedAt <=
    waitMs
  ) {
    const now =
      new Date();

    const expiresAt =
      new Date(
        now.getTime() +
          leaseMs
      );

    try {
      const lock =
        await BookingMutex
          .findOneAndUpdate(
            {
              resourceKey,

              $or: [
                {
                  expiresAt: {
                    $lte: now,
                  },
                },
                {
                  ownerToken,
                },
              ],
            },

            {
              $set: {
                ownerToken,
                expiresAt,
              },

              $setOnInsert: {
                resourceKey,
              },
            },

            {
              upsert: true,
              new: true,
              setDefaultsOnInsert:
                true,
            }
          )
          .lean();

      /*
       * Only the owner that receives its own token is allowed
       * to proceed.
       */
      if (
        lock &&
        lock.ownerToken ===
          ownerToken
      ) {
        return {
          resourceKey,
          ownerToken,
          expiresAt,
        };
      }
    } catch (error) {
      /*
       * Another process may win the unique upsert race.
       *
       * E11000 here means:
       * "someone else currently owns this resource."
       *
       * We simply retry.
       */
      if (
        error?.code !==
        11000
      ) {
        throw error;
      }
    }

    await sleep(
      LOCK_RETRY_MS
    );
  }

  const error =
    new Error(
      "The accommodation is busy processing another reservation. Please try again."
    );

  error.code =
    "BOOKING_LOCK_TIMEOUT";

  throw error;
}

/**
 * Release only the lock owned by this request/process.
 *
 * This prevents one process from accidentally deleting another
 * process's lock.
 */
async function releaseResourceLock(
  lock
) {
  if (
    !lock?.resourceKey ||
    !lock?.ownerToken
  ) {
    return;
  }

  try {
    await BookingMutex.deleteOne(
      {
        resourceKey:
          lock.resourceKey,

        ownerToken:
          lock.ownerToken,
      }
    );
  } catch (error) {
    /*
     * The TTL expiry is the final cleanup mechanism.
     *
     * A cleanup failure should not convert an otherwise
     * successful booking into an error response.
     */
    console.error(
      "Booking mutex release error:",
      error.stack ||
        error.message ||
        error
    );
  }
}

/**
 * Generic lock wrapper.
 */
async function withResourceLock(
  resourceKey,
  work,
  options = {}
) {
  const lock =
    await acquireResourceLock(
      resourceKey,
      options
    );

  try {
    return await work(
      lock
    );
  } finally {
    await releaseResourceLock(
      lock
    );
  }
}

/**
 * Room-specific convenience wrapper.
 */
async function withRoomLock(
  roomOrId,
  work,
  options = {}
) {
  const resourceKey =
    getRoomResourceKey(
      roomOrId
    );

  if (!resourceKey) {
    const error =
      new Error(
        "Unable to establish an inventory lock for this accommodation."
      );

    error.code =
      "ROOM_LOCK_UNAVAILABLE";

    throw error;
  }

  return withResourceLock(
    resourceKey,
    work,
    options
  );
}

/* ============================================================
   ROOM MATCHING
============================================================ */

/**
 * Builds a compatibility-aware room filter.
 *
 * roomId is the authoritative relationship.
 *
 * Legacy room fields remain included so old appointments
 * created before roomId was introduced are still recognized.
 */
function buildRoomMatch(
  room
) {
  const roomId =
    room?._id ||
    room?.id ||
    null;

  const roomName =
    room?.name
      ? String(
          room.name
        ).trim()
      : "";

  const conditions =
    [];

  if (
    isValidObjectId(
      roomId
    )
  ) {
    conditions.push({
      roomId,
    });
  }

  if (roomName) {
    const regex =
      new RegExp(
        `^${escapeRegex(
          roomName
        )}$`,
        "i"
      );

    conditions.push(
      {
        room: regex,
      },
      {
        roomType:
          regex,
      },
      {
        accommodation:
          regex,
      },
      {
        roomName:
          regex,
      }
    );
  }

  if (
    conditions.length === 1
  ) {
    return conditions[0];
  }

  return {
    $or: conditions,
  };
}

/* ============================================================
   OVERLAP QUERY
============================================================ */

/**
 * Standard accommodation overlap:
 *
 * existing.checkin < requested.checkout
 * AND
 * existing.checkout > requested.checkin
 *
 * This intentionally allows:
 *
 * Booking A checkout = June 10
 * Booking B checkin  = June 10
 *
 * because one guest leaves before the next guest arrives.
 */
function buildOverlapQuery({
  room,
  checkin,
  checkout,
  excludeAppointmentId =
    null,
}) {
  const match =
    buildRoomMatch(
      room
    );

  const query = {
    status: {
      $in:
        BLOCKING_STATUSES,
    },

    checkin: {
      $lt: checkout,
    },

    checkout: {
      $gt: checkin,
    },

    ...(match?.$or
      ? match
      : match),
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

  return query;
}

/* ============================================================
   GET OVERLAPPING BOOKINGS
============================================================ */

async function getOverlappingAppointments({
  room,
  checkin,
  checkout,
  excludeAppointmentId =
    null,
}) {
  if (
    !room?._id &&
    !room?.id &&
    !room?.name
  ) {
    return [];
  }

  const start =
    new Date(
      checkin
    );

  const end =
    new Date(
      checkout
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
    return [];
  }

  return Appointment
    .find(
      buildOverlapQuery({
        room,
        checkin:
          start,
        checkout:
          end,
        excludeAppointmentId,
      })
    )
    .select(
      [
        "_id",
        "roomId",
        "room",
        "roomType",
        "accommodation",
        "roomName",
        "checkin",
        "checkout",
        "status",
      ].join(" ")
    )
    .sort({
      checkin: 1,
      checkout: 1,
    })
    .lean();
}

/* ============================================================
   OCCUPANCY EVENTS
============================================================ */

/**
 * Convert reservations into occupancy events.
 */
function buildEvents(
  appointments,
  requestedStart,
  requestedEnd
) {
  const events =
    [];

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
      start >
      requestedStart
        ? start
        : requestedStart;

    const overlapEnd =
      end <
      requestedEnd
        ? end
        : requestedEnd;

    if (
      overlapEnd <=
      overlapStart
    ) {
      continue;
    }

    events.push({
      time:
        overlapStart.getTime(),

      delta:
        1,

      appointment,
    });

    events.push({
      time:
        overlapEnd.getTime(),

      delta:
        -1,

      appointment,
    });
  }

  /*
   * At the exact same timestamp:
   *
   * -1 must happen before +1.
   *
   * That means:
   *
   * checkout at 12:00
   * checkin  at 12:00
   *
   * does NOT temporarily count as two occupied units.
   */
  events.sort(
    (a, b) =>
      a.time !== b.time
        ? a.time - b.time
        : a.delta - b.delta
  );

  return events;
}

/* ============================================================
   PEAK FUTURE OCCUPANCY
============================================================ */

/**
 * Returns the maximum number of simultaneous units occupied
 * by active reservations from the supplied date onward.
 *
 * Used before reducing Room.quantity.
 */
async function getPeakOccupancy({
  room,
  fromDate =
    new Date(),
  excludeAppointmentId =
    null,
}) {
  if (
    !room?._id &&
    !room?.id &&
    !room?.name
  ) {
    return 0;
  }

  const from =
    new Date(
      fromDate
    );

  if (
    Number.isNaN(
      from.getTime()
    )
  ) {
    return 0;
  }

  const match =
    buildRoomMatch(
      room
    );

  const query = {
    status: {
      $in:
        BLOCKING_STATUSES,
    },

    checkout: {
      $gt: from,
    },

    ...(match?.$or
      ? match
      : match),
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
    await Appointment
      .find(
        query
      )
      .select(
        [
          "_id",
          "roomId",
          "room",
          "roomType",
          "accommodation",
          "roomName",
          "checkin",
          "checkout",
          "status",
        ].join(" ")
      )
      .sort({
        checkin: 1,
        checkout: 1,
      })
      .lean();

  const events =
    [];

  for (
    const appointment of
      appointments
  ) {
    const startRaw =
      new Date(
        appointment.checkin
      );

    const end =
      new Date(
        appointment.checkout
      );

    if (
      Number.isNaN(
        startRaw.getTime()
      ) ||
      Number.isNaN(
        end.getTime()
      ) ||
      end <= startRaw
    ) {
      continue;
    }

    const start =
      startRaw > from
        ? startRaw
        : from;

    if (
      end <= start
    ) {
      continue;
    }

    events.push({
      time:
        start.getTime(),
      delta:
        1,
    });

    events.push({
      time:
        end.getTime(),
      delta:
        -1,
    });
  }

  events.sort(
    (a, b) =>
      a.time !== b.time
        ? a.time - b.time
        : a.delta - b.delta
  );

  let occupancy =
    0;

  let peak =
    0;

  for (
    const event of
      events
  ) {
    occupancy +=
      event.delta;

    peak =
      Math.max(
        peak,
        occupancy
      );
  }

  return peak;
}

/* ============================================================
   FINAL AVAILABILITY CHECK
============================================================ */

/**
 * Checks whether the requested stay can fit inside the
 * room's quantity.
 *
 * Example:
 *
 * Room quantity = 3
 *
 * Existing overlapping:
 *   Booking A
 *   Booking B
 *
 * Occupancy = 2
 *
 * New booking:
 *   allowed
 *
 * If:
 *   Booking A
 *   Booking B
 *   Booking C
 *
 * Occupancy = 3
 *
 * New booking:
 *   rejected
 */
async function findAvailabilityConflict({
  room,
  checkin,
  checkout,
  excludeAppointmentId =
    null,
}) {
  const quantity =
    normalizeRoomQuantity(
      room
    );

  if (
    quantity <= 0
  ) {
    return {
      reason:
        "NO_INVENTORY",

      conflict:
        null,

      occupancy:
        0,

      capacity:
        quantity,
    };
  }

  const start =
    new Date(
      checkin
    );

  const end =
    new Date(
      checkout
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
    return {
      reason:
        "INVALID_DATES",

      conflict:
        null,
    };
  }

  const appointments =
    await getOverlappingAppointments(
      {
        room,
        checkin:
          start,
        checkout:
          end,
        excludeAppointmentId,
      }
    );

  const events =
    buildEvents(
      appointments,
      start,
      end
    );

  let occupancy =
    0;

  for (
    const event of
      events
  ) {
    occupancy +=
      event.delta;

    if (
      occupancy >=
      quantity
    ) {
      return {
        reason:
          "NO_INVENTORY",

        conflict:
          event.appointment,

        occupancy,

        capacity:
          quantity,
      };
    }
  }

  return null;
}

/* ============================================================
   EXPORTS
============================================================ */

module.exports = {
  BLOCKING_STATUSES,

  normalizeRoomQuantity,

  getRoomResourceKey,

  withResourceLock,

  withRoomLock,

  getOverlappingAppointments,

  getPeakOccupancy,

  findAvailabilityConflict,
};