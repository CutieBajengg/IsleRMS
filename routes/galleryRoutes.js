"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * routes/galleryRoutes.js
 *
 * SPATIAL / STREET VIEW-STYLE GALLERY ADMIN ROUTES
 *
 * Backward compatible with:
 *   left, right, forward, backward
 *
 * Adds support for:
 *   slug, thumbnail, description, caption, alt,
 *   category, location, tags, projection,
 *   heading, pitch, fov, northOffset,
 *   position {x,y,z}, mapPosition {x,y},
 *   hotspots[], tour/viewer/map settings.
 *
 * Mounted by:
 *   routes/adminRoutes.js
 *
 * Routes:
 *   GET  /admin/gallery-editor
 *   POST /admin/gallery-editor
 *   POST /admin/gallery-editor/delete
 *   GET  /admin/api/gallery
 * ============================================================
 */

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const Gallery =
  require("../models/Gallery");

const csrf =
  require("../middleware/csrf");

const verifyCsrfToken =
  csrf.verifyCsrfToken ||
  csrf.verifyCsrf;

const router =
  express.Router();


/* ============================================================
   SAFETY CHECK
============================================================ */

if (
  typeof verifyCsrfToken !==
  "function"
) {
  throw new Error(
    "CSRF middleware is missing a compatible verification function."
  );
}


/* ============================================================
   CONFIGURATION
============================================================ */

const ADMIN_CSRF_REQUIRED =
  String(
    process.env.ADMIN_CSRF_REQUIRED ||
      "false"
  )
    .trim()
    .toLowerCase() ===
  "true";


const GALLERY_IMAGE_MAX_BYTES =
  25 *
  1024 *
  1024;


const GALLERY_UPLOAD_DIR =
  path.join(
    __dirname,
    "..",
    "public",
    "uploads",
    "gallery"
  );


const GALLERY_PUBLIC_PREFIX =
  "/uploads/gallery/";


const GALLERY_IMAGE_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
];


const MIN_FOV =
  30;

const MAX_FOV =
  110;


/* ============================================================
   FILE SYSTEM INITIALIZATION
============================================================ */

try {

  fs.mkdirSync(
    GALLERY_UPLOAD_DIR,
    {
      recursive:
        true,
    }
  );

} catch (error) {

  console.error(
    "Gallery upload directory initialization failed:",
    error.stack ||
      error.message ||
      error
  );
}


/* ============================================================
   MULTER
============================================================ */

const galleryUpload =
  multer({
    storage:
      multer.memoryStorage(),

    limits: {
      fileSize:
        GALLERY_IMAGE_MAX_BYTES,

      files: 1,
    },

    fileFilter:
      function (
        req,
        file,
        callback
      ) {

        const mimetype =
          String(
            file?.mimetype ||
              ""
          )
            .trim()
            .toLowerCase();


        if (
          GALLERY_IMAGE_CONTENT_TYPES.includes(
            mimetype
          )
        ) {

          return callback(
            null,
            true
          );
        }


        return callback(
          new Error(
            "Only JPG, PNG, and WEBP images are allowed."
          )
        );
      },
  });


/* ============================================================
   BASIC HELPERS
============================================================ */

function hasOwn(
  object,
  key
) {

  return Object.prototype.hasOwnProperty.call(
    object || {},
    key
  );
}


function normalizeString(
  value,
  maxLength = 500
) {

  if (
    value === undefined ||
    value === null
  ) {

    return "";
  }


  return String(
    value
  )
    .trim()
    .replace(
      /\s+/g,
      " "
    )
    .slice(
      0,
      maxLength
    );
}


function normalizeTitle(
  value
) {

  return (
    normalizeString(
      value,
      150
    ) ||
    "Resort Photo"
  );
}


function normalizeSlug(
  value,
  fallback = ""
) {

  return (
    normalizeString(
      value ||
        fallback,
      180
    )
      .toLowerCase()
      .replace(
        /[^a-z0-9]+/g,
        "-"
      )
      .replace(
        /^-+|-+$/g,
        ""
      )
      .slice(
        0,
        180
    )
  );
}


function normalizeBoolean(
  value,
  fallback = false
) {

  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {

    return fallback;
  }


  if (
    value === true ||
    value === "true" ||
    value === "1" ||
    value === 1 ||
    value === "on" ||
    value === "yes"
  ) {

    return true;
  }


  if (
    value === false ||
    value === "false" ||
    value === "0" ||
    value === 0 ||
    value === "off" ||
    value === "no"
  ) {

    return false;
  }


  return fallback;
}


function parseNumber(
  value,
  fallback = null
) {

  if (
    value === undefined ||
    value === null ||
    String(
      value
    ).trim() ===
      ""
  ) {

    return fallback;
  }


  const parsed =
    Number(
      value
    );


  return Number.isFinite(
    parsed
  )
    ? parsed
    : fallback;
}


function parseInteger(
  value,
  fallback = null
) {

  const parsed =
    parseNumber(
      value,
      fallback
    );


  return Number.isInteger(
    parsed
  )
    ? parsed
    : fallback;
}


function clamp(
  value,
  min,
  max,
  fallback = null
) {

  const parsed =
    parseNumber(
      value,
      fallback
    );


  if (
    !Number.isFinite(
      parsed
    )
  ) {

    return fallback;
  }


  return Math.min(
    max,
    Math.max(
      min,
      parsed
    )
  );
}


function parseJson(
  value,
  fallback = null
) {

  if (
    value === undefined ||
    value === null
  ) {

    return fallback;
  }


  if (
    typeof value ===
    "object"
  ) {

    return value;
  }


  const text =
    String(
      value
    ).trim();


  if (!text) {

    return fallback;
  }


  try {

    return JSON.parse(
      text
    );

  } catch (_) {

    return fallback;
  }
}


function getFirst(
  body,
  keys
) {

  for (
    const key of
    keys
  ) {

    if (
      hasOwn(
        body,
        key
      )
    ) {

      return body[
        key
      ];
    }
  }


  return undefined;
}


function getAdminSession(
  req
) {

  return (
    req.session?.admin ||
    null
  );
}


function getRequestId(
  req
) {

  return (
    normalizeString(
      req.requestId ||
        "",
      120
    ) ||
    null
  );
}


function logGalleryAdminAction(
  req,
  action,
  details = {}
) {

  const admin =
    getAdminSession(
      req
    );


  const adminId =
    admin?.id ||
    admin?._id ||
    "unknown";


  const detailText =
    Object.entries(
      details
    )
      .map(
        ([key, value]) => {

          const safe =
            String(
              value
            ).replace(
              /[\r\n]+/g,
              " "
            );

          return `${key}=${safe}`;
        }
      )
      .join(
        " "
      );


  console.log(
    `[ADMIN ACTION] action=${action} adminId=${adminId} username=${
      admin?.username ||
      "unknown"
    } requestId=${
      getRequestId(req) ||
      "none"
    } ${detailText}`
  );
}


/* ============================================================
   ADMIN AUTHENTICATION
============================================================ */

function isValidAdminSession(
  req
) {

  const admin =
    req.session?.admin;


  const adminId =
    admin?.id ||
    admin?._id;


  return Boolean(
    admin &&
      adminId &&
      mongoose.Types.ObjectId.isValid(
        String(
          adminId
        )
      )
  );
}


function requireGalleryAdmin(
  req,
  res,
  next
) {

  if (
    isValidAdminSession(
      req
    )
  ) {

    return next();
  }


  if (
    req.method ===
    "GET"
  ) {

    return res.redirect(
      "/admin/login?error=" +
        encodeURIComponent(
          "Administrator login required."
        )
    );
  }


  return res
    .status(401)
    .json({
      success:
        false,

      message:
        "Administrator authentication required.",
    });
}


/* ============================================================
   CSRF
============================================================ */

function verifyAdminMutationCsrf(
  req,
  res,
  next
) {

  if (
    !ADMIN_CSRF_REQUIRED
  ) {

    return next();
  }


  return verifyCsrfToken(
    req,
    res,
    next
  );
}


function requireGalleryMutation(
  req,
  res,
  next
) {

  return requireGalleryAdmin(
    req,
    res,
    () =>
      verifyAdminMutationCsrf(
        req,
        res,
        next
      )
  );
}


/* ============================================================
   IMAGE VALIDATION
============================================================ */

function detectGalleryImageType(
  buffer
) {

  if (
    !Buffer.isBuffer(
      buffer
    ) ||
    buffer.length <
      12
  ) {

    return null;
  }


  /* JPEG */

  if (
    buffer[0] ===
      0xff &&
    buffer[1] ===
      0xd8 &&
    buffer[2] ===
      0xff
  ) {

    return {
      extension:
        "jpg",

      contentType:
        "image/jpeg",
    };
  }


  /* PNG */

  const pngSignature =
    Buffer.from([
      0x89,
      0x50,
      0x4e,
      0x47,
      0x0d,
      0x0a,
      0x1a,
      0x0a,
    ]);


  if (
    buffer.length >=
      pngSignature.length &&
    buffer
      .subarray(
        0,
        pngSignature.length
      )
      .equals(
        pngSignature
      )
  ) {

    return {
      extension:
        "png",

      contentType:
        "image/png",
    };
  }


  /* WEBP */

  if (
    buffer.toString(
      "ascii",
      0,
      4
    ) ===
      "RIFF" &&
    buffer.toString(
      "ascii",
      8,
      12
    ) ===
      "WEBP"
  ) {

    return {
      extension:
        "webp",

      contentType:
        "image/webp",
    };
  }


  return null;
}


function isManagedGalleryImageUrl(
  value
) {

  const normalized =
    normalizeString(
      value,
      2000
    );


  if (
    !normalized.startsWith(
      GALLERY_PUBLIC_PREFIX
    )
  ) {

    return false;
  }


  const filename =
    normalized.slice(
      GALLERY_PUBLIC_PREFIX.length
    );


  if (
    !filename ||
    filename.includes(
      "/"
    ) ||
    filename.includes(
      "\\"
    )
  ) {

    return false;
  }


  return /^[A-Za-z0-9._-]+$/.test(
    filename
  );
}


function isAllowedGalleryReference(
  value
) {

  const image =
    normalizeString(
      value,
      2000
    );


  if (!image) {

    return false;
  }


  if (
    image.startsWith(
      "/images/"
    )
  ) {

    return true;
  }


  if (
    image.startsWith(
      GALLERY_PUBLIC_PREFIX
    )
  ) {

    return isManagedGalleryImageUrl(
      image
    );
  }


  return false;
}


function galleryImageAbsolutePathFromUrl(
  value
) {

  if (
    !isManagedGalleryImageUrl(
      value
    )
  ) {

    return null;
  }


  const filename =
    value.slice(
      GALLERY_PUBLIC_PREFIX.length
    );


  const uploadRoot =
    path.resolve(
      GALLERY_UPLOAD_DIR
    );


  const absolutePath =
    path.resolve(
      GALLERY_UPLOAD_DIR,
      filename
    );


  if (
    absolutePath !==
      uploadRoot &&
    !absolutePath.startsWith(
      `${uploadRoot}${path.sep}`
    )
  ) {

    return null;
  }


  return absolutePath;
}


async function removeManagedGalleryImage(
  imageUrl
) {

  const filePath =
    galleryImageAbsolutePathFromUrl(
      imageUrl
    );


  if (!filePath) {

    return;
  }


  try {

    await fs.promises.unlink(
      filePath
    );

  } catch (error) {

    if (
      error?.code !==
      "ENOENT"
    ) {

      console.warn(
        "Unable to remove gallery image:",
        error.message ||
          error
      );
    }
  }
}


function createGalleryImageFilename(
  extension
) {

  return (
    `gallery-${Date.now()}-${crypto
      .randomBytes(
        16
      )
      .toString(
        "hex"
      )}.${extension}`
  );
}


async function saveGalleryImageBuffer(
  buffer,
  imageType
) {

  await fs.promises.mkdir(
    GALLERY_UPLOAD_DIR,
    {
      recursive:
        true,
    }
  );


  const filename =
    createGalleryImageFilename(
      imageType.extension
    );


  const finalPath =
    path.join(
      GALLERY_UPLOAD_DIR,
      filename
    );


  const temporaryPath =
    `${finalPath}.${crypto
      .randomBytes(
        6
      )
      .toString(
        "hex"
      )}.tmp`;


  await fs.promises.writeFile(
    temporaryPath,
    buffer,
    {
      flag:
        "wx",
    }
  );


  try {

    await fs.promises.rename(
      temporaryPath,
      finalPath
    );

  } catch (error) {

    try {

      await fs.promises.unlink(
        temporaryPath
      );

    } catch (_) {
      /* Best effort cleanup. */
    }


    throw error;
  }


  return {
    filename,

    path:
      finalPath,

    url:
      `${GALLERY_PUBLIC_PREFIX}${filename}`,
  };
}


/* ============================================================
   GALLERY DATA HELPERS
============================================================ */

function galleryItemToPlain(
  item
) {

  if (!item) {

    return null;
  }


  if (
    typeof item.toObject ===
    "function"
  ) {

    return item.toObject();
  }


  return {
    ...item,
  };
}


function sortGalleryImages(
  galleryImages
) {

  return (
    Array.isArray(
      galleryImages
    )
      ? galleryImages
      : []
  )
    .map(
      (
        item,
        originalIndex
      ) => ({
        item,
        originalIndex,
      })
    )
    .sort(
      (
        a,
        b
      ) => {

        const orderA =
          Number.isFinite(
            Number(
              a.item?.order
            )
          )
            ? Number(
                a.item.order
              )
            : a.originalIndex +
              1;


        const orderB =
          Number.isFinite(
            Number(
              b.item?.order
            )
          )
            ? Number(
                b.item.order
              )
            : b.originalIndex +
              1;


        if (
          orderA !==
          orderB
        ) {

          return (
            orderA -
            orderB
          );
        }


        return (
          a.originalIndex -
          b.originalIndex
        );
      }
    )
    .map(
      (
        entry
      ) =>
        entry.item
    );
}


function normalizeGalleryOrder(
  galleryImages
) {

  const sorted =
    sortGalleryImages(
      galleryImages
    );


  sorted.forEach(
    (
      item,
      index
    ) => {

      item.order =
        index + 1;
    }
  );


  return sorted;
}


/* ============================================================
   SCENE TARGET
============================================================ */

function getGalleryTargetIndex(
  galleryImages,
  body = {}
) {

  const imageId =
    normalizeString(
      body.imageId ||
        body.galleryId ||
        body.id ||
        "",
      100
    );


  if (
    imageId &&
    mongoose.Types.ObjectId.isValid(
      imageId
    )
  ) {

    const index =
      galleryImages.findIndex(
        (item) =>
          String(
            item?._id ||
              ""
          ) ===
          imageId
      );


    if (
      index >= 0
    ) {

      return index;
    }
  }


  const imageKey =
    normalizeString(
      body.imageKey ||
        "",
      1000
    );


  if (
    imageKey
  ) {

    const index =
      galleryImages.findIndex(
        (item) =>
          String(
            item?.image ||
              ""
          ) ===
          imageKey
      );


    if (
      index >= 0
    ) {

      return index;
    }
  }


  const rawIndex =
    body.imageIndex;


  if (
    rawIndex !==
      undefined &&
    rawIndex !==
      null &&
    String(
      rawIndex
    ).trim() !==
      ""
  ) {

    const index =
      Number(
        rawIndex
      );


    if (
      Number.isInteger(
        index
      ) &&
      index >= 0 &&
      index <
        galleryImages.length
    ) {

      return index;
    }
  }


  return -1;
}


/* ============================================================
   LEGACY NAVIGATION
============================================================ */

function parseDirectionValue(
  value
) {

  if (
    value === undefined ||
    value === null ||
    String(
      value
    ).trim() ===
      ""
  ) {

    return null;
  }


  const parsed =
    Number(
      value
    );


  return Number.isInteger(
    parsed
  )
    ? parsed
    : null;
}


function sanitizeDirectionValue(
  value,
  totalLength,
  selfIndex
) {

  const parsed =
    parseDirectionValue(
      value
    );


  if (
    parsed ===
    null
  ) {

    return null;
  }


  if (
    parsed < 0 ||
    parsed >=
      totalLength
  ) {

    return null;
  }


  if (
    parsed ===
    selfIndex
  ) {

    return null;
  }


  return parsed;
}


function applyNavigationFields(
  item,
  body,
  totalLength,
  currentIndex
) {

  [
    "left",
    "right",
    "forward",
    "backward",
  ].forEach(
    (
      direction
    ) => {

      if (
        !hasOwn(
          body,
          direction
        )
      ) {

        return;
      }


      item[
        direction
      ] =
        sanitizeDirectionValue(
          body[
            direction
          ],
          totalLength,
          currentIndex
        );
    }
  );
}


/* ============================================================
   TAGS
============================================================ */

function normalizeTags(
  value
) {

  let tags =
    value;


  if (
    typeof tags ===
    "string"
  ) {

    tags =
      tags.split(
        ","
      );
  }


  if (
    !Array.isArray(
      tags
    )
  ) {

    return [];
  }


  return [
    ...new Set(
      tags
        .map(
          (
            tag
          ) =>
            normalizeString(
              tag,
              60
            )
              .toLowerCase()
        )
        .filter(Boolean)
    ),
  ].slice(
    0,
    30
  );
}


/* ============================================================
   HOTSPOTS
============================================================ */

function normalizeHotspot(
  hotspot,
  totalLength,
  currentIndex
) {

  if (
    !hotspot ||
    typeof hotspot !==
      "object"
  ) {

    return null;
  }


  let target =
    hotspot.target ??
    hotspot.scene ??
    hotspot.destination ??
    null;


  if (
    typeof target ===
      "string" &&
    /^-?\d+$/.test(
      target.trim()
    )
  ) {

    target =
      Number(
        target.trim()
      );
  }


  const numericTarget =
    Number.isInteger(
      target
    )
      ? target
      : null;


  let targetIndex =
    parseInteger(
      hotspot.targetIndex,
      null
    );


  if (
    targetIndex !==
      null
  ) {

    if (
      targetIndex <
        0 ||
      targetIndex >=
        totalLength ||
      targetIndex ===
        currentIndex
    ) {

      targetIndex =
        null;
    }
  }


  if (
    numericTarget !==
      null
  ) {

    if (
      numericTarget <
        0 ||
      numericTarget >=
        totalLength ||
      numericTarget ===
        currentIndex
    ) {

      target =
        null;
    }
  }


  return {
    type:
      normalizeString(
        hotspot.type ||
          "info",
        40
      ).toLowerCase(),

    yaw:
      clamp(
        hotspot.yaw,
        -360,
        360,
        0
      ),

    pitch:
      clamp(
        hotspot.pitch,
        -89,
        89,
        0
      ),

    title:
      normalizeString(
        hotspot.title ||
          "Explore this location",
        150
      ),

    label:
      normalizeString(
        hotspot.label ||
          hotspot.title ||
          "Explore",
        120
      ),

    description:
      normalizeString(
        hotspot.description ||
          "",
        2000
      ),

    icon:
      normalizeString(
        hotspot.icon ||
          "info",
        60
      ),

    target,

    targetSceneId:
      normalizeString(
        hotspot.targetSceneId ||
          "",
        100
      ) ||
      null,

    targetIndex,

    action:
      normalizeString(
        hotspot.action ||
          "info",
        50
      ).toLowerCase(),

    url:
      normalizeString(
        hotspot.url ||
          "",
        2000
      ),

    visible:
      normalizeBoolean(
        hotspot.visible,
        true
      ),

    interactive:
      normalizeBoolean(
        hotspot.interactive,
        true
      ),

    scale:
      clamp(
        hotspot.scale,
        0.25,
        5,
        1
      ),
  };
}


function parseHotspots(
  body,
  existing = [],
  totalLength = 0,
  currentIndex = -1
) {

  const supplied =
    getFirst(
      body,
      [
        "hotspots",
        "hotspotsJson",
        "hotspotData",
      ]
    );


  if (
    !hasOwn(
      body,
      "hotspots"
    ) &&
    !hasOwn(
      body,
      "hotspotsJson"
    ) &&
    !hasOwn(
      body,
      "hotspotData"
    )
  ) {

    return existing ||
      [];
  }


  const parsed =
    parseJson(
      supplied,
      []
    );


  if (
    !Array.isArray(
      parsed
    )
  ) {

    return [];
  }


  return parsed
    .map(
      (
        hotspot
      ) =>
        normalizeHotspot(
          hotspot,
          totalLength,
          currentIndex
        )
    )
    .filter(Boolean);
}


/* ============================================================
   SPATIAL POSITION
============================================================ */

function applyPosition(
  item,
  body
) {

  const current =
    item.position ||
    {};


  const json =
    parseJson(
      getFirst(
        body,
        [
          "position",
          "positionJson",
        ]
      ),
      null
    );


  const position =
    {
      x:
        current.x ??
        null,

      y:
        current.y ??
        null,

      z:
        current.z ??
        null,
    };


  if (
    json &&
    typeof json ===
      "object"
  ) {

    if (
      hasOwn(
        json,
        "x"
      )
    ) {

      position.x =
        parseNumber(
          json.x,
          null
        );
    }


    if (
      hasOwn(
        json,
        "y"
      )
    ) {

      position.y =
        parseNumber(
          json.y,
          null
        );
    }


    if (
      hasOwn(
        json,
        "z"
      )
    ) {

      position.z =
        parseNumber(
          json.z,
          null
        );
    }
  }


  if (
    hasOwn(
      body,
      "positionX"
    )
  ) {

    position.x =
      parseNumber(
        body.positionX,
        null
      );
  }


  if (
    hasOwn(
      body,
      "positionY"
    )
  ) {

    position.y =
      parseNumber(
        body.positionY,
        null
      );
  }


  if (
    hasOwn(
      body,
      "positionZ"
    )
  ) {

    position.z =
      parseNumber(
        body.positionZ,
        null
      );
  }


  item.position =
    position;
}


/* ============================================================
   MAP POSITION
============================================================ */

function applyMapPosition(
  item,
  body
) {

  const current =
    item.mapPosition ||
    {};


  const json =
    parseJson(
      getFirst(
        body,
        [
          "mapPosition",
          "mapPositionJson",
        ]
      ),
      null
    );


  const mapPosition =
    {
      x:
        current.x ??
        null,

      y:
        current.y ??
        null,
    };


  if (
    json &&
    typeof json ===
      "object"
  ) {

    if (
      hasOwn(
        json,
        "x"
      )
    ) {

      mapPosition.x =
        clamp(
          json.x,
          0,
          1,
          null
        );
    }


    if (
      hasOwn(
        json,
        "y"
      )
    ) {

      mapPosition.y =
        clamp(
          json.y,
          0,
          1,
          null
        );
    }
  }


  if (
    hasOwn(
      body,
      "mapX"
    )
  ) {

    mapPosition.x =
      clamp(
        body.mapX,
        0,
        1,
        null
      );
  }


  if (
    hasOwn(
      body,
      "mapY"
    )
  ) {

    mapPosition.y =
      clamp(
        body.mapY,
        0,
        1,
        null
      );
  }


  item.mapPosition =
    mapPosition;
}


/* ============================================================
   SCENE METADATA
============================================================ */

function applySceneMetadata(
  item,
  body,
  mode,
  currentIndex,
  totalLength
) {

  const isAdd =
    mode ===
    "add";


  if (
    isAdd ||
    hasOwn(
      body,
      "title"
    )
  ) {

    item.title =
      normalizeTitle(
        body.title
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "slug"
    )
  ) {

    item.slug =
      normalizeSlug(
        body.slug,
        item.title
      );
  }


  const textFields =
    [
      [
        "description",
        2000,
      ],
      [
        "caption",
        1000,
      ],
      [
        "alt",
        500,
      ],
      [
        "category",
        100,
      ],
      [
        "location",
        300,
      ],
    ];


  textFields.forEach(
    (
      [field, maxLength]
    ) => {

      if (
        isAdd ||
        hasOwn(
          body,
          field
        )
      ) {

        item[field] =
          normalizeString(
            body[field],
            maxLength
          );
      }
    }
  );


  if (
    isAdd ||
    hasOwn(
      body,
      "tags"
    ) ||
    hasOwn(
      body,
      "tagsJson"
    )
  ) {

    const rawTags =
      getFirst(
        body,
        [
          "tags",
          "tagsJson",
        ]
      );


    item.tags =
      normalizeTags(
        parseJson(
          rawTags,
          rawTags
        )
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "projection"
    )
  ) {

    item.projection =
      normalizeString(
        body.projection ||
          "equirectangular",
        50
      )
        .toLowerCase() ||
      "equirectangular";
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "active"
    )
  ) {

    item.active =
      normalizeBoolean(
        body.active,
        true
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "featured"
    )
  ) {

    item.featured =
      normalizeBoolean(
        body.featured,
        false
      );
  }


  /* CAMERA */

  if (
    isAdd ||
    hasOwn(
      body,
      "heading"
    )
  ) {

    item.heading =
      clamp(
        body.heading,
        -360,
        360,
        0
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "pitch"
    )
  ) {

    item.pitch =
      clamp(
        body.pitch,
        -89,
        89,
        0
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "fov"
    )
  ) {

    item.fov =
      clamp(
        body.fov,
        MIN_FOV,
        MAX_FOV,
        75
      );
  }


  if (
    isAdd ||
    hasOwn(
      body,
      "northOffset"
    )
  ) {

    item.northOffset =
      clamp(
        body.northOffset,
        -360,
        360,
        0
      );
  }


  /* POSITION */

  if (
    isAdd ||
    hasOwn(
      body,
      "position"
    ) ||
    hasOwn(
      body,
      "positionJson"
    ) ||
    hasOwn(
      body,
      "positionX"
    ) ||
    hasOwn(
      body,
      "positionY"
    ) ||
    hasOwn(
      body,
      "positionZ"
    )
  ) {

    applyPosition(
      item,
      body
    );
  }


  /* MAP */

  if (
    isAdd ||
    hasOwn(
      body,
      "mapPosition"
    ) ||
    hasOwn(
      body,
      "mapPositionJson"
    ) ||
    hasOwn(
      body,
      "mapX"
    ) ||
    hasOwn(
      body,
      "mapY"
    )
  ) {

    applyMapPosition(
      item,
      body
    );
  }


  /* HOTSPOTS */

  if (
    isAdd ||
    hasOwn(
      body,
      "hotspots"
    ) ||
    hasOwn(
      body,
      "hotspotsJson"
    ) ||
    hasOwn(
      body,
      "hotspotData"
    )
  ) {

    item.hotspots =
      parseHotspots(
        body,
        item.hotspots ||
          [],
        totalLength,
        currentIndex
      );
  }


  /* THUMBNAIL */

  if (
    isAdd ||
    hasOwn(
      body,
      "thumbnail"
    )
  ) {

    const thumbnail =
      normalizeString(
        body.thumbnail ||
          "",
        2000
      );


    if (
      thumbnail &&
      isAllowedGalleryReference(
        thumbnail
      )
    ) {

      item.thumbnail =
        thumbnail;

    } else if (
      isAdd
    ) {

      item.thumbnail =
        item.image ||
        "";
    }
  }


  /* LEGACY NAVIGATION */

  applyNavigationFields(
    item,
    body,
    totalLength,
    currentIndex
  );
}


/* ============================================================
   DELETE REMAPPING
============================================================ */

function remapNavigationAfterDelete(
  galleryImages,
  deletedIndex,
  deletedSceneId = null
) {

  galleryImages.forEach(
    (
      item
    ) => {

      [
        "left",
        "right",
        "forward",
        "backward",
      ].forEach(
        (
          direction
        ) => {

          const current =
            parseDirectionValue(
              item[
                direction
              ]
            );


          if (
            current ===
            null
          ) {

            item[
              direction
            ] =
              null;

            return;
          }


          if (
            current ===
            deletedIndex
          ) {

            item[
              direction
            ] =
              null;

            return;
          }


          item[
            direction
          ] =
            current >
            deletedIndex
              ? current -
                1
              : current;
        }
      );


      if (
        !Array.isArray(
          item.hotspots
        )
      ) {

        return;
      }


      item.hotspots.forEach(
        (
          hotspot
        ) => {

          if (
            !hotspot ||
            typeof hotspot !==
              "object"
          ) {

            return;
          }


          const indexTarget =
            parseInteger(
              hotspot.targetIndex,
              null
            );


          let target =
            hotspot.target;


          if (
            typeof target ===
              "string" &&
            /^-?\d+$/.test(
              target.trim()
            )
          ) {

            target =
              Number(
                target.trim()
              );
          }


          const numericTarget =
            Number.isInteger(
              target
            )
              ? target
              : null;


          const effectiveTarget =
            indexTarget !==
              null
              ? indexTarget
              : numericTarget;


          if (
            deletedSceneId &&
            String(
              hotspot.targetSceneId ||
                ""
            ) ===
              String(
                deletedSceneId
              )
          ) {

            hotspot.target =
              null;

            hotspot.targetSceneId =
              null;

            hotspot.targetIndex =
              null;

            return;
          }


          if (
            effectiveTarget ===
            deletedIndex
          ) {

            hotspot.target =
              null;

            hotspot.targetSceneId =
              null;

            hotspot.targetIndex =
              null;

            return;
          }


          if (
            effectiveTarget !==
              null &&
            effectiveTarget >
              deletedIndex
          ) {

            const nextTarget =
              effectiveTarget -
              1;


            if (
              indexTarget !==
                null
            ) {

              hotspot.targetIndex =
                nextTarget;
            }


            if (
              numericTarget !==
                null
            ) {

              hotspot.target =
                nextTarget;
            }
          }
        }
      );
    }
  );
}


/* ============================================================
   AUTO CONNECT NEW LOCATION
============================================================ */

function setAutomaticNeighborConnection(
  galleryImages,
  previousIndex,
  newIndex
) {

  if (
    previousIndex <
      0 ||
    newIndex <
      0 ||
    newIndex >=
      galleryImages.length
  ) {

    return;
  }


  galleryImages[
    previousIndex
  ].right =
    newIndex;


  galleryImages[
    newIndex
  ].left =
    previousIndex;
}


/* ============================================================
   LOAD GALLERY
============================================================ */

async function getGalleryForEditor() {

  const gallery =
    await Gallery.getOrCreateDefault();


  const sorted =
    normalizeGalleryOrder(
      gallery.images ||
        []
    );


  gallery.images =
    sorted;


  return {
    gallery,

    galleryImages:
      sorted,
  };
}


/* ============================================================
   APPLY GALLERY SETTINGS
============================================================ */

function applyGallerySettings(
  gallery,
  body
) {

  const parsedSettings =
    parseJson(
      body.settings ||
        body.settingsJson,
      null
    );


  const source =
    parsedSettings &&
    typeof parsedSettings ===
      "object"
      ? {
          ...body,
          ...parsedSettings,
        }
      : body;


  gallery.tour =
    gallery.tour ||
    {};


  gallery.viewer =
    gallery.viewer ||
    {};


  gallery.map =
    gallery.map ||
    {};


  /* TOUR */

  if (
    hasOwn(
      source,
      "tourEnabled"
    ) ||
    hasOwn(
      source,
      "tour_enabled"
    )
  ) {

    gallery.tour.enabled =
      normalizeBoolean(
        source.tourEnabled ??
          source.tour_enabled,
        true
      );
  }


  if (
    hasOwn(
      source,
      "startScene"
    )
  ) {

    gallery.tour.startScene =
      Math.max(
        0,
        parseInteger(
          source.startScene,
          0
        )
      );
  }


  [
    "preloadNeighbors",
    "allowSharing",
    "showMap",
    "showHotspots",
  ].forEach(
    (
      key
    ) => {

      if (
        hasOwn(
          source,
          key
        )
      ) {

        gallery.tour[
          key
        ] =
          normalizeBoolean(
            source[
              key
            ],
            true
          );
      }
    }
  );


  if (
    hasOwn(
      source,
      "preloadDepth"
    )
  ) {

    gallery.tour.preloadDepth =
      clamp(
        source.preloadDepth,
        1,
        4,
        2
      );
  }


  /* VIEWER */

  [
    "defaultFov",
    "minFov",
    "maxFov",
  ].forEach(
    (
      key
    ) => {

      if (
        !hasOwn(
          source,
          key
        )
      ) {

        return;
      }


      const limits = {
        defaultFov: [
          MIN_FOV,
          MAX_FOV,
          75,
        ],

        minFov: [
          20,
          90,
          MIN_FOV,
        ],

        maxFov: [
          60,
          140,
          MAX_FOV,
        ],
      }[
        key
      ];


      gallery.viewer[
        key
      ] =
        clamp(
          source[
            key
          ],
          limits[0],
          limits[1],
          limits[2]
        );
    }
  );


  [
    "motionEnabled",
    "touchEnabled",
    "mouseEnabled",
  ].forEach(
    (
      key
    ) => {

      if (
        hasOwn(
          source,
          key
        )
      ) {

        gallery.viewer[
          key
        ] =
          normalizeBoolean(
            source[
              key
            ],
            true
          );
      }
    }
  );


  /* MAP */

  if (
    hasOwn(
      source,
      "mapEnabled"
    )
  ) {

    gallery.map.enabled =
      normalizeBoolean(
        source.mapEnabled,
        true
      );
  }


  if (
    hasOwn(
      source,
      "mapImage"
    )
  ) {

    const mapImage =
      normalizeString(
        source.mapImage,
        2000
      );


    if (
      !mapImage ||
      isAllowedGalleryReference(
        mapImage
      )
    ) {

      gallery.map.image =
        mapImage;
    }
  }


  if (
    hasOwn(
      source,
      "mapTitle"
    )
  ) {

    gallery.map.title =
      normalizeString(
        source.mapTitle,
        150
      ) ||
      "Puffer Isle Resort";
  }


  if (
    hasOwn(
      source,
      "mapWidth"
    )
  ) {

    gallery.map.width =
      Math.max(
        1,
        parseNumber(
          source.mapWidth,
          1000
        )
      );
  }


  if (
    hasOwn(
      source,
      "mapHeight"
    )
  ) {

    gallery.map.height =
      Math.max(
        1,
        parseNumber(
          source.mapHeight,
          700
        )
      );
  }


  gallery.formatVersion =
    Math.max(
      2,
      parseInteger(
        gallery.formatVersion,
        2
      )
    );
}


/* ============================================================
   UPLOAD MIDDLEWARE
============================================================ */

function galleryUploadMiddleware(
  req,
  res,
  next
) {

  galleryUpload.single(
    "imageFile"
  )(
    req,
    res,
    (
      error
    ) => {

      if (!error) {

        return next();
      }


      console.error(
        `[GALLERY UPLOAD ERROR] requestId=${
          getRequestId(req) ||
          "none"
        }`,
        error.stack ||
          error.message ||
          error
      );


      if (
        error instanceof
        multer.MulterError
      ) {

        if (
          error.code ===
          "LIMIT_FILE_SIZE"
        ) {

          return redirectGalleryError(
            res,
            "The selected 360° image is larger than 25 MB."
          );
        }


        return redirectGalleryError(
          res,
          "Unable to process the uploaded gallery image."
        );
      }


      return redirectGalleryError(
        res,
        error.message ||
          "Unable to process the uploaded gallery image."
      );
    }
  );
}


/* ============================================================
   EDITOR PAGE
============================================================ */

router.get(
  "/gallery-editor",

  requireGalleryAdmin,

  async (
    req,
    res
  ) => {

    try {

      const {
        gallery,
        galleryImages,
      } =
        await getGalleryForEditor();


      if (
        gallery.isModified()
      ) {

        await gallery.save();
      }


      return res.render(
        "admin/gallery-editor",
        {
          title:
            "Street View Editor | IsleRMS",

          admin:
            getAdminSession(
              req
            ),

          gallery:
            gallery.toObject(),

          galleryImages:
            galleryImages.map(
              galleryItemToPlain
            ),

          success:
            normalizeString(
              req.query?.success,
              300
            ) ||
            null,

          error:
            normalizeString(
              req.query?.error,
              500
            ) ||
            null,

          csrfToken:
            res.locals?.csrfToken ||
            req.session?.csrfToken ||
            null,
        }
      );

    } catch (error) {

      console.error(
        `[GALLERY EDITOR ERROR] requestId=${
          getRequestId(req) ||
          "none"
        }`,
        error.stack ||
          error.message ||
          error
      );


      return res
        .status(500)
        .render(
          "error",
          {
            title:
              "Gallery Editor Error",

            statusCode:
              500,

            error:
              "Unable to load the 360° gallery editor.",
          }
        );
    }
  }
);


/* ============================================================
   SAVE / CREATE / EDIT / SETTINGS
============================================================ */

async function saveGalleryLocation(
  req,
  res
) {

  let savedFile =
    null;


  try {

    const body =
      req.body ||
      {};


    const {
      gallery,
      galleryImages,
    } =
      await getGalleryForEditor();


    const requestedAction =
      normalizeString(
        body.action ||
          "",
        50
      ).toLowerCase();


    /* ========================================================
       SETTINGS
    ======================================================== */

    if (
      requestedAction ===
        "settings" ||
      requestedAction ===
        "save-settings" ||
      requestedAction ===
        "update-settings"
    ) {

      applyGallerySettings(
        gallery,
        body
      );


      const sceneCount =
        galleryImages.length;


      gallery.tour =
        gallery.tour ||
        {};


      gallery.tour.startScene =
        sceneCount >
          0
          ? Math.min(
              Math.max(
                0,
                parseInteger(
                  gallery.tour.startScene,
                  0
                )
              ),
              sceneCount -
                1
            )
          : 0;


      gallery.viewer =
        gallery.viewer ||
        {};


      const minFov =
        clamp(
          gallery.viewer.minFov,
          20,
          90,
          MIN_FOV
        );


      const maxFov =
        clamp(
          gallery.viewer.maxFov,
          60,
          140,
          MAX_FOV
        );


      gallery.viewer.minFov =
        Math.min(
          minFov,
          maxFov -
            1
        );


      gallery.viewer.maxFov =
        Math.max(
          maxFov,
          gallery.viewer.minFov +
            1
        );


      gallery.viewer.defaultFov =
        Math.min(
          gallery.viewer.maxFov,

          Math.max(
            gallery.viewer.minFov,

            clamp(
              gallery.viewer.defaultFov,
              MIN_FOV,
              MAX_FOV,
              75
            )
          )
        );


      await gallery.save();


      logGalleryAdminAction(
        req,
        "gallery-settings-update",
        {
          startScene:
            gallery.tour.startScene,

          showMap:
            gallery.tour.showMap,

          showHotspots:
            gallery.tour.showHotspots,
        }
      );


      return redirectGallerySuccess(
        res,
        "Gallery experience settings saved."
      );
    }


    const targetIndex =
      getGalleryTargetIndex(
        galleryImages,
        body
      );


    const action =
      requestedAction ||
      (
        targetIndex >=
          0
          ? "edit"
          : "add"
      );


    /* ========================================================
       DELETE
    ======================================================== */

    if (
      action ===
        "delete" ||
      action ===
        "remove"
    ) {

      return deleteGalleryLocation(
        req,
        res,
        gallery,
        galleryImages,
        targetIndex
      );
    }


    /* ========================================================
       ADD
    ======================================================== */

    if (
      action ===
        "add" ||
      action ===
        "create"
    ) {

      const title =
        normalizeTitle(
          body.title
        );


      let imageUrl =
        normalizeString(
          body.image ||
            "",
          1000
        );


      /* Upload */

      if (
        req.file
      ) {

        const detected =
          detectGalleryImageType(
            req.file.buffer
          );


        if (
          !detected
        ) {

          return redirectGalleryError(
            res,
            "The uploaded file is not a valid JPG, PNG, or WEBP image."
          );
        }


        const actualMimetype =
          String(
            req.file.mimetype ||
              ""
          )
            .trim()
            .toLowerCase();


        if (
          detected.contentType !==
          actualMimetype
        ) {

          return redirectGalleryError(
            res,
            "The uploaded image type does not match its file contents."
          );
        }


        savedFile =
          await saveGalleryImageBuffer(
            req.file.buffer,
            detected
          );


        imageUrl =
          savedFile.url;
      }


      /* Validate */

      if (
        !imageUrl ||
        !isAllowedGalleryReference(
          imageUrl
        )
      ) {

        await cleanupSavedFile(
          savedFile
        );


        savedFile =
          null;


        return redirectGalleryError(
          res,
          "Please provide a valid 360° gallery image."
        );
      }


      const newIndex =
        galleryImages.length;


      const newItem =
        {
          title,

          image:
            imageUrl,

          thumbnail:
            imageUrl,

          order:
            newIndex +
            1,

          left:
            null,

          right:
            null,

          forward:
            null,

          backward:
            null,

          heading:
            0,

          pitch:
            0,

          fov:
            75,

          northOffset:
            0,

          position:
            {
              x:
                null,

              y:
                null,

              z:
                null,
            },

          mapPosition:
            {
              x:
                null,

              y:
                null,
            },

          slug:
            normalizeSlug(
              body.slug,
              title
            ),

          description:
            "",

          caption:
            "",

          alt:
            title,

          category:
            "Resort",

          location:
            "",

          tags:
            [],

          projection:
            "equirectangular",

          active:
            true,

          featured:
            false,

          hotspots:
            [],
        };


      galleryImages.push(
        newItem
      );


      /* Automatic linear connection */

      if (
        newIndex >
        0
      ) {

        setAutomaticNeighborConnection(
          galleryImages,
          newIndex -
            1,
          newIndex
        );
      }


      applySceneMetadata(
        newItem,
        body,
        "add",
        newIndex,
        galleryImages.length
      );


      gallery.images =
        normalizeGalleryOrder(
          galleryImages
        );


      gallery.formatVersion =
        Math.max(
          2,
          parseInteger(
            gallery.formatVersion,
            2
          )
        );


      await gallery.save();


      savedFile =
        null;


      logGalleryAdminAction(
        req,
        "gallery-create",
        {
          title:
            newItem.title,

          image:
            newItem.image,

          slug:
            newItem.slug,
        }
      );


      return redirectGallerySuccess(
        res,
        "Gallery location added successfully."
      );
    }


    /* ========================================================
       EDIT
    ======================================================== */

    if (
      action ===
        "edit" ||
      action ===
        "update"
    ) {

      if (
        targetIndex <
        0
      ) {

        return redirectGalleryError(
          res,
          "The gallery location could not be found."
        );
      }


      const target =
        galleryImages[
          targetIndex
        ];


      const oldImage =
        String(
          target?.image ||
            ""
        ).trim();


      applySceneMetadata(
        target,
        body,
        "edit",
        targetIndex,
        galleryImages.length
      );


      /* Replace image */

      if (
        req.file
      ) {

        const detected =
          detectGalleryImageType(
            req.file.buffer
          );


        if (
          !detected
        ) {

          return redirectGalleryError(
            res,
            "The uploaded file is not a valid JPG, PNG, or WEBP image."
          );
        }


        const actualMimetype =
          String(
            req.file.mimetype ||
              ""
          )
            .trim()
            .toLowerCase();


        if (
          detected.contentType !==
          actualMimetype
        ) {

          return redirectGalleryError(
            res,
            "The uploaded image type does not match its file contents."
          );
        }


        savedFile =
          await saveGalleryImageBuffer(
            req.file.buffer,
            detected
          );


        target.image =
          savedFile.url;


        if (
          !hasOwn(
            body,
            "thumbnail"
          ) ||
          !normalizeString(
            body.thumbnail,
            2000
          )
        ) {

          target.thumbnail =
            savedFile.url;
        }
      }


      /* Optional image reference */

      else if (
        hasOwn(
          body,
          "image"
        )
      ) {

        const requestedImage =
          normalizeString(
            body.image,
            1000
          );


        if (
          requestedImage &&
          isAllowedGalleryReference(
            requestedImage
          )
        ) {

          target.image =
            requestedImage;
        }
      }


      /* Final validation */

      if (
        !target.image ||
        !isAllowedGalleryReference(
          target.image
        )
      ) {

        await cleanupSavedFile(
          savedFile
        );


        savedFile =
          null;


        return redirectGalleryError(
          res,
          "The gallery image is invalid."
        );
      }


      if (
        target.thumbnail &&
        !isAllowedGalleryReference(
          target.thumbnail
        )
      ) {

        target.thumbnail =
          target.image;
      }


      if (
        !target.thumbnail
      ) {

        target.thumbnail =
          target.image;
      }


      gallery.images =
        normalizeGalleryOrder(
          galleryImages
        );


      gallery.formatVersion =
        Math.max(
          2,
          parseInteger(
            gallery.formatVersion,
            2
          )
        );


      await gallery.save();


      savedFile =
        null;


      /* Delete old managed upload after successful save */

      if (
        oldImage &&
        oldImage !==
          target.image
      ) {

        await removeManagedGalleryImage(
          oldImage
        );
      }


      logGalleryAdminAction(
        req,
        "gallery-update",
        {
          imageId:
            target?._id ||
            "unknown",

          title:
            target.title,

          image:
            target.image,

          slug:
            target.slug ||
            "",
        }
      );


      return redirectGallerySuccess(
        res,
        "Gallery location saved."
      );
    }


    return redirectGalleryError(
      res,
      "Unsupported gallery action."
    );

  } catch (error) {

    await cleanupSavedFile(
      savedFile
    );


    console.error(
      `[GALLERY SAVE ERROR] requestId=${
        getRequestId(req) ||
        "none"
      }`,
      error.stack ||
        error.message ||
        error
    );


    if (
      error?.name ===
      "ValidationError"
    ) {

      const message =
        Object.values(
          error.errors ||
            {}
        )
          .map(
            (
              entry
            ) =>
              entry.message
          )
          .filter(Boolean)
          .join(
            " "
          );


      return redirectGalleryError(
        res,
        message ||
          "The gallery information is invalid."
      );
    }


    return redirectGalleryError(
      res,
      "Unable to save the gallery location."
    );
  }
}


/* ============================================================
   MAIN POST
============================================================ */

router.post(
  "/gallery-editor",

  requireGalleryMutation,

  galleryUploadMiddleware,

  saveGalleryLocation
);


/* ============================================================
   DELETE ENDPOINT
============================================================ */

router.post(
  "/gallery-editor/delete",

  requireGalleryMutation,

  async (
    req,
    res
  ) => {

    try {

      const gallery =
        await Gallery.getOrCreateDefault();


      const galleryImages =
        normalizeGalleryOrder(
          gallery.images ||
            []
        );


      const targetIndex =
        getGalleryTargetIndex(
          galleryImages,
          req.body ||
            {}
        );


      return deleteGalleryLocation(
        req,
        res,
        gallery,
        galleryImages,
        targetIndex
      );

    } catch (error) {

      console.error(
        `[GALLERY DELETE ERROR] requestId=${
          getRequestId(req) ||
          "none"
        }`,
        error.stack ||
          error.message ||
          error
      );


      return redirectGalleryError(
        res,
        "Unable to delete the gallery location."
      );
    }
  }
);


/* ============================================================
   DELETE HELPER
============================================================ */

async function deleteGalleryLocation(
  req,
  res,
  gallery,
  galleryImages,
  targetIndex
) {

  if (
    targetIndex <
    0
  ) {

    return redirectGalleryError(
      res,
      "The gallery location could not be found."
    );
  }


  const target =
    galleryImages[
      targetIndex
    ];


  const oldImage =
    String(
      target?.image ||
        ""
    ).trim();


  const deletedSceneId =
    target?._id
      ? String(
          target._id
        )
      : null;


  galleryImages.splice(
    targetIndex,
    1
  );


  remapNavigationAfterDelete(
    galleryImages,
    targetIndex,
    deletedSceneId
  );


  gallery.images =
    normalizeGalleryOrder(
      galleryImages
    );


  gallery.tour =
    gallery.tour ||
    {};


  const currentStartScene =
    parseInteger(
      gallery.tour.startScene,
      0
    );


  if (
    gallery.images.length ===
    0
  ) {

    gallery.tour.startScene =
      0;

  } else if (
    currentStartScene ===
    targetIndex
  ) {

    gallery.tour.startScene =
      Math.min(
        targetIndex,
        gallery.images.length -
          1
      );

  } else if (
    currentStartScene >
    targetIndex
  ) {

    gallery.tour.startScene =
      currentStartScene -
      1;
  }


  gallery.formatVersion =
    Math.max(
      2,
      parseInteger(
        gallery.formatVersion,
        2
      )
    );


  await gallery.save();


  if (
    oldImage
  ) {

    await removeManagedGalleryImage(
      oldImage
    );
  }


  logGalleryAdminAction(
    req,
    "gallery-delete",
    {
      imageId:
        target?._id ||
        "unknown",

      title:
        target?.title ||
        "Resort Photo",
    }
  );


  return redirectGallerySuccess(
    res,
    "Gallery location deleted."
  );
}


/* ============================================================
   ADMIN GALLERY DATA API
============================================================ */

router.get(
  "/api/gallery",

  requireGalleryAdmin,

  async (
    req,
    res
  ) => {

    try {

      const gallery =
        await Gallery.getOrCreateDefault();


      const galleryImages =
        normalizeGalleryOrder(
          gallery.images ||
            []
        )
          .map(
            galleryItemToPlain
          );


      const publicData =
        typeof gallery.toPublicData ===
          "function"
          ? gallery.toPublicData()
          : null;


      return res.json(
        {
          success:
            true,

          galleryImages,

          settings:
            {
              tour:
                gallery.tour ||
                {},

              viewer:
                gallery.viewer ||
                {},

              map:
                gallery.map ||
                {},

              formatVersion:
                gallery.formatVersion ||
                2,
            },

          publicData,
        }
      );

    } catch (error) {

      console.error(
        `[ADMIN GALLERY API ERROR] requestId=${
          getRequestId(req) ||
          "none"
        }`,
        error.stack ||
          error.message ||
          error
      );


      return res
        .status(500)
        .json(
          {
            success:
              false,

            message:
              "Unable to load gallery data.",
          }
        );
    }
  }
);


/* ============================================================
   RESPONSE HELPERS
============================================================ */

function redirectGallerySuccess(
  res,
  message
) {

  return res.redirect(
    "/admin/gallery-editor?success=" +
      encodeURIComponent(
        message
      )
  );
}


function redirectGalleryError(
  res,
  message
) {

  return res.redirect(
    "/admin/gallery-editor?error=" +
      encodeURIComponent(
        message
      )
  );
}


/* ============================================================
   CLEANUP
============================================================ */

async function cleanupSavedFile(
  savedFile
) {

  if (
    savedFile?.url
  ) {

    await removeManagedGalleryImage(
      savedFile.url
    );
  }
}


/* ============================================================
   EXPORT
============================================================ */

module.exports =
  router;