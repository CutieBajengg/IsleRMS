"use strict";

/**
 * ============================================================
 * PUFFER ISLE RESORT | IsleRMS
 * routes/galleryRoutes.js
 *
 * ADMIN GALLERY MANAGEMENT
 *
 * Handles:
 * - View gallery editor
 * - Add 360° locations
 * - Edit 360° locations
 * - Replace gallery images
 * - Delete gallery locations
 * - Configure left/right/forward/backward navigation
 * - Maintain navigation indexes after deletion
 * - Remove old managed upload files safely
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


/* ============================================================
   FILE SYSTEM INITIALIZATION
============================================================ */

try {

  fs.mkdirSync(
    GALLERY_UPLOAD_DIR,
    {
      recursive: true,
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
        ([key, value]) =>
          `${key}=${String(
            value
          ).replace(
            /[\r\n]+/g,
            " "
          )}`
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


  if (
    !admin ||
    !adminId
  ) {

    return false;
  }


  return mongoose.Types.ObjectId.isValid(
    String(
      adminId
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
   IMAGE TYPE DETECTION
============================================================ */

function detectGalleryImageType(
  buffer
) {

  if (
    !Buffer.isBuffer(
      buffer
    ) ||
    buffer.length < 12
  ) {

    return null;
  }


  /* ----------------------------------------------------------
     JPEG
  ---------------------------------------------------------- */

  if (
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {

    return {
      extension:
        "jpg",

      contentType:
        "image/jpeg",
    };
  }


  /* ----------------------------------------------------------
     PNG
  ---------------------------------------------------------- */

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


  /* ----------------------------------------------------------
     WEBP
  ---------------------------------------------------------- */

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


/* ============================================================
   MANAGED IMAGE PATH CHECK
============================================================ */

function isManagedGalleryImageUrl(
  value
) {

  const normalized =
    normalizeString(
      value,
      1000
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


/* ============================================================
   IMAGE ABSOLUTE PATH
============================================================ */

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


/* ============================================================
   REMOVE MANAGED IMAGE
============================================================ */

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


/* ============================================================
   IMAGE FILE NAME
============================================================ */

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


/* ============================================================
   SAVE IMAGE BUFFER
============================================================ */

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
      // Best-effort cleanup.
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


/* ============================================================
   SORT GALLERY
============================================================ */

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


/* ============================================================
   NORMALIZE ORDER
============================================================ */

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
   DIRECTION PARSING
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


/* ============================================================
   DIRECTION VALIDATION
============================================================ */

function sanitizeDirectionValue(
  value,
  totalLength,
  selfIndex = -1
) {

  const parsed =
    parseDirectionValue(
      value
    );


  if (
    parsed === null
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


/* ============================================================
   TARGET LOCATION
============================================================ */

function getGalleryTargetIndex(
  galleryImages,
  body = {}
) {

  /* ----------------------------------------------------------
     MongoDB ID
  ---------------------------------------------------------- */

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
      index >=
      0
    ) {

      return index;
    }
  }


  /* ----------------------------------------------------------
     IMAGE PATH
  ---------------------------------------------------------- */

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
      index >=
      0
    ) {

      return index;
    }
  }


  /* ----------------------------------------------------------
     ARRAY INDEX
  ---------------------------------------------------------- */

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
      index >=
        0 &&
      index <
        galleryImages.length
    ) {

      return index;
    }
  }


  return -1;
}


/* ============================================================
   ALLOWED GALLERY REFERENCES
============================================================ */

function isAllowedGalleryReference(
  value
) {

  const image =
    normalizeString(
      value,
      1000
    );


  if (!image) {

    return false;
  }


  /*
   * Existing bundled resort images.
   */

  if (
    image.startsWith(
      "/images/"
    )
  ) {

    return true;
  }


  /*
   * Images uploaded by Gallery.js.
   */

  if (
    image.startsWith(
      GALLERY_PUBLIC_PREFIX
    )
  ) {

    return true;
  }


  return false;
}


/* ============================================================
   APPLY NAVIGATION
============================================================ */

function applyNavigationFields(
  item,
  body,
  totalLength,
  currentIndex
) {

  const directions = [
    "left",
    "right",
    "forward",
    "backward",
  ];


  directions.forEach(
    (
      direction
    ) => {

      if (
        Object.prototype.hasOwnProperty.call(
          body ||
            {},
          direction
        )
      ) {

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
    }
  );
}


/* ============================================================
   REMAP NAVIGATION AFTER DELETE
============================================================ */

function remapNavigationAfterDelete(
  galleryImages,
  deletedIndex
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


      /*
       * Save normalized ordering only when Mongoose
       * reports actual changes.
       */

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
   SAVE / CREATE / EDIT / DELETE
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


    const mutableGallery =
      galleryImages;


    const requestedAction =
      normalizeString(
        body.action ||
          "",
        30
      ).toLowerCase();


    const targetIndex =
      getGalleryTargetIndex(
        mutableGallery,
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
        mutableGallery,
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


      /* ------------------------------------------------------
         Uploaded image
      ------------------------------------------------------ */

      if (
        req.file
      ) {

        const detected =
          detectGalleryImageType(
            req.file.buffer
          );


        if (!detected) {

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


      /* ------------------------------------------------------
         Validate image
      ------------------------------------------------------ */

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


      /* ------------------------------------------------------
         Create image
      ------------------------------------------------------ */

      const newIndex =
        mutableGallery.length;


      const newItem =
        {
          title,

          image:
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
        };


      mutableGallery.push(
        newItem
      );


      /* ------------------------------------------------------
         Automatically connect to previous location
      ------------------------------------------------------ */

      if (
        newIndex >
        0
      ) {

        setAutomaticNeighborConnection(
          mutableGallery,
          newIndex -
            1,
          newIndex
        );
      }


      /* ------------------------------------------------------
         Explicit navigation values
      ------------------------------------------------------ */

      applyNavigationFields(
        newItem,
        body,
        mutableGallery.length,
        newIndex
      );


      gallery.images =
        normalizeGalleryOrder(
          mutableGallery
        );


      await gallery.save();


      savedFile =
        null;


      logGalleryAdminAction(
        req,
        "gallery-create",
        {
          title,

          image:
            imageUrl,
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
        mutableGallery[
          targetIndex
        ];


      const oldImage =
        String(
          target?.image ||
            ""
        ).trim();


      target.title =
        normalizeTitle(
          body.title
        );


      /* ------------------------------------------------------
         Replace uploaded image
      ------------------------------------------------------ */

      if (
        req.file
      ) {

        const detected =
          detectGalleryImageType(
            req.file.buffer
          );


        if (!detected) {

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


      } else if (
        Object.prototype.hasOwnProperty.call(
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


      /* ------------------------------------------------------
         Final image validation
      ------------------------------------------------------ */

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


      /* ------------------------------------------------------
         Navigation
      ------------------------------------------------------ */

      applyNavigationFields(
        target,
        body,
        mutableGallery.length,
        targetIndex
      );


      gallery.images =
        normalizeGalleryOrder(
          mutableGallery
        );


      await gallery.save();


      /*
       * Database save succeeded.
       * The new image is now active.
       */

      savedFile =
        null;


      /*
       * Remove old managed image.
       */

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
        }
      );


      return redirectGallerySuccess(
        res,
        "Gallery location saved."
      );
    }


    /* ========================================================
       UNSUPPORTED
    ======================================================== */

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


  /*
   * Remove selected location.
   */

  galleryImages.splice(
    targetIndex,
    1
  );


  /*
   * Repair every navigation reference.
   */

  remapNavigationAfterDelete(
    galleryImages,
    targetIndex
  );


  /*
   * Rebuild order.
   */

  gallery.images =
    normalizeGalleryOrder(
      galleryImages
    );


  /*
   * Save database first.
   */

  await gallery.save();


  /*
   * Then remove old managed file.
   */

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
   POST /admin/gallery-editor
============================================================ */

router.post(
  "/gallery-editor",

  requireGalleryMutation,

  galleryUploadMiddleware,

  saveGalleryLocation
);


/* ============================================================
   POST /admin/gallery-editor/delete
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


      return res.json(
        {
          success:
            true,

          galleryImages,
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