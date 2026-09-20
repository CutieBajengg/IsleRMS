"use strict";

require("dotenv").config();

const mongoose = require("mongoose");

const Room = require("../models/Room");
const AddOn = require("../models/AddOn");

const MONGO_URI =
  process.env.MONGO_URI ||
  process.env.MONGODB_URI ||
  "mongodb://127.0.0.1:27017/isleRMS";

async function seedCatalog() {
  try {
    console.log("🔌 Connecting to MongoDB...");

    await mongoose.connect(MONGO_URI);

    console.log(
      `✅ Connected to database: ${mongoose.connection.name}`
    );

    /*
     * ----------------------------------------------------------
     * INITIAL ROOMS
     * ----------------------------------------------------------
     *
     * These are seed values only.
     *
     * After they are inserted, the admin panel controls
     * the actual prices and availability.
     */

    const rooms = [
      {
        name: "Aircon Room",
        price: 3500,
        maxGuests: 8,
        quantity: 1,
        image: "/images/room1.jpg",
        description:
          "Comfortable air-conditioned room for larger groups.",
        active: true,
        sortOrder: 1,
      },

      {
        name: "Fan Room",
        price: 2500,
        maxGuests: 6,
        quantity: 1,
        image: "/images/room2.jpg",
        description:
          "Affordable fan-cooled accommodation.",
        active: true,
        sortOrder: 2,
      },
    ];

    /*
     * ----------------------------------------------------------
     * INITIAL ADD-ONS
     * ----------------------------------------------------------
     *
     * Seaside Cottage was previously charged per night,
     * so its new catalog pricing type is "perNight".
     */

    const addOns = [
      {
        name: "Seaside Cottage",
        price: 1200,
        pricingType: "perNight",
        image: "/images/cottage.jpg",
        description:
          "Optional seaside cottage add-on.",
        active: true,
        sortOrder: 1,
      },
    ];

    /*
     * ----------------------------------------------------------
     * SEED ROOMS
     * ----------------------------------------------------------
     */

    for (const roomData of rooms) {
      const existingRoom =
        await Room.findOne({
          name: roomData.name,
        });

      if (existingRoom) {
        console.log(
          `ℹ️ Room already exists: ${roomData.name}`
        );

        continue;
      }

      await Room.create(roomData);

      console.log(
        `✅ Room created: ${roomData.name}`
      );
    }

    /*
     * ----------------------------------------------------------
     * SEED ADD-ONS
     * ----------------------------------------------------------
     */

    for (const addOnData of addOns) {
      const existingAddOn =
        await AddOn.findOne({
          name: addOnData.name,
        });

      if (existingAddOn) {
        console.log(
          `ℹ️ Add-on already exists: ${addOnData.name}`
        );

        continue;
      }

      await AddOn.create(
        addOnData
      );

      console.log(
        `✅ Add-on created: ${addOnData.name}`
      );
    }

    console.log("");
    console.log(
      "=============================================="
    );
    console.log(
      "✅ CATALOG SEED COMPLETE"
    );
    console.log(
      "=============================================="
    );

    process.exit(0);
  } catch (error) {
    console.error("");
    console.error(
      "❌ CATALOG SEED FAILED"
    );
    console.error(
      "----------------------------------------------"
    );
    console.error(error);
    console.error(
      "----------------------------------------------"
    );

    process.exit(1);
  }
}

seedCatalog();