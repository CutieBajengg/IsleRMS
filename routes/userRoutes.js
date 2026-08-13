// routes/userRoutes.js
/**
 * Isle RMS | User Routes
 * Handles profile, appointments, notifications, and real-time updates
 * Author: Isle RMS Dev Team
 */

const express = require("express");
const router = express.Router();
const Appointment = require("../models/Appointment"); // Appointment model
const User = require("../models/User");
const Notification = require("../models/Notification");

// -------------------------------
// Middleware: Require Login
// -------------------------------
function requireLogin(req, res, next) {
  if (!req.session?.userId) {
    return res.redirect("/"); // Redirect to home or show login modal
  }
  next();
}

// -------------------------------
// 0️⃣ Booking Page (Accessible only if logged in)
// -------------------------------
router.get("/booking", async (req, res) => {
  try {
    const userId = req.session?.userId;

    if (!userId) {
      // User not logged in → redirect to home (modal will trigger from navbar)
      return res.redirect("/");
    }

    // Fetch user data
    const user = await User.findById(userId).lean();
    if (!user) {
      return res.redirect("/"); // fallback
    }

    // Fetch user's appointments
    const appointments = await Appointment.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    res.render("appointments", {
      title: "My Bookings | Isle RMS",
      user,
      appointments,
    });
  } catch (error) {
    console.error("❌ Error loading booking page:", error);
    res.status(500).render("error", {
      message: "Failed to load your bookings.",
    });
  }
});

// -------------------------------
// 1️⃣ View User Profile Page
// -------------------------------
router.get("/profile/:id", requireLogin, async (req, res) => {
  try {
    const userId = req.params.id;

    // Make sure the logged-in user can only see their own profile
    if (req.session.userId !== userId) {
      return res.status(403).render("error", { message: "Unauthorized access." });
    }

    const user = await User.findById(userId).lean();
    if (!user) {
      return res.status(404).render("error", { message: "User not found." });
    }

    const appointments = await Appointment.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    res.render("profile", {
      title: `${user.fullname} | Isle RMS Profile`,
      user,
      appointments,
      notifications,
    });
  } catch (error) {
    console.error("❌ Error loading user profile:", error);
    res.status(500).render("error", {
      message: "An error occurred while loading your profile.",
    });
  }
});

// -------------------------------
// 2️⃣ Submit Appointment (User Form)
// -------------------------------
router.post("/appointment/submit", requireLogin, async (req, res) => {
  try {
    const { room, checkin, checkout, guests, contact, specialRequests } = req.body;
    const userId = req.session.userId;

    if (!room || !checkin || !checkout || !guests) {
      return res.status(400).send("❌ Missing appointment details.");
    }

    const newAppointment = new Appointment({
      userId,
      room,
      checkin,
      checkout,
      guests,
      contact,
      specialRequests,
    });

    await newAppointment.save();

    // Notify user
    await Notification.create({
      userId,
      message: `Your appointment request for ${room} has been submitted and is pending confirmation.`,
      type: "booking",
    });

    console.log("✅ Appointment created and notification sent:", newAppointment);
    res.redirect("/booking");
  } catch (error) {
    console.error("❌ Error submitting appointment:", error);
    res.status(500).render("error", {
      message: "Failed to submit appointment. Please try again later.",
    });
  }
});

// -------------------------------
// 3️⃣ Polling Route: Real-time Updates
// -------------------------------
router.get("/userUpdates/:userId", requireLogin, async (req, res) => {
  try {
    const { userId } = req.params;

    // Ensure user can only access their own updates
    if (req.session.userId !== userId) {
      return res.status(403).json({ success: false, error: "Unauthorized access." });
    }

    const appointments = await Appointment.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      appointments,
      notifications,
    });
  } catch (err) {
    console.error("❌ Error in userUpdates polling:", err);
    res.status(500).json({ success: false, error: "Failed to fetch user updates." });
  }
});

// -------------------------------
// 4️⃣ Cancel Appointment
// -------------------------------
router.post("/appointment/cancel/:appointmentId", requireLogin, async (req, res) => {
  try {
    const appointmentId = req.params.appointmentId;
    const appointment = await Appointment.findById(appointmentId);

    if (!appointment) {
      return res.status(404).json({ success: false, message: "Appointment not found." });
    }

    // Ensure only the owner can cancel
    if (appointment.userId.toString() !== req.session.userId) {
      return res.status(403).json({ success: false, message: "Unauthorized action." });
    }

    await Appointment.findByIdAndDelete(appointmentId);

    // Notify user
    await Notification.create({
      userId: appointment.userId,
      message: `Your appointment for ${appointment.room} has been successfully cancelled.`,
      type: "booking",
    });

    res.json({ success: true, message: "Appointment cancelled successfully." });
  } catch (error) {
    console.error("❌ Error cancelling appointment:", error);
    res.status(500).json({ success: false, message: "Failed to cancel appointment." });
  }
});

module.exports = router;