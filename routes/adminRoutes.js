// routes/adminRoutes.js
/**
 * Puffer Isle Resort | Admin Routes
 * Handles dashboard, analytics, history, user management, and appointment approvals
 * Author: Puffer Isle Resort Dev Team
 */

const express = require("express");
const router = express.Router();
const Appointment = require("../models/Appointment"); // renamed Booking -> Appointment
const Notification = require("../models/Notification");
const User = require("../models/User");
const Admin = require("../models/Admin");

// ----------------------------
// 🔒 Middleware: Protect admin routes
// ----------------------------
function requireAdmin(req, res, next) {
  if (!req.session.admin) return res.redirect("/admin/login");
  next();
}

// ----------------------------
// 🧠 ADMIN LOGIN PAGE
// ----------------------------
router.get("/login", async (req, res) => {
  if (req.session.admin) return res.redirect("/admin/dashboard");
  res.render("adminlog", { title: "Admin Login | Puffer Isle Resort", error: null });
});

// ----------------------------
// 🔐 ADMIN LOGIN HANDLER
// ----------------------------
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const admin = await Admin.findOne({ username });
    if (!admin || !(await admin.comparePassword(password))) {
      return res.render("adminlog", {
        title: "Admin Login | Puffer Isle Resort",
        error: "Invalid username or password",
      });
    }

    req.session.admin = { _id: admin._id, username: admin.username };
    req.session.message = { type: "success", text: "Welcome back, Admin!" };
    console.log("✅ Admin logged in:", admin.username);
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("❌ Admin login error:", err);
    res.render("adminlog", { title: "Admin Login | Puffer Isle Resort", error: "Something went wrong" });
  }
});

// ----------------------------
// 🚪 ADMIN LOGOUT
// ----------------------------
router.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

// ----------------------------
// 🏠 Redirect /admin → /admin/dashboard
// ----------------------------
router.get("/", (req, res) => res.redirect("/admin/dashboard"));

// ----------------------------
// 📊 DASHBOARD (Pending Appointments + Filters)
// ----------------------------
router.get("/dashboard", requireAdmin, async (req, res) => {
  try {
    const filter = req.query.filter || "all";
    const today = new Date();
    let dateQuery = {};

    if (filter === "week") {
      const start = new Date();
      start.setDate(today.getDate() - 7);
      dateQuery = { checkin: { $gte: start } };
    } else if (filter === "month") {
      const start = new Date(today.getFullYear(), today.getMonth(), 1);
      dateQuery = { checkin: { $gte: start } };
    }

    const appointments = await Appointment.find({ status: "pending", ...dateQuery })
      .sort({ checkin: 1 })
      .lean();

    // Dashboard metrics
    const totalAppointments = await Appointment.countDocuments();
    const acceptedCount = await Appointment.countDocuments({ status: "accepted" });
    const declinedCount = await Appointment.countDocuments({ status: "declined" });
    const pendingCount = await Appointment.countDocuments({ status: "pending" });

    const totalGuestsAgg = await Appointment.aggregate([{ $group: { _id: null, totalGuests: { $sum: "$guests" } } }]);
    const totalGuests = totalGuestsAgg[0]?.totalGuests || 0;

    const totalRevenueAgg = await Appointment.aggregate([
      { $match: { status: "accepted" } },
      { $group: { _id: null, totalRevenue: { $sum: "$totalPrice" } } },
    ]);
    const totalRevenue = totalRevenueAgg[0]?.totalRevenue || 0;

    res.render("admin", {
      title: "Dashboard | Puffer Isle Resort",
      admin: req.session.admin,
      appointments,
      filter,
      totalAppointments,
      acceptedCount,
      declinedCount,
      pendingCount,
      totalGuests,
      totalRevenue,
      message: req.session.message || null,
    });

    delete req.session.message;
  } catch (err) {
    console.error("❌ Error loading dashboard:", err);
    res.status(500).render("error", { title: "Error | Puffer Isle Resort", message: "Failed to load dashboard." });
  }
});

// ----------------------------
// 📈 ANALYTICS
// ----------------------------
router.get("/analytics", requireAdmin, (req, res) => {
  res.render("admin/analytics", { title: "Analytics | Puffer Isle Resort", admin: req.session.admin });
});

router.get("/analytics/data", requireAdmin, async (req, res) => {
  try {
    const { period } = req.query;
    const now = new Date();
    let startDate;

    if (period === "week") startDate = new Date(now.setDate(now.getDate() - 7));
    else if (period === "month") startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    else if (period === "year") startDate = new Date(now.getFullYear(), 0, 1);

    const dateFilter = startDate ? { checkin: { $gte: startDate } } : {};
    const appointments = await Appointment.find({ status: "accepted", ...dateFilter }).lean();

    const totalAppointments = appointments.length;
    const totalGuests = appointments.reduce((sum, a) => sum + (a.guests || 0), 0);
    const totalRevenue = appointments.reduce((sum, a) => sum + (a.totalPrice || 0), 0);

    // Revenue time series
    const timeseriesMap = {};
    appointments.forEach((a) => {
      const d = new Date(a.checkin);
      const label = period === "year" ? `${d.getMonth() + 1}/${d.getFullYear()}` : `${d.getDate()}/${d.getMonth() + 1}`;
      timeseriesMap[label] = (timeseriesMap[label] || 0) + (a.totalPrice || 0);
    });

    const timeseries = Object.keys(timeseriesMap)
      .sort((a, b) => new Date(a) - new Date(b))
      .map((label) => ({ label, revenue: timeseriesMap[label] }));

    // Status summary
    const allAppointments = await Appointment.find(dateFilter).lean();
    const statusMap = {};
    allAppointments.forEach((a) => (statusMap[a.status] = (statusMap[a.status] || 0) + 1));
    const status = Object.keys(statusMap).map((key) => ({ status: key, count: statusMap[key] }));

    // Top rooms
    const roomMap = {};
    appointments.forEach((a) => { if (a.room) roomMap[a.room] = (roomMap[a.room] || 0) + 1; });
    const rooms = Object.keys(roomMap)
      .map((room) => ({ room, count: roomMap[room] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    res.json({ totals: { totalAppointments, totalGuests, totalRevenue }, timeseries, status, rooms });
  } catch (err) {
    console.error("❌ Error loading analytics data:", err);
    res.status(500).json({ error: "Failed to load analytics data" });
  }
});

// ----------------------------
// 🕓 HISTORY PAGE
// ----------------------------
router.get("/history", requireAdmin, async (req, res) => {
  try {
    const appointments = await Appointment.find({ status: { $in: ["accepted", "declined"] } })
      .sort({ createdAt: -1 })
      .lean();

    res.render("admin/history", { title: "Appointment History | Puffer Isle Resort", admin: req.session.admin, appointments });
  } catch (err) {
    console.error("❌ Error loading history:", err);
    res.status(500).render("error", { title: "Error | Puffer Isle Resort", message: "Failed to load appointment history." });
  }
});

// ----------------------------
// 👥 USERS PAGE
// ----------------------------
router.get("/users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).lean();
    res.render("admin/users", { title: "Users | Puffer Isle Resort", admin: req.session.admin, users });
  } catch (err) {
    console.error("❌ Error loading users:", err);
    res.status(500).render("error", { title: "Error | Puffer Isle Resort", message: "Failed to load users." });
  }
});

// ----------------------------
// ✅ ACCEPT APPOINTMENT
// ----------------------------
router.post("/accept/:id", requireAdmin, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    if (!appointment) {
      req.session.message = { type: "error", text: "Appointment not found." };
      return res.redirect("/admin/dashboard");
    }

    appointment.status = "accepted";
    appointment.updatedAt = new Date();
    await appointment.save();

    await Notification.create({
      userId: appointment.userId,
      message: `✅ Your appointment for ${appointment.room} has been accepted!`,
      type: "booking",
    });

    req.session.message = { type: "success", text: "Appointment accepted successfully!" };
    res.redirect("/admin/history");
  } catch (err) {
    console.error("❌ Error accepting appointment:", err);
    req.session.message = { type: "error", text: "Error accepting appointment." };
    res.redirect("/admin/dashboard");
  }
});

// ----------------------------
// ❌ DECLINE APPOINTMENT
// ----------------------------
router.post("/decline/:id", requireAdmin, async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    if (!appointment) {
      req.session.message = { type: "error", text: "Appointment not found." };
      return res.redirect("/admin/dashboard");
    }

    appointment.status = "declined";
    appointment.updatedAt = new Date();
    await appointment.save();

    await Notification.create({
      userId: appointment.userId,
      message: `❌ Your appointment for ${appointment.room} has been declined.`,
      type: "booking",
    });

    req.session.message = { type: "success", text: "Appointment declined successfully!" };
    res.redirect("/admin/history");
  } catch (err) {
    console.error("❌ Error declining appointment:", err);
    req.session.message = { type: "error", text: "Error declining appointment." };
    res.redirect("/admin/dashboard");
  }
});

module.exports = router;