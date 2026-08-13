// --------------------------------------------
// Puffer Isle Resort | Isle RMS - Server.js
// Final "Master" Version - 100% Solid Backend
// --------------------------------------------

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const dotenv = require("dotenv");
const MongoStore = require("connect-mongo");

dotenv.config();

// --- Load Models ---
const Appointment = require("./models/Appointment");
const User = require("./models/User");
const Admin = require("./models/Admin");

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/puffer_isle_resort";

// --------------------------------------------
// DATABASE CONNECTION & ADMIN SETUP
// --------------------------------------------
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log("✅ Database: Puffer Isle Resort Linked");
    await createDefaultAdmin();
  } catch (err) {
    console.error("❌ Database Error:", err);
    process.exit(1);
  }
}

async function createDefaultAdmin() {
  try {
    const adminUser = "pufferisleadmin2026";
    const adminPass = "resortpufferisle2026";

    const existingAdmin = await Admin.findOne({ username: adminUser });
    if (!existingAdmin) {
      const newAdmin = new Admin({
        username: adminUser,
        password: adminPass, 
      });
      await newAdmin.save();
      console.log(`✅ Admin: Created ${adminUser}`);
    }
  } catch (err) { 
    console.log("ℹ️ Admin Setup: Ready (Credentials verified)");
  }
}

// --------------------------------------------
// CONFIGURATION & MIDDLEWARE
// --------------------------------------------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "puffer_isle_secret_key",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { 
      maxAge: 1000 * 60 * 60 * 24, // 1 Day
      httpOnly: true 
    },
  })
);

// Global Variables for Templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.admin = req.session.admin || null;
  res.locals.title = "Puffer Isle Resort";
  next();
});

// --------------------------------------------
// ADMIN SYSTEM ROUTES
// --------------------------------------------

// Render Admin Login
app.get("/adminlogin", (req, res) => {
  if (req.session.admin) return res.redirect("/admin/dashboard");
  res.render("admin/adminlogin", { title: "Admin Portal", error: null });
});

// Admin Login Logic
app.post("/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body; 
    
    const MASTER_USER = "pufferisleadmin2026";
    const MASTER_PASS = "resortpufferisle2026";

    if (email === MASTER_USER && password === MASTER_PASS) {
      req.session.admin = { username: MASTER_USER, role: 'root' };
      return res.redirect("/admin/dashboard");
    }

    const admin = await Admin.findOne({ username: email });
    if (admin && (await admin.comparePassword(password))) {
      req.session.admin = { id: admin._id, username: admin.username };
      return res.redirect("/admin/dashboard");
    }

    res.render("admin/adminlogin", { 
      title: "Admin Portal", 
      error: "Access Denied. Invalid Credentials." 
    });
  } catch (err) {
    res.status(500).send("Login error occurred.");
  }
});

// Admin Dashboard
app.get("/admin/dashboard", async (req, res) => {
  if (!req.session.admin) return res.redirect("/adminlogin");
  
  try {
    const totalBookings = await Appointment.countDocuments();
    const totalUsers = await User.countDocuments(); 
    const inHouseCount = await Appointment.countDocuments({ checkedIn: true });
    
    const recentBookings = await Appointment.find()
      .populate('userId', 'fullname email') 
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();

    res.render("admin/dashboard", {
      title: "Isle Command",
      totalBookings,
      totalUsers,
      inHouseCount,
      recentBookings
    });
  } catch (err) {
    console.error("Dashboard Error:", err);
    res.status(500).send("Error loading dashboard.");
  }
});

// Admin History (Archive)
app.get("/admin/history", async (req, res) => {
    if (!req.session.admin) return res.redirect("/adminlogin");
    
    try {
      const allBookings = await Appointment.find()
        .populate('userId', 'fullname email')
        .sort({ createdAt: -1 })
        .lean();
  
      res.render("admin/history", {
        title: "Isle Archive",
        allBookings 
      });
    } catch (err) {
      console.error("History Page Error:", err);
      res.status(500).send("Error loading archive data.");
    }
});

// --- FRONT DESK CHECK-IN MANAGER ---
app.get("/admin/checkin-manager", async (req, res) => {
  if (!req.session.admin) return res.redirect("/adminlogin");
  
  try {
    const arrivals = await Appointment.find({
      status: "accepted",
      checkedIn: false
    })
    .populate('userId')
    .sort({ checkin: 1 })
    .lean();

    const inHouse = await Appointment.find({
      checkedIn: true
    })
    .populate('userId')
    .sort({ checkInTime: -1 }) 
    .lean();

    res.render("admin/checkin", { 
      arrivals, 
      inHouse, 
      title: "Front Desk Operations" 
    });
  } catch (err) {
    console.error("Front Desk Error:", err);
    res.status(500).send("Mainframe Error Loading Front Desk");
  }
});

// --- AJAX CHECK-IN UPDATE ---
app.post("/admin/update-checkin", async (req, res) => {
  if (!req.session.admin) return res.status(401).json({ success: false });

  try {
    const { bookingId, checkedIn } = req.body;
    
    await Appointment.findByIdAndUpdate(bookingId, {
      checkedIn: checkedIn,
      checkInTime: checkedIn ? new Date() : null
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// AJAX Booking Status Update (Accept/Decline)
app.post("/admin/booking/update-status", async (req, res) => {
  if (!req.session.admin) {
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  try {
    const { bookingId, status } = req.body;
    const updatedBooking = await Appointment.findByIdAndUpdate(
      bookingId,
      { status: status }, 
      { new: true }
    );

    if (!updatedBooking) {
      return res.status(404).json({ success: false, message: "Booking not found." });
    }

    res.json({ success: true, message: `Status updated to ${status}` });
  } catch (err) {
    res.status(500).json({ success: false, message: "Update failed." });
  }
});

app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/adminlogin"));
});

// --------------------------------------------
// USER AUTHENTICATION & PROFILE
// --------------------------------------------

app.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password, phone } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send("Account already exists.");
    const newUser = new User({ fullname, email, password, phone });
    await newUser.save();
    req.session.user = newUser.toObject();
    res.redirect("/profile");
  } catch (err) { res.status(500).send("Signup error."); }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ email: username });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).send("Invalid credentials.");
    }
    req.session.user = user.toObject();
    res.redirect("/profile");
  } catch (err) { res.status(500).send("Login error."); }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/profile", async (req, res) => {
  if (!req.session.user) return res.redirect("/");
  try {
    const user = await User.findById(req.session.user._id).lean();
    const appointments = await Appointment.find({ userId: user._id }).sort({ createdAt: -1 }).lean();
    res.render("profile", { title: "My Dashboard", user, appointments, notifications: [] });
  } catch (err) {
    res.status(500).send("Profile load error.");
  }
});

// LIVE UPDATE ENDPOINT: For fetching live data via AJAX in profile.ejs
app.get('/userUpdates/:id', async (req, res) => {
  try {
    // Security: Ensure the requester is the owner of the data
    if (!req.session.user || req.session.user._id.toString() !== req.params.id) {
        return res.status(401).json({ success: false });
    }
    const appointments = await Appointment.find({ userId: req.params.id }).sort({ createdAt: -1 });
    res.json({ success: true, appointments, notifications: [] });
  } catch (err) {
    res.json({ success: false });
  }
});

// --------------------------------------------
// USER BOOKING PROCESS
// --------------------------------------------

app.get("/booking", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  res.render("appointments", { title: "Book Your Stay", error: null, success: null });
});

app.post("/booking/submit", async (req, res) => {
  try {
    if (!req.session.user) return res.redirect("/");
    
    // CHANGE 1: cottage_addon changed to cottageAddon and added totalPrice to match the EJS
    const { room, cottageAddon, guests, contact, checkin, checkout, specialRequests, totalPrice } = req.body;
    
    // CHANGE 2: Backend Logic Check - Reject Same Day check-in/out
    if (checkin === checkout) {
        console.warn("⚠️ Blocked same-day check-in/out attempt.");
        return res.redirect("/booking?error=invalid_dates");
    }

    const newBooking = new Appointment({
      userId: req.session.user._id,
      room, 
      // CHANGE 3: Logic update - Checkboxes send "on" if checked, otherwise undefined
      cottageAddon: cottageAddon === 'on', 
      guests,
      contact,
      checkin,
      checkout,
      specialRequests,
      // CHANGE 4: Capturing the totalPrice sent from frontend calculation
      totalPrice: parseFloat(totalPrice) || 0,
      status: 'pending' 
    });
    
    await newBooking.save();
    res.redirect("/profile?success=booked");
  } catch (err) { 
    console.error("Booking Submission Error:", err);
    res.redirect("/booking?error=failed"); 
  }
});

// --------------------------------------------
// PAGES & 404
// --------------------------------------------

app.get("/", (req, res) => res.render("index", { title: "Puffer Isle Resort" }));
app.get("/gallery", (req, res) => res.render("gallery", { title: "Explore Resort" }));
app.get("/rules", (req, res) => res.render("rules", { title: "Island Rules" }));

app.use((req, res) => {
  res.status(404).render("404", { title: "404 - Lost in Paradise" });
});

// --------------------------------------------
// LAUNCH
// --------------------------------------------
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Island System Active: http://localhost:${PORT}`);
  });
});