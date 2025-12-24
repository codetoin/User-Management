import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy } from "passport-local";
import session, { Session } from "express-session";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = parseInt(process.env.SALT_ROUNDS, 10);
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      httpOnly: true,
      sameSite: "lax",
      secure: false, // set true only in HTTPS production
    },
  })
);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());


const { Pool } = pg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Supabase
  },
});

db.connect()
  .then(() => console.log("✅ Connected to Supabase via Pool!"))
  .catch((err) => console.error("❌ Connection error:", err));

app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

app.use(async (req, res, next) => {
  try {
    res.locals.user = req.user || null;
    let theme = "light";
    if (req.user && req.user.id) {
      const result = await db.query(
        "SELECT theme FROM users WHERE id=$1",
        [req.user.id]
      );
      if (result.rows.length > 0) theme = result.rows[0].theme;
    }
    res.locals.theme = theme;
    next();
  } catch (err) {
    console.error(err);
    next();
  }
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/about", (req, res) => {
  res.render("about.ejs");
});

// All other codes go here below

// Admin Routes Below
app.get("/admin/dashboard", async (req, res) => {
  const result = await db.query(`
  SELECT
    COUNT(*) FILTER (WHERE role = 'user') AS total_users,
    COUNT(*) FILTER (WHERE role = 'user' AND is_active = true) AS active_users,
    COUNT(*) FILTER (WHERE role = 'user' AND is_active = false) AS inactive_users,
    COUNT(*) FILTER (WHERE role = 'admin') AS admin_count
  FROM users
  `);
  const statues = result.rows[0];
  if (req.isAuthenticated() && req.user.role === "admin") {
    res.render("admin/admin-dashboard.ejs", {
      admin: req.user,
      stats: statues,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/users", async (req, res) => {
  if (req.isAuthenticated() && req.user.role == "admin") {
    const search = req.query.search || "";

    const result = await db.query(
      `
    SELECT id, user_name, email, role, is_active, created_at
    FROM users
    WHERE user_name ILIKE $1 OR email ILIKE $1
    ORDER BY created_at DESC
    `,
      [`%${search}%`]
    );

    res.render("admin/users.ejs", {
      admin: req.user,
      users: result.rows,
      search,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/view-user", (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    res.render("admin/view-user.ejs", { admin: req.user, user });
  } else {
    res.redirect("/login");
  }
});

app.get("/view-user/back", (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    res.redirect("/admin/users");
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/users/:id", async (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    const userId = req.params.id;

    try {
      // Query the user from database
      const result = await db.query(
        "SELECT id, user_name, email, role, is_active, created_at, updated_at FROM users WHERE id = $1",
        [userId]
      );

      if (result.rows.length === 0) {
        // User not found
        return res.send("User not found");
      }

      const user = result.rows[0];

      // Render the view page
      res.render("admin/view-user.ejs", {
        admin: req.user, // current admin info
        user,
      });
    } catch (err) {
      console.error(err);
      res.send("Error fetching user");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/admin/users/:id/activate", async (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    await db.query(
      "UPDATE users SET is_active = true, updated_at = NOW() WHERE id = $1",
      [req.params.id]
    );
    res.redirect("/admin/users");
  } else {
    res.redirect("/login");
  }
});

app.post("/admin/users/:id/deactivate", async (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    await db.query(
      "UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1",
      [req.params.id]
    );
    res.redirect("/admin/users");
  } else {
    res.redirect("/login");
  }
});

app.post("/admin/users/:id/delete", async (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    if (req.user.id === Number(req.params.id)) {
      return res.redirect("/admin/users");
    }

    await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);

    res.redirect("/admin/users");
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/users/:id/edit", async (req, res) => {
  const userId = req.params.id;
  if (req.isAuthenticated() && req.user.role === "admin") {
    try {
      const result = await db.query("SELECT * FROM users WHERE id = $1", [
        userId,
      ]);
      const data = result.rows[0];
      res.render("admin/user-edit.ejs", { user: data });
    } catch (err) {
      console.log(err);
      res.redirect("/admin/users/:id/edit");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/admin/users/:id/edit", async (req, res) => {
  const userId = req.params.id;
  const role = req.body.role;
  const status = req.body.status;

  const { name, email} = req.body;

  try {
    // 1. Basic validation
    if (!name) {
      return res.send("Name is required");
    }

    // 2. Check email is not used by another user
    const emailCheck = await db.query(
      "SELECT id FROM users WHERE user_name = $1 AND id != $2",
      [name, userId]
    );

    if (emailCheck.rows.length > 0) {
      return res.send("User Name already exists");
    }
    let is_active = status === "active" ? true : false;
    await db.query(
      `UPDATE users
       SET user_name = $1,
           email = $2,
           role = $3,
           is_active = $4,
           updated_at = NOW()
       WHERE id = $5`,
      [name, email, role, is_active, userId]
    );

    // 5. Redirect back to users list or details page
    res.redirect("/admin/users");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.get("/admin/settings", (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    res.render("admin/admin-settings.ejs", {user : req.user});
  } else {
    res.redirect("/login");
  }
});

app.get("/admin-update-profile", (req, res) => {
  if (req.isAuthenticated() && req.user.role === "admin") {
    res.render("admin/admin-update-profile.ejs", {user : req.user});
  }else {
    res.redirect("/login");
  }
});

app.post("/admin-update-profile", async (req, res) => {
  const { user_name, email, currentPassword, newPassword, confirmPassword } = req.body;
  const adminId = req.user.id;

  try {
    // 1️⃣ Get current admin from DB
    const result = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [adminId]
    );

    const admin = result.rows[0];

    // 2️⃣ If password change requested
    if (newPassword || confirmPassword) {

      // Check new password match
      if (newPassword !== confirmPassword) {
        return res.send("<script>alert('New passwords do not match'); window.history.back();</script>");
      }

      // Verify current password
      const valid = await bcrypt.compare(currentPassword, admin.password);
      if (!valid) {
        return res.send("<script>alert('Current password is incorrect'); window.history.back();</script>");
      }
      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      // Update with password
      await db.query(
        `UPDATE users 
         SET user_name = $1, email = $2, password = $3, updated_at = NOW()
         WHERE id = $4`,
        [user_name, email, hashedPassword, adminId]
      );

    } else {
      // 3️⃣ Update without password
      await db.query(
        `UPDATE users 
         SET user_name = $1, email = $2, updated_at = NOW()
         WHERE id = $3`,
        [user_name, email, adminId]
      );
    }

    // 4️⃣ Redirect back
    res.redirect("/admin/settings");

  } catch (err) {
    console.error(err);
    res.send("Something went wrong");
  }
});

// Admin Routes Above

app.get("/user-home", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("user/user-home.ejs", { user: req.user });
  } else {
    res.redirect("/login");
  }
});

app.get("/user-profile", (req, res) => {
  if (req.isAuthenticated()) {
    const date = new Date(req.user.created_at);
    const updateDate = new Date(req.user.updated_at);
    res.render("user/profile.ejs", {
      user: req.user.user_name,
      email: req.user.email,
      role: req.user.role,
      status: req.user.is_active,
      activationTime: date.toLocaleString(),
      updateTime: updateDate.toLocaleString(),
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/change-password", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("user/change-password.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/change-password", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const { currentPassword, newPassword, confirmPassword } = req.body;

  // 1️⃣ New passwords must match
  if (newPassword !== confirmPassword) {
    return res.redirect("/change-password");
  }

  try {
    // 2️⃣ Get current user from session
    const userId = req.user.id;

    const result = await db.query("SELECT password FROM users WHERE id = $1", [
      userId,
    ]);

    const user = result.rows[0];

    // 3️⃣ Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.redirect("/change-password");
    }

    // 4️⃣ Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // 5️⃣ Update password
    await db.query(
      "UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2",
      [hashedPassword, userId]
    );

    // 6️⃣ Success
    res.redirect("/user-home");
  } catch (err) {
    console.error(err);
    res.redirect("/change-password");
  }
});

app.get("/settings", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("user/settings.ejs", { user: req.user });
  } else {
    res.redirect("/login");
  }
});

app.post("/diactivate", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id;
      const isActive = req.user.is_active;

      await db.query(
        "UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2",
        [!isActive, userId]
      );
      res.redirect("/user-profile");
    } catch (err) {
      console.log(err);
      res.redirect("/settings");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/delete-account", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id; // get logged-in user's ID

      // 1️⃣ Delete the user from the database
      await db.query("DELETE FROM users WHERE id = $1", [userId]);

      // 2️⃣ Log the user out after deletion
      req.logout((err) => {
        if (err) {
          console.error(err);
          return res.redirect("/user-profile");
        }
        res.redirect("/register"); // or home page
      });
    } catch (err) {
      console.error(err);
      res.redirect("/user-profile");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/edit-profile", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("user/edit-profile.ejs", { user: req.user });
  } else {
    res.redirect("/login");
  }
});

app.post("/edit-profile", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id;
      const newName = req.body.name;
      await db.query(
        "UPDATE users SET user_name = $1, updated_at = NOW() WHERE id = $2",
        [newName, userId]
      );
      res.redirect("/user-profile");
    } catch (err) {
      console.log(err);
      res.redirect("/edit-profile");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/settings/preferences", async (req, res) => {
  const userId = req.user.id; 
  const theme = req.body.theme; // 'light' or 'dark'

  // Update in database
  await db.query("UPDATE users SET theme=$1, updated_at = NOW() WHERE id=$2", [theme, userId]);
  if (req.user.role === "user") {
    res.redirect("/settings");
  } else {
    res.redirect("/admin/settings");
  }
});


// All other codes go here above

app.get("/register", (req, res) => {
  res.render("auth/register.ejs");
});

app.get("/login", (req, res) => {
  res.render("auth/login.ejs");
});

app.get("/log-out", (req, res) => {
  res.render("auth/log-out.ejs");
});

app.post("/register", async (req, res) => {
  const user_name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword; // make sure your form has this field

  // 1️⃣ Check if passwords match
  if (password !== confirmPassword) {
    console.log("Passwords do not match!");
    return res.send(
      `<script>alert('Passwords do not match!'); window.location.href='/register';</script>`
    );
  }

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (user_name, email, password) VALUES ($1, $2, $3) RETURNING *",
            [user_name, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.log(err);
              return res.redirect("/login");
            }
            console.log("success");
            res.redirect("/user-home");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      return res.redirect("/register");
    }

    req.logIn(user, (err) => {
      if (err) return next(err);

      // 🔑 ROLE-BASED REDIRECT
      if (user.role === "admin") {
        return res.redirect("/admin/dashboard");
      } else {
        return res.redirect("/user-home");
      }
    });
  })(req, res, next);
});

app.post("/log-out", async (req, res, next) => {
  const { email, password } = req.body;

  try {
    // 1️⃣ Find user in database
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res.render("auth/log-out", { error: "User not found!" });
    }

    const user = result.rows[0];

    // 2️⃣ Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render("auth/log-out", { error: "Incorrect password!" });
    }

    // 3️⃣ Password correct → logout
    req.logout({ keepSessionInfo: false }, (err) => {
      if (err) return next(err);
      res.redirect("/");
    });
  } catch (err) {
    console.error(err);
    res.render("auth/log-out", { error: "Something went wrong!" });
  }
});

passport.use(
  new Strategy(
    {
      usernameField: "email", // 👈 THIS IS REQUIRED
      passwordField: "password",
    },
    async function verify(email, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          email,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); // just store the user id
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]); // fetch user from DB
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
