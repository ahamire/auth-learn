import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local"; 
import env from "dotenv";

const app = express();
const port = 3000;

// Database setup
const db = new pg.Client({
  user: 'postgres',
  host: 'localhost',
  database: 'authentication',
  password: '1111',
  port: 5432,
});
db.connect();

env.config();
// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.secret,
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

const saltRounds = 10; // number of rounds

// Passport configuration
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const userQuery = await db.query("SELECT * FROM users WHERE email = $1", [username]);

      if (userQuery.rows.length === 0) {
        return done(null, false, { message: "Incorrect username." });
      }

      const user = userQuery.rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        return done(null, user);  // Authentication successful
      } else {
        return done(null, false, { message: "Incorrect password." });
      }
    } catch (err) {
      return done(err);
    }
  }
));

// Serialize and deserialize user to manage session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const userQuery = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, userQuery.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Registration route
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [username, hashedPassword]);
    res.redirect("/login");
  } catch (err) {
    res.status(500).send("Error registering user");
  }
});

// Secret route, only accessible to authenticated users
app.get("/secret", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

// Login route
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secret",
  failureRedirect: "/login",
  failureFlash: true
}));

// Logout route
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) { return next(err); }
    res.redirect("/");  // Redirect to homepage or login page
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
