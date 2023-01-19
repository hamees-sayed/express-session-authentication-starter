const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const crypto = require("crypto");
const LocalStrategy = require("passport-local").Strategy;
const verifyPassword = require("./lib/passwordUtils").verifyPassword;
const genPassword = require("./lib/passwordUtils").genPassword;

// Package documentation - https://www.npmjs.com/package/connect-mongo
const MongoStore = require("connect-mongodb-session")(session);

// Need to require the entire Passport config module so app.js knows about it

/**
 * -------------- GENERAL SETUP ----------------
 */

// Gives us access to variables set in the .env file via `process.env.VARIABLE_NAME` syntax
require("dotenv").config();

// Create the Express application
var app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * -------------- SESSION SETUP ----------------
 */

// TODO

const conn = process.env.MONGO_URI;

mongoose.connect(conn, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Creates simple schema for a User.  The hash and salt are derived from the user's given password when they register
const UserSchema = new mongoose.Schema({
  username: String,
  hash: String,
  salt: String,
});

const User = mongoose.model("User", UserSchema);

const sessionStore = new MongoStore({
  uri: process.env.MONGO_URI,
  collection: "sessions",
});

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

/**
 * -------------- PASSPORT AUTHENTICATION ----------------
 */

passport.use(
  new LocalStrategy(function (username, password, done) {
    User.findOne({ username: username }, function (err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false);
      }
      if (!verifyPassword(password, user.hash, user.salt)) {
        return done(null, false);
      }
      return done(null, user);
    });
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  User.findById(userId, function (err, user) {
    if (err) {
      return done(err);
    }
    return done(null, user);
  });
});

app.use(passport.initialize());
app.use(passport.session());

/**
 * -------------- ROUTES ----------------
 */

// TODO
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login-failure",
    successRedirect: "/login-success",
  })
);

// TODO
app.post("/register", (req, res, next) => {
  const saltedHashedPW = genPassword(req.body.password);

  const salt = saltedHashedPW.salt;
  const hash = saltedHashedPW.hash;

  const newUser = new User({
    username: req.body.username,
    hash: hash,
    salt: salt,
  });

  newUser.save((err, user) => {
    if (err) {
      return next(err);
    }
    console.log(user);
    res.redirect("/login");
  });
});

/**
 * -------------- GET ROUTES ----------------
 */

app.get("/", (req, res, next) => {
  res.send('<h1>Home</h1><p>Please <a href="/register">register</a></p>');
});

// When you visit http://localhost:3000/login, you will see "Login Page"
app.get("/login", (req, res, next) => {
  const form =
    '<h1>Login Page</h1><form method="POST" action="/login">\
   Enter Username:<br><input type="text" name="username">\
   <br>Enter Password:<br><input type="password" name="password">\
   <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

// When you visit http://localhost:3000/register, you will see "Register Page"
app.get("/register", (req, res, next) => {
  const form =
    '<h1>Register Page</h1><form method="post" action="register">\
                   Enter Username:<br><input type="text" name="username">\
                   <br>Enter Password:<br><input type="password" name="password">\
                   <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

/**
 * Lookup how to authenticate users on routes with Local Strategy
 * Google Search: "How to use Express Passport Local Strategy"
 *
 * Also, look up what behaviour express session has without a maxage set
 */
app.get("/protected-route", (req, res, next) => {
  // This is how you check if a user is authenticated and protect a route.  You could turn this into a custom middleware to make it less redundant
  if (req.isAuthenticated()) {
    res.send(
      '<h1>You are authenticated</h1><p><a href="/logout">Logout and reload</a></p>'
    );
  } else {
    res.send(
      '<h1>You are not authenticated</h1><p><a href="/login">Login</a></p>'
    );
  }
});

// Visiting this route logs the user out
app.get("/logout", (req, res, next) => {
  req.logout();
  res.redirect("/protected-route");
});

app.get("/login-success", (req, res, next) => {
  res.send(
    '<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>'
  );
});

app.get("/login-failure", (req, res, next) => {
  res.send("You entered the wrong password.");
});

// Imports all of the routes from ./routes/index.js

/**
 * -------------- SERVER ----------------
 */

// Server listens on http://localhost:3000
app.listen(3000);
