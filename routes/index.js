var express = require('express');
var router = express.Router();
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const User = require("../models/users");
const bcrypt = require("bcryptjs");

router.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
router.use(passport.initialize());
router.use(passport.session());
router.use(express.urlencoded({ extended: false }));
router.use((req, res, next) => {
  res.locals.currentUser = req.user || "";
  next();
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      };
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" })
      }
      return done(null, user);
    } catch(err) {
      return done(err);
    };
  })
);
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  };
});


/* GET home page. */
router.get('/', function(req, res, next) {
  res.redirect('/catalog');
});
router.get("/signup", (req, res) => res.render("signup"))
router.get("/login", (req, res) => res.render("login"))

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/"
}));

router.post("/signup", async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
    if(err){
      return next(err);
    }
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });
    const result = await user.save();
    res.redirect("/");
  });
});

router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

module.exports = router;

