require("dotenv").config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");

const mongoDb = process.env.DB_URL;

mongoose.connect(mongoDb, { useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'ошибка подключения к mongo'));

const User = mongoose.model(
  'User',
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username }, (err, user) => {
            if (err) {
                return done(err);
            };
            if (!user) {
                return done(null, false, { msg: "Incorrect username" });
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    return done(null, user);
                } else {
                    return done(null, false, { msg: "Pass isnt correct!" });
                }
            });
            return done(null, user);
        });
    })
);
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if (err) console.err();
        const user = new User({
          username: req.body.username,
          password: hashedPassword
        }).save(err => {
          if (err) {
            return next(err);
          }
          res.redirect("/");
        });
    });
});
app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
);
app.get("/log-out", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(3000, () => console.log('App is listening port 3000!'));