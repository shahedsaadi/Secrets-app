
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const  findOrCreate = require('mongoose-findorcreate');

const app = express();


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

// set up our session
app.use(session({
  secret: process.env.SECRET_MESSAGE,
  resave: false,
  saveUninitialized: false
}));

// initialize and start usining passport
app.use(passport.initialize());
app.use(passport.session());   // use passport to manage our sessions.


//connect to MongoDB
mongoose.set('strictQuery', false);
main().catch(err => console.log(err));
async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");
}

// Schema
const userSchema = new mongoose.Schema ({
  username: { type: String, unique: true }, // values: email address, googleId, facebookId
  password: String,
  provider: String,  // values: 'local', 'google', 'facebook'
  email: String,
  secret: String
});

//set up passportLocalMongoose , we have to add it to our mongoose Schema as a plugin.
userSchema.plugin(passportLocalMongoose, {usernameField: "username"}); // hash and salt passwords and to save our users into mongodb

userSchema.plugin(findOrCreate);

// Model
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate( { username: profile.id },{provider: "google", email: profile._json.email}, function (err, user) { // create them as a user on our database .
      return cb(err, user);
    });
  }
));

// Facebook Strategy
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        profileFields: ["id","email"]
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ username: profile.id },{provider: "facebook", email: profile._json.email},function (err, user) {
            return cb(err, user);
      });
    }
));



app.get("/", function(req, res){
  res.render("home");
});


app.get("/auth/google",
  passport.authenticate('google', {scope: ['profile', 'email'] })  //initiate authentication with Google.//asking them for the user's profile once they've logged in.
);

// Now once that's been successful, Google will redirect the user back to our website and make a get request to /auth/google/secrets.
//GET request, gets made by Google when they try to redirect the user back to our website.
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook', {scope: ["email"]})
);

  app.get('/auth/facebook/secrets',

  passport.authenticate('facebook', {failureRedirect: '/login'}),
  function(req, res) {
  res.redirect('/secrets');
  });


app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
User.find({"secret": {$ne: null}}, function(err, foundUsers){
  if(err){
    console.log(err);
  } else {
    if (foundUsers) {
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  }
});
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret; // secret that user submitted

    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.

    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
      if (err){
        console.log(err);
      }else {
        if(foundUser){
          foundUser.secret = submittedSecret;
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        }
      }
    });
});

app.get("/logout", function(req, res){
  req.logout(function(err){       // to end the session.
    if(err){
      console.log(err);
    }else {
      res.redirect("/");
    }
  });
});


app.post("/register", function(req, res){
  const username = req.body.username;
  const password = req.body.password;
  User.register({username: username, email: username, provider: 'local'}, password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");   // try again
    }else{       // if no err,
      passport.authenticate("local")(req, res, function(){  // this call back only triggerd if the authentication was successful.
        res.redirect("/secrets");                          //then managed to successfully set up a cookie that saved their current logged in
      });
    }
  });

});

app.post("/login", function(req, res){
  //create document
 const user = new User ({
   username: req.body.username,
   password: req.body.password
 });

// login method comes from passport
 req.login(user, function(err){
   if(err){
     console.log(err);
   }else{
     passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
     });
   }
 })
});




app.listen(3000, function() {
  console.log("Server started on port 3000");
});
