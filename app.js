//jshint esversion:6
require('dotenv').config();//håller hemligheter hemliga, högst upp
const express = require ("express");
const bodyParser = require ("body-parser");
const ejs = require("ejs");
const mongoose =require ("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const { serializeUser } = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();




app.use(express.static("public"));
app.set("view engine" , "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));
//cookies som sparas
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());//startar passport kryptering
app.use(passport.session());//passport startar cookies

//cookies slutar


//mongo db connection med schema
mongoose.connect("mongodb://localhost:27017/userDB",   {useNewUrlParser: true});//defaultport för MongoDB
//mongoose.set("useCreateIndex", true);

//crypterar databasen med plugin
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,//id som hittar user som loggar in genom google, och inte skapar ny id varje gång i DB
    secret: String 
});

userSchema.plugin(passportLocalMongoose);//krypterar när man (call save plugin) 
userSchema.plugin(findOrCreate);//dekrypterar (när man call find plugin)
//slutar här

const User = new mongoose.model("User", userSchema);//skapar användare i DB

passport.use(User.createStrategy());//autentiserar användaren
//serialize skapar  krypterad cookie med personens id, funkar för alla strategies
passport.serializeUser(function(user, done){
    done(null, user.id);
});
//deserialize tar sönder cookie så vi kan identifiera personen
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});//funkar på alla strategies


//passport google oauth, autentiserar user med new google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secretapp",//hjälper google att känna igen vår app
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"//hjälper google att känna igen vår app
  }, //hämtar info från userinfo inte google+ account
  
  //google skickar accesstoken så att vi kan använda data så länge det behövs
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
//installera paket mongoose findOrCreate, skapar el hittar id och profil genom googleid
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/", function(req, res){
    res.render("home")
});
//passport auth med google strategy, popup ruta för att user ska logga in
app.get("/auth/google", 
  passport.authenticate("google", {scope: ["profile"] }) 
);
//google skickar tbx user, autentiserar user lokalt och blir hänvisar till appen om login
app.get("/auth/google/secretapp", passport.authenticate("google", { failureRedirect: "/login" }), function(req, res){
    res.redirect("/secrets");
});


app.get("/login", function(req, res){
    res.render("login")
});

app.get("/register", function(req, res){
    res.render("register")
});
//hittar alla secrets i databasen som blir inskickade
app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if(err){
          console.log(err);
      }else{
          if(foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers});
          }
      }
  }); 
});
//skicka in en secret, om dom inte är inloggade skickas dom dit först
app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
     }else{
        res.redirect("/login");
     }  
});
//secret blir inskickad
app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    //när user blir aut, sparas info i req.user
//console.log(req.user.id);
//om samma user loggar in igen så lagras deras secret på deras id
User.findById(req.user.id, function(err, foundUser){
   if(err) {
       console.log(err);
   }else{
       if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
         res.redirect("/secrets");   
        });
       }
   }
});
});
//loggar ut användare avslutar session/cookies
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/"); 
});

//registrerar nya anändare med passport med local strategy

app.post("/register", function(req, res){

User.register({username: req.body.username}, req.body.password, function(err, user){
  if(err) {
      console.log(err);
      res.redirect("/register");
  } else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");  
      });
  } 
});

});
//kollar så att username och password matchar med passport
app.post("/login", function(req, res){
   
 const user =  new User({
     username: req.body.username,
     password: req.body.password

 });           
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

         




app.listen(3000, function(){
console.log("Server started on port 3000.")
});