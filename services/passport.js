const passport = require('passport');
const User = require('../models/user');
const secret = require('../config').secret;

const LocalStrategy = require('passport-local');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

//create local strategy
const localOptions = {
    usernameField: 'email'
};
const localLogin = new LocalStrategy(localOptions,function(email,password,done){
    //verify this email and password, call done with the user
    //or call done this false
    User.findOne({email:email},function(err,user){
        if(err){ return done(err,false)}
        if(!user){ return done(null,false)}
        user.comparePassword(password,function(err,isMatch){
            if(err){ return done(err) }
            if(!isMatch){ return done(null,false) }
            return done(null,user)
        })
    })
});


//set up options for jwtStrategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey:secret
};
//create jwt strategy
const jwtLogin = new JwtStrategy(jwtOptions,function(payload,done){
    //see if the userId exists in our payload
    //id it does, call done with that outer
    //otherwise, call it without user object
    User.findById(payload.sub, function(err,user){
        if(err){ return done(err,false) }
        if(user) { done(null,user) }
        else { done(null,false) }
    })
});
//tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);