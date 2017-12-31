const User = require('../models/user');
const jwt = require('jwt-simple');
const secret = require('../config').secret;

function tokenForUser(user){
    const timeStamp = new Date().getTime();
    return jwt.encode({sub: user.id, iat: timeStamp},secret)
}

exports.signup = function(req,res,next){
    const email = req.body.email;
    const password = req.body.password;
    if(!email || !password){ return res.status(422).send({error:'you must provide email and password'})}
    User.findOne({email:email},function(err,existingUser){
        if(err){ return next(err); }
        if(existingUser){
            return res.status(422).send({error:'Email is in use'})
        }
        const user = new User({email:email, password:password});
        user.save(function(err){
            if(err) { return next(err) }
            res.json({token:tokenForUser(user)})
        });
    });
};

exports.signin = function(req,res,next){
    //user has already had their email and password auth'd
    //we just need to give them a token
    res.send({token:tokenForUser(req.user)})
};