const express=require('express');
const routes=express.Router();
const mongoose=require('mongoose');
const bodyparser=require('body-parser');
const bcrypt=require('bcryptjs');
const user=require('./models.js');
const passport=require('passport');
const session=require('express-session');
const cookieParser=require('cookie-parser');
const flash=require('connect-flash');
routes.use(bodyparser.urlencoded({extended:true}));

routes.use(cookieParser('secret'));
routes.use(session({
    secret: 'secret',
    maxAge:3600000,
    resave:true,
    saveUninitialized:true,
}));

routes.use(passport.initialize());
routes.use(passport.session());

routes.use(flash());

//Global variables

routes.use((req,res,next)=>{
    res.locals.success_message=req.flash('success_message');
    res.locals.error_message=req.flash('error_message');
    res.locals.error=req.flash('error');
    next();
});

const checkAuthenticated=(req,res,next)=>{
if(req.isAuthenticated()){
    res.set('Cache-Control','no-cache,private,no-store,must-revalidate,post-check=0,pre-check=0');
    return next();
}
else
{
    res.redirect('/login');
}
}


mongoose.connect('mongodb://localhost:27017/login',{useNewUrlParser:true,useUnifiedTopology:true})
    .then(()=>console.log('DB connected'))
    .catch(err=>console.log('Err',err));
routes.get('/',(req,res)=>{
    res.render('index');
});
routes.post('/register',(req,res)=>{
    var {email,username,password,confirmpassword}=req.body;
    var err;
    if(!email || !username || !password || !confirmpassword)
    {
    err='Please fill the form';
res.render('index',{'err':err});
    }
    if(password !=confirmpassword)
    {
        err="Password don't match";
        res.render('index',{'err':err,'email':email,'username':username});
    }
    if(typeof err=='undefined')
    {
user.findOne({email:email},(err,data)=>{
    if(err)
    throw err;
    if(data){
        console.log("User Exists");
        err="User Already Exists with this Email...";
        res.render('index',{'err':err,email,'username':username});
    }
    else{
        bcrypt.genSalt(10,(err,salt)=>{
            if(err)
            throw err;
            bcrypt.hash(password,salt,(err,hash)=>{
                if(err) throw err;
                password=hash;
                user({
                    email,
                    username,
                    password,
                }).save((err,data)=>{
                    if(err)
                    throw err;
                    req.flash('success_message',"Registered successfully.. Login to Continue..");
                    res.redirect('/login');
                });
            });
        });
    }
});
    }
    
});


//Authentication stratergy

var localStrategy=require('passport-local').Strategy;
passport.use(new localStrategy({ usernameField : 'email',passwordField: 'password'},(email,password,done)=>{
    user.findOne({ email: email},(err,data)=>{
        if(err) throw err;
        if(!data){
            return done(null,false,{message: "User dosen't exist"});
        }
        bcrypt.compare(password,data.password,(err,match)=>{
            if(err){
                return done(null,false);
            }
            if(!match){
                return done(null,false, {message: "Password dosen't match"});
            }
            if(match){
                return done(null,data);
            }
        });
    });
}));

passport.serializeUser((user,cb)=>{
    cb(null,user.id);
});
passport.deserializeUser((id,cb)=>{
    user.findById(id,(err,user)=>{
        cb(err,user)
    });
});

//end of authentication

routes.get('/login',(req,res)=>{
    res.render('login');
});
routes.post('/login',(req,res,next)=>{
    passport.authenticate('local',{
        failureRedirect : '/login',
        successRedirect: '/success',
        failureFlash: true,
    })(req,res,next);
});
routes.get('/success',checkAuthenticated,(req,res)=>{
    res.render('success',{'user':req.user});
});
routes.get('/logout',(req,res)=>{
    req.logout();
    res.redirect('/login');
});
routes.post('/addmsg',checkAuthenticated,(req,res)=>{
    user.findOneAndUpdate(
        {email:req.user.email},
        {$push : {
            messages : req.body['msg']
        }},(err,suc)=>{
            if(err) throw err;
            if(suc) console.log("Added Successfully...");
        }
    );
    res.redirect('/success');
});
module.exports=routes;