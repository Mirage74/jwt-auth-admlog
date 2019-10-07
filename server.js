const Koa = require('koa'); // core
const Router = require('koa-router'); // routing
const bodyParser = require('koa-bodyparser'); // POST parser
const serve = require('koa-static'); // serves static files like index.html
const logger = require('koa-logger'); // optional module for logging

const passport = require('koa-passport'); //passport for Koa
const LocalStrategy = require('passport-local'); //local Auth Strategy
const JwtStrategy = require('passport-jwt').Strategy; // Auth via JWT
const ExtractJwt = require('passport-jwt').ExtractJwt; // Auth via JWT

const { jwtsecret, PASS_FOR_CREATE_SUPERVISOR } = require('./config')

const jwt = require('jsonwebtoken'); // auth via JWT for hhtp
const socketioJwt = require('socketio-jwt'); // auth via JWT for socket.io

const socketIO = require('socket.io');
const mongoose = require('./libs/mongoose');


const app = new Koa();
const router = new Router();
app.use(serve('public'));
app.use(logger());
app.use(bodyParser());



app.use(async (ctx, next) => {
  const origin = ctx.get('Origin');
//  console.log("origin ", origin)
//  console.log(ctx.method)
  if (ctx.method !== 'OPTIONS') {
    ctx.set('Access-Control-Allow-Origin', origin);
    ctx.set('Access-Control-Allow-Credentials', 'true');
//console.log("ctx.response.header 1 : ", ctx.response.header)
  } else if (ctx.get('Access-Control-Request-Method')) {
    ctx.set('Access-Control-Allow-Origin', origin);
    ctx.set('Access-Control-Allow-Methods', ['GET', 'POST', 'DELETE', 'PUT', 'PATCH', 'OPTIONS']);
    ctx.set('Access-Control-Allow-Headers', ['Content-Type', 'Authorization', 'Access-Control-Allow-Headers', 'headers', 'login']);
    ctx.set('Access-Control-Max-Age', '42');
    ctx.set('Access-Control-Allow-Credentials', 'true');
    ctx.response.status = 200
    //console.log('ctx.response.status', ctx.response.status)
  }
  await next();
});





app.use(passport.initialize()); // initialize passport first
app.use(router.routes()); // then routes
const server = app.listen(process.env.PORT || 4000);// launch server on port  4000


const User = require('./libs/user')


const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("jwt"),
  secretOrKey: jwtsecret
};



passport.use(new LocalStrategy({
  usernameField: 'login',
  passwordField: 'password',
  session: false
},
  function (login, password, done) {
    User.findOne({ login }, (err, user) => {
      if (err) {
        return done(err);
      }

      if (!user || !user.checkPassword(password)) {
        return done(null, false, { message: 'User does not exist or wrong password.' });
      }
      return done(null, user);
    })
  })
)



passport.use(new JwtStrategy(jwtOptions, function (payload, done) {
  User.findById(payload.id, (err, user) => {
    if (err) {
      return done(err)
    }
    if (user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})
)



router.param('userById', async (id, ctx, next) => {
//  let tempUser = await User.findById(id)
//  ctx.userById = tempUser.toObject()

   ctx.userById = await User.findById(id);

//  console.log("userById : ", ctx.userById)
  if (!ctx.userById) {
    ctx.throw(404);
  }
  await next();
})


router.post('/user', async (ctx, next) => {
  //passportGetJWTuser()
  //passportGetUserNameUser()
  try {
    //console.log("USER : ", User)
    //console.log("post, ctx.request.body : ", ctx.request.body)
    let user = await User.create(ctx.request.body)
    let Obj = user.toObject()
    let userObj = {
      _id: Obj._id,
      login: Obj.login,
      attempts: Obj.attempts,
      userNo: Obj.userNo,
      lockUser: Obj.lockUser,
      allowedApps: Obj.allowedApps
    } 
    ctx.body = userObj
  }
  catch (err) {
    ctx.status = 400
    ctx.body = err
  }
})


router.get('/checkuserexist', async (ctx, next) => {
  let isAdmin = false
  //console.log("ctx.request ", ctx.request)
  //console.log(ctx.request)
  await passport.authenticate('jwt', function (err, user) {
    if (user) {
      //    console.log(user)
      isAdmin = user.isAdmin
    } else {
      ctx.body = "No such user";
      console.log("err", err)
    }
  })(ctx, next)

  if (isAdmin) {
    //console.log("ctx.request ", ctx.request)
    let user = await User.findOne({ login: ctx.request.header.login })
    //console.log(user)
    if (user) {
      ctx.body = user.toObject().login
    } else {
      ctx.body = "USER_NOT_FOUND"
    }
  } else {
    console.log("Access denied, user not admin ")
//    ctx.status = 401
    ctx.body = "Unauthorized admin, checkuserexist"
  }
})

router.del('/user/:userById',  async function(ctx) {
//  console.log("userById : ",  userById)
  let user = await User.findOne({ _id: userById })
  ctx.body = user
})


router.get('/admins', async (ctx, next) => {
  let isSupervisor = false
  await passport.authenticate('jwt', function (err, user) {
    if (user) {
      isSupervisor = user.isSupervisor
    } else {
      ctx.body = "No such jwt user, router.get(/admins)"
      console.log("err", err)
    }
  })(ctx, next)

  if (isSupervisor) {
    let admins = await User.find({ isSupervisor: false, isAdmin: true }).sort({"login" : 1})
    if (admins) {
      let adminsObj = admins.map(
        admin => { return { _id: admin._id, login: admin.login } }
      )
      ctx.body = adminsObj
    } else {
      ctx.body = "ADMINS_NOT_FOUND"
    }
  } else {
    console.log("Access denied, user not supervisor ")
//    ctx.status = 401
    ctx.body = "Unauthorized supervisor"
  }
})



router.get('/users', async (ctx, next) => {
  let isAdmin = false
  await passport.authenticate('jwt', function (err, user) {
    if (user) {
//      console.log("user ", user)
      isAdmin = user.isAdmin
    } else {
      ctx.body = "No such jwt user, router.get(/users)"
      console.log("err", err)
    }
  })(ctx, next)

  if (isAdmin) {
    let users = await User.find({userNo: {$exists: true} }).sort({"userNo" : 1})
    if (users) {
      let usersObj = users.map(
        user => { return { _id: user._id, login: user.login, attempts: user.attempts, userNo: user.userNo, lockUser: user.lockUser, allowedApps: user.allowedApps  } }
      )
      ctx.body = usersObj
    } else {
      ctx.body = "USERS_NOT_FOUND"
    }
  } else {
    console.log("Access denied, user not admin ")
//    ctx.status = 401
    ctx.body = "Unauthorized admin, users"
  }
})


router.get('/user/edit/:userById',  async function(ctx) {
//console.log("ctx.userById router.get(/users/:userById ) : ", ctx.userById)

  let usersObj = {
    _id: ctx.userById._id,
    login: ctx.userById.login,
    attempts: ctx.userById.attempts,
    userNo: ctx.userById.userNo,
    lockUser: ctx.userById.lockUser,
    allowedApps: ctx.userById.allowedApps
  } 
  const payload = {
    id: ctx.userById._id,
    login: ctx.userById.login
  }
  usersObj.jwt = jwt.sign(payload, jwtsecret)
  //console.log(  usersObj)
  ctx.body = usersObj
})

router.put('/user/edit/:userById',  async function(ctx) {
  let user = await User.updateOne({_id:ctx.userById}, ctx.request.body.data);
  ctx.userById = await User.findById(ctx.userById);
  console.log("ctx.request.body.data : ", ctx.request.body.data) 
    let tmp = ctx.userById.toObject()
    ctx.body = { login: tmp.login }
//  ctx.body = ctx.userById.toObject()
})



router.post('/createsuper', async (ctx, next) => {
  try {
    ctx.request.body.login = ctx.request.body.newSupervisorlogin.toLowerCase()
    ctx.request.body.password = ctx.request.body.newSupervisorPassword
    ctx.request.body.isSupervisor = true
    ctx.request.body.isAdmin = true
    //console.log("ctx.request.body : ", ctx.request.body)
    if (ctx.request.body.verifyAccessPassword === PASS_FOR_CREATE_SUPERVISOR) {
      console.log("PASS OK")
      try {
        let user = await User.create(ctx.request.body)
        ctx.body = user.toObject()
      }
      catch (err) {
        console.log("Error create createsuper : ", err)
      }
    } else {
      console.log("ACCESS DENIED")
      ctx.body = "ACCESS DENIED"
    }
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
})




router.post('/login', async (ctx, next) => {
  //  passportGetJWTuser()
  await passport.authenticate('local', function (err, user) {
    if (user == false) {
//      ctx.response.status = 401
      ctx.body = "Login failed";
    } else {
      //--payload - info to put in the JWT
      const payload = {
        id: user.id,
        login: user.login,
      }
      const token = jwt.sign(payload, jwtsecret); //JWT is created here
      ctx.body = { login: user.login, isSupervisor: user.isSupervisor, isAdmin: user.isAdmin, allowedApps: user.allowedApps, token: 'JWT ' + token }
    }
  })(ctx, next);

});

// JWT auth route

router.get('/custom', async (ctx, next) => {
  //passportGetUserNameUser()
  console.log(ctx.request.headers)
//console.log("ctx.response.header : ", ctx.response.header)
  await passport.authenticate('jwt', function (err, user) {
    if (user) {
      ctx.body = user.login;
    } else {
      ctx.body = "No such user";
      console.log("err", err)
    }
  })(ctx, next)

});


router.del('/admins/:userById',  async function(ctx) {
  await ctx.userById.remove();

  ctx.body = 'ok';
})


router.del('/users/:userById',  async function(ctx) {
  await ctx.userById.remove();
  ctx.body = 'ok';
})

//---Socket Communication-----//
let io = socketIO(server);

io.on('connection', socketioJwt.authorize({
  secret: jwtsecret,
  timeout: 15000
})).on('authenticated', function (socket) {

  console.log('this is the name from the JWT: ' + socket.decoded_token.login);

  socket.on("clientEvent", (data) => {
    console.log(data);
  })
});
