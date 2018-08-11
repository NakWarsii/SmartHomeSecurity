var createError = require('http-errors');
var express = require('express');
const mongoose = require("mongoose")
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var routDevices = require('./routes/devices');
const config = require("./config/database")//requiring database folder
var subscrib = require('./subscribe_post');

/**
 * Create public and private keys of client and store them in file
 */
const rsaWrapper = require('./crypto/rsa-wrapper');
rsaWrapper.generateIfRequired('server');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/device', routDevices);
app.use('/subscribe', subscrib);


//database connect
mongoose.connect(config.database)

//connection checking
mongoose.connection.on('connected', () => {
  console.log("connected to mongodb" + config.database);

})

//database error checking
mongoose.connection.on('err', (err) => {
  console.log("database error" + err);
})

// //server starting
const port= 4003
app.listen(port, () => {
  console.log("server working on port no:" + port)
})

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});


module.exports = app;
