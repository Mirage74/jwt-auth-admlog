const mongoUriBuilder = require('mongo-uri-builder')
const mongoose = require('mongoose');
const {DBUser, DBPass, DBhost, DBport, DBName} = require('./config-mongo')
mongoose.Promise = Promise;

const beautifyUnique = require('mongoose-beautiful-unique-validation');

mongoose.plugin(beautifyUnique);
mongoose.set('debug', true);

mongoose.plugin(schema => {
  if (!schema.options.toObject) {
    schema.options.toObject = {};
  }

  if (schema.options.toObject.transform == undefined) {
    schema.options.toObject.transform = (doc, ret) => { delete ret.__v; return ret; };
    schema.options.toObject.transform = (doc, ret) => { delete ret.createdAt; return ret; };
    schema.options.toObject.transform = (doc, ret) => { delete ret.updatedAt; return ret; };


  }

});



const connectionString = mongoUriBuilder({
  username: encodeURIComponent(DBUser),
  password: encodeURIComponent(DBPass),
  host: DBhost,
  port: DBport,
  database: DBName
});

mongoose.set('useCreateIndex', true)
mongoose.connect(connectionString, {useNewUrlParser: true })


module.exports = mongoose;
