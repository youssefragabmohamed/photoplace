const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  try {
    const uri = process.env.MONGODB_URI;
    
    // Log the connection string (without password for security)
    const logUri = uri.replace(/\/\/[^:]+:[^@]+@/, '//***:***@');
    console.log('🔗 Connecting to MongoDB:', logUri);
    
    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10
    });
    
    console.log('✅ MongoDB Atlas Connected Successfully');
    console.log('📊 Database:', mongoose.connection.db.databaseName);
    
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to database:', mongoose.connection.db.databaseName);
    });
    
    mongoose.connection.on('error', (err) => {
      console.error('Mongoose connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected');
    });
    
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    process.exit(1);
  }
};

// Close connection on process termination
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});

module.exports = connectDB;