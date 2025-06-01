require('dotenv').config();
const mongoose = require('mongoose');
const Photo = require('../models/photo');
const User = require('../models/user');
const elasticsearchService = require('../services/elasticsearchService');

async function initializeElasticsearch() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Initialize Elasticsearch indices
    await elasticsearchService.initializeIndex();
    console.log('✅ Elasticsearch indices initialized');

    // Get all photos from MongoDB
    const photos = await Photo.find().lean();
    console.log(`📸 Found ${photos.length} photos to index`);

    // Get all users from MongoDB
    const users = await User.find().lean();
    console.log(`👥 Found ${users.length} users to index`);

    // Reindex all photos
    const photosSuccess = await elasticsearchService.reindexAllPhotos(photos);
    if (photosSuccess) {
      console.log('✅ All photos indexed successfully');
    } else {
      console.error('❌ Failed to index some photos');
    }

    // Reindex all users
    const usersSuccess = await elasticsearchService.reindexAllUsers(users);
    if (usersSuccess) {
      console.log('✅ All users indexed successfully');
    } else {
      console.error('❌ Failed to index some users');
    }
  } catch (error) {
    console.error('❌ Initialization error:', error);
  } finally {
    await mongoose.disconnect();
    process.exit();
  }
}

initializeElasticsearch(); 