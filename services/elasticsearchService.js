const { Client } = require('@elastic/elasticsearch');

// Configure Elasticsearch client for Bonsai
const client = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
  ssl: {
    rejectUnauthorized: false
  }
});

// Test connection on startup
async function testConnection() {
  try {
    const health = await client.cluster.health();
    console.log('✅ Elasticsearch connection successful:', health.status);
    return true;
  } catch (error) {
    console.error('❌ Elasticsearch connection failed:', error.message);
    return false;
  }
}

const PHOTO_INDEX = 'photos';
const USER_INDEX = 'users';

// Initialize Elasticsearch indices
async function initializeIndex() {
  try {
    // Initialize photos index
    const photoIndexExists = await client.indices.exists({ index: PHOTO_INDEX });
    if (!photoIndexExists) {
      await client.indices.create({
        index: PHOTO_INDEX,
        body: {
          mappings: {
            _doc: {
              properties: {
                title: { type: 'text', analyzer: 'standard' },
                description: { type: 'text', analyzer: 'standard' },
                location: { type: 'keyword' },
                userId: { type: 'keyword' },
                createdAt: { type: 'date' },
                url: { type: 'keyword' }
              }
            }
          }
        }
      });
      console.log('✅ Photos index created successfully');
    }

    // Initialize users index
    const userIndexExists = await client.indices.exists({ index: USER_INDEX });
    if (!userIndexExists) {
      await client.indices.create({
        index: USER_INDEX,
        body: {
          mappings: {
            _doc: {
              properties: {
                username: { type: 'text', analyzer: 'standard', fields: { keyword: { type: 'keyword' } } },
                name: { type: 'text', analyzer: 'standard' },
                bio: { type: 'text', analyzer: 'standard' },
                email: { type: 'keyword' },
                profilePic: { type: 'keyword' },
                createdAt: { type: 'date' }
              }
            }
          }
        }
      });
      console.log('✅ Users index created successfully');
    }
  } catch (error) {
    console.error('❌ Failed to initialize Elasticsearch:', error);
  }
}

// Index a photo
async function indexPhoto(photo) {
  try {
    await client.index({
      index: PHOTO_INDEX,
      type: '_doc',
      id: photo._id.toString(),
      body: {
        title: photo.title,
        description: photo.description,
        location: photo.location,
        userId: photo.userId.toString(),
        createdAt: photo.createdAt,
        url: photo.url
      }
    });
    return true;
  } catch (error) {
    console.error('Failed to index photo:', error);
    return false;
  }
}

// Index a user
async function indexUser(user) {
  try {
    await client.index({
      index: USER_INDEX,
      type: '_doc',
      id: user._id.toString(),
      body: {
        username: user.username,
        name: user.name || '',
        bio: user.bio || '',
        email: user.email,
        profilePic: user.profilePic || '',
        createdAt: user.createdAt
      }
    });
    return true;
  } catch (error) {
    console.error('Failed to index user:', error);
    return false;
  }
}

// Search photos
async function searchPhotos({ query, location, sortBy = 'recent', page = 1, limit = 12 }) {
  const skip = (page - 1) * limit;

  // Build search query
  const searchQuery = {
    bool: {
      must: []
    }
  };

  if (query && query.trim()) {
    searchQuery.bool.must.push({
      multi_match: {
        query: query.trim(),
        fields: ['title^2', 'description'],
        fuzziness: 'AUTO'
      }
    });
  }

  if (location && location !== 'all') {
    searchQuery.bool.must.push({
      term: { location: location }
    });
  }

  let sort = [];
  switch (sortBy) {
    case 'recent':
      sort.push({ createdAt: 'desc' });
      break;
    case 'oldest':
      sort.push({ createdAt: 'asc' });
      break;
    case 'title':
      sort.push({ 'title.keyword': 'asc' });
      break;
    default:
      sort.push({ createdAt: 'desc' });
  }

  try {
    const response = await client.search({
      index: PHOTO_INDEX,
      type: '_doc',
      body: {
        query: searchQuery,
        sort,
        from: skip,
        size: limit
      }
    });

    const hits = response.hits.hits;
    const total = response.hits.total;

    return {
      photos: hits.map(hit => ({
        _id: hit._id,
        ...hit._source
      })),
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: skip + hits.length < total
    };
  } catch (error) {
    console.error('Search error:', error);
    throw error;
  }
}

// Search users
async function searchUsers({ query, page = 1, limit = 12 }) {
  const skip = (page - 1) * limit;

  const searchQuery = {
    bool: {
      should: [
        {
          multi_match: {
            query: query.trim(),
            fields: ['username^3', 'name^2', 'bio'],
            fuzziness: 'AUTO',
            operator: 'or'
          }
        }
      ],
      minimum_should_match: 1
    }
  };

  try {
    const response = await client.search({
      index: USER_INDEX,
      type: '_doc',
      body: {
        query: searchQuery,
        sort: [
          { '_score': 'desc' },
          { 'username.keyword': 'asc' }
        ],
        from: skip,
        size: limit
      }
    });

    const hits = response.hits.hits;
    const total = response.hits.total;

    return {
      users: hits.map(hit => ({
        _id: hit._id,
        ...hit._source
      })),
      total,
      page,
      totalPages: Math.ceil(total / limit),
      hasMore: skip + hits.length < total
    };
  } catch (error) {
    console.error('User search error:', error);
    throw error;
  }
}

// Delete photo from index
async function deletePhoto(photoId) {
  try {
    await client.delete({
      index: PHOTO_INDEX,
      type: '_doc',
      id: photoId.toString()
    });
    return true;
  } catch (error) {
    console.error('Failed to delete photo from index:', error);
    return false;
  }
}

// Delete user from index
async function deleteUser(userId) {
  try {
    await client.delete({
      index: USER_INDEX,
      type: '_doc',
      id: userId.toString()
    });
    return true;
  } catch (error) {
    console.error('Failed to delete user from index:', error);
    return false;
  }
}

// Reindex all photos
async function reindexAllPhotos(photos) {
  try {
    const indexExists = await client.indices.exists({ index: PHOTO_INDEX });
    if (indexExists) {
      await client.indices.delete({ index: PHOTO_INDEX });
    }

    await initializeIndex();

    const operations = photos.flatMap(photo => [
      { index: { _index: PHOTO_INDEX, _type: '_doc', _id: photo._id.toString() } },
      {
        title: photo.title,
        description: photo.description,
        location: photo.location,
        userId: photo.userId.toString(),
        createdAt: photo.createdAt,
        url: photo.url
      }
    ]);

    if (operations.length > 0) {
      const { errors } = await client.bulk({ refresh: true, body: operations });
      if (errors) {
        console.error('Some photos failed to index');
      }
    }

    return true;
  } catch (error) {
    console.error('Failed to reindex photos:', error);
    return false;
  }
}

// Reindex all users
async function reindexAllUsers(users) {
  try {
    const indexExists = await client.indices.exists({ index: USER_INDEX });
    if (indexExists) {
      await client.indices.delete({ index: USER_INDEX });
    }

    await initializeIndex();

    const operations = users.flatMap(user => [
      { index: { _index: USER_INDEX, _type: '_doc', _id: user._id.toString() } },
      {
        username: user.username,
        name: user.name || '',
        bio: user.bio || '',
        email: user.email,
        profilePic: user.profilePic || '',
        createdAt: user.createdAt
      }
    ]);

    if (operations.length > 0) {
      const { errors } = await client.bulk({ refresh: true, body: operations });
      if (errors) {
        console.error('Some users failed to index');
      }
    }

    return true;
  } catch (error) {
    console.error('Failed to reindex users:', error);
    return false;
  }
}

module.exports = {
  initializeIndex,
  indexPhoto,
  indexUser,
  searchPhotos,
  searchUsers,
  deletePhoto,
  deleteUser,
  reindexAllPhotos,
  reindexAllUsers,
  testConnection
}; 