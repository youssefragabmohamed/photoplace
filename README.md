# Photo Marketplace Backend

Backend API for the photo marketplace application built with Express.js and MongoDB.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file based on `.env.example` and fill in your values:
```bash
cp .env.example .env
```

3. Start the development server:
```bash
npm run dev
```

## Available Scripts

- `npm start`: Start the production server
- `npm run dev`: Start the development server with hot reload
- `npm run build`: Install production dependencies

## Environment Variables

- `JWT_SECRET`: Secret key for JWT token generation
- `MONGODB_URI`: MongoDB connection string
- `PORT`: Server port (default: 5000)
- `NODE_ENV`: Environment (development/production)
- `ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins

## API Endpoints

### Authentication
- `POST /api/auth/signup`: Register a new user
- `POST /api/auth/login`: Login user
- `POST /api/auth/logout`: Logout user
- `GET /api/auth/session`: Check session status

### Photos
- `GET /api/photos`: Get all photos
- `POST /api/photos/upload`: Upload a new photo
- `GET /api/photos/user/:userId`: Get user's photos
- `GET /api/photos/saved`: Get saved photos
- `POST /api/photos/save/:photoId`: Save/unsave a photo
- `DELETE /api/photos/:photoId`: Delete a photo
- `GET /api/photos/:photoId`: Get single photo

### Profile
- `GET /api/profile/:userId`: Get user profile
- `PATCH /api/profile/update/:userId`: Update profile
- `POST /api/profile/portfolio/:photoId`: Add to portfolio
- `DELETE /api/profile/portfolio/:photoId`: Remove from portfolio

## File Upload

- Supported formats: JPEG, PNG, GIF, WEBP
- Maximum file size: 10MB
- Files are stored in the `uploads` directory

## Security Features

- JWT authentication
- Rate limiting
- CORS protection
- Helmet security headers
- Input validation
- File type validation
