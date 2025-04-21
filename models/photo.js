const photoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  url: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  height: Number, // no longer required
  width: Number,  // no longer required
  createdAt: { type: Date, default: Date.now }
});
