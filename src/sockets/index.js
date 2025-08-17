const Notification = require('../models/Notification');

// Track connected users
const connectedUsers = new Map();

// Initialize Socket.IO
function initializeSocket(io) {
  io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Handle user authentication
    socket.on('authenticate', async (token) => {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (user) {
          // Store user's socket ID
          connectedUsers.set(user.id, {
            socketId: socket.id,
            userId: user.id,
            username: user.username
          });
          
          // Join user to their own room for private messages
          socket.join(`user_${user.id}`);
          
          // Notify user of successful connection
          socket.emit('authenticated', { success: true });
          
          console.log(`User authenticated: ${user.username} (${user.id})`);
        }
      } catch (error) {
        console.error('Socket authentication error:', error);
        socket.emit('error', { message: 'Authentication failed' });
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      // Remove user from connected users
      for (const [userId, userData] of connectedUsers.entries()) {
        if (userData.socketId === socket.id) {
          connectedUsers.delete(userId);
          console.log(`User disconnected: ${userData.username} (${userId})`);
          break;
        }
      }
    });

    // Handle joining a room (e.g., for notifications)
    socket.on('joinRoom', (room) => {
      socket.join(room);
      console.log(`Socket ${socket.id} joined room ${room}`);
    });

    // Handle leaving a room
    socket.on('leaveRoom', (room) => {
      socket.leave(room);
      console.log(`Socket ${socket.id} left room ${room}`);
    });
  });

  return io;
}

// Helper function to send notification to a specific user
function sendToUser(userId, event, data) {
  const user = connectedUsers.get(userId);
  if (user) {
    io.to(user.socketId).emit(event, data);
  }
}

// Helper function to broadcast to all connected users
function broadcast(event, data) {
  io.emit(event, data);
}

// Helper function to send to a specific room
function sendToRoom(room, event, data) {
  io.to(room).emit(event, data);
}

module.exports = {
  initializeSocket,
  sendToUser,
  broadcast,
  sendToRoom,
  connectedUsers
};
