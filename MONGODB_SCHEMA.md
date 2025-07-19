# MongoDB Schema Documentation

## Database: `scoring-system`

### Collections

#### 1. `users`
Stores user/team information.

```javascript
{
  _id: ObjectId,
  id: String,           // User ID (string format)
  username: String,     // Unique username
  password: String,     // Hashed password
  role: String,         // 'admin' or 'user'
  teamName: String,     // Display name
  coins: Number,        // Current coins
  score: Number         // Current score
}
```

**Indexes:**
- `{ username: 1 }` (unique)
- `{ id: 1 }`

#### 2. `countries`
Stores available countries for purchase.

```javascript
{
  _id: ObjectId,
  id: String,           // Country ID
  name: String,         // Country name
  cost: Number,         // Purchase cost
  owner: String,        // User ID of owner (null if unowned)
  score: Number         // Points value
}
```

**Indexes:**
- `{ id: 1 }`

#### 3. `inventories`
Stores user card inventories.

```javascript
{
  _id: ObjectId,
  userId: String,       // User ID
  createdAt: Date,      // When inventory was created
  items: [              // Array of cards
    {
      id: String,       // Card ID
      name: String,     // Card name
      type: String,     // 'luck', 'attack', 'alliance'
      effect: String,   // Card description
      obtainedAt: Date  // When card was obtained
    }
  ]
}
```

**Indexes:**
- `{ userId: 1 }`

#### 4. `notifications` ⭐ **NEW**
Stores all user notifications with MongoDB optimization.

```javascript
{
  _id: ObjectId,
  id: String,           // Notification ID (string format)
  userId: String,       // User ID (for user-specific notifications)
  type: String,         // Notification type:
                        // - 'coins-updated'
                        // - 'score-updated'
                        // - 'spin'
                        // - 'country-purchased'
                        // - 'global'
                        // - 'scoreboard-update'
                        // - 'promo-code'
                        // - 'card-received'
                        // - 'card-used'
  message: String,      // Notification message
  timestamp: String,    // ISO timestamp
  read: Boolean,        // Whether user has read it
  readAt: Date,         // When it was marked as read
  // Additional fields for specific types:
  teamName: String,     // For admin notifications
  cardName: String,     // For card-related notifications
  cardType: String,     // For card-related notifications
  selectedTeam: String, // For card usage notifications
  description: String   // For card usage notifications
}
```

**Indexes:**
- `{ timestamp: -1 }` (for sorting by newest first)
- `{ userId: 1 }` (for user-specific queries)
- `{ userId: 1, read: 1 }` (for unread count queries)
- `{ type: 1 }` (for type-based queries)

#### 5. `promoCodes`
Stores promotional codes.

```javascript
{
  _id: ObjectId,
  id: String,           // Promo code ID
  code: String,         // Promo code string
  teamId: String,       // User ID
  discount: Number,     // Discount percentage
  used: Boolean,        // Whether code has been used
  createdAt: Date,      // When code was created
  usedAt: Date          // When code was used
}
```

**Indexes:**
- `{ code: 1, teamId: 1 }`

## MongoDB Functions

### Notification Management Functions

#### `addNotification(notification)`
Adds a new notification to the database.

#### `getUserNotifications(userId)`
Gets all notifications for a specific user (including global ones).

#### `getUnreadNotificationsCount(userId)`
Gets the count of unread notifications for a user.

#### `markNotificationAsRead(notificationId, userId)`
Marks a specific notification as read.

#### `markAllNotificationsAsRead(userId)`
Marks all notifications for a user as read.

#### `deleteOldNotifications(daysOld)`
Deletes notifications older than specified days (cleanup function).

## Performance Optimizations

### Indexes
- **Compound indexes** for efficient user-specific queries
- **Timestamp index** for sorting by date
- **Type index** for filtering by notification type

### Query Optimization
- **User-specific queries** use `userId` index
- **Unread count** uses compound `{ userId: 1, read: 1 }` index
- **Sorting** uses `{ timestamp: -1 }` index

### Automatic Cleanup
- **Scheduled cleanup** runs daily at 2 AM
- **30-day retention** for old notifications
- **Automatic deletion** of expired notifications

## API Endpoints

### User Endpoints
- `GET /api/notifications` - Get user notifications
- `GET /api/notifications/unread-count` - Get unread count
- `POST /api/notifications/:id/read` - Mark as read
- `POST /api/notifications/read-all` - Mark all as read

### Admin Endpoints
- `GET /api/admin/notifications` - Get all notifications
- `DELETE /api/admin/notifications/cleanup` - Manual cleanup

## Benefits of MongoDB Implementation

### 1. **Scalability**
- Handles large numbers of notifications efficiently
- Indexed queries for fast retrieval
- Automatic cleanup prevents database bloat

### 2. **Performance**
- Optimized indexes for common queries
- Efficient user-specific filtering
- Fast unread count calculations

### 3. **Reliability**
- Persistent storage across server restarts
- Automatic backup and recovery
- Data consistency with proper indexing

### 4. **Flexibility**
- Schema-less design allows for easy modifications
- Support for complex queries and aggregations
- Easy to add new notification types

### 5. **Maintenance**
- Automatic cleanup of old data
- Index optimization for query performance
- Easy monitoring and debugging 