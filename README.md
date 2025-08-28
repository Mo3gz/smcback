

This project is more than just a game; it is a professional-grade backend platform created to serve a real-life volunteering camp. As a vital tool for the scoring team leader, this application transforms the chaotic nature of a real-world event into a structured, manageable, and engaging digital experience. It is a testament to how technology can amplify a team leader's impact and bring an organization's vision to life by linking physical camp activities ("faqrāt") directly to a transparent and interactive scoring system.

---

### **Key Features**

* **User & Team Management**: A secure system for handling multiple teams and an admin user, complete with hashed passwords and JWT-based authentication for secure access.
* **Dynamic Live Scoreboard**: A real-time scoreboard that updates instantly using **Socket.IO**, providing a transparent view of team performance for all participants.
* **Activity Scoring System**: Performance in each camp activity ("faqrā") is directly linked to "Kaizen" (virtual currency) and points, providing a precise and objective measure for team evaluation.
* **Virtual Mining System**: Teams can acquire virtual "countries" that generate a passive income of "Kaizen" over time, rewarding strategic long-term planning.
* **Interactive "Spin the Wheel" Mechanic**: A core gameplay loop where participants can spend their "Kaizen" to spin a wheel and win game-changing "cards".
* **Diverse In-Game Cards**: The system supports multiple card types with unique strategic effects, including:
    * **Lucky Cards**: Provide instant "Kaizen" boosts or special privileges like borrowing currency to make purchases.
    * **Game Helper Cards**: Offer secret information about upcoming activities or opponents.
    * **Challenge Cards**: Introduce dynamic, real-time mini-games such as a spiritual MCQ quiz with a 13-second timer.
* **Comprehensive Admin Panel**: A single, powerful dashboard that gives administrators full control over the game:
    * Adjusting team scores and coins.
    * Assigning cards and managing promotional codes.
    * Toggling games on/off and managing country ownership.
    * Monitoring all in-game actions through a detailed, real-time notification feed.
* **Advanced Notification System**: All user and admin notifications are efficiently managed in a dedicated MongoDB collection with optimized indexes for fast querying and real-time updates to ensure all team leaders are immediately aware of crucial events.

---

### **Technical Stack**

This project is built for reliability and scalability using a powerful combination of technologies.

* **Backend Framework**: **Express.js**
* **Database**: **MongoDB**, with a meticulously documented schema and strategic indexes for high performance.
* **Real-time Communication**: **Socket.IO** enables instant updates to the scoreboard, countries, and notifications.
* **Authentication & Security**: User authentication is handled with **JWT** and **bcrypt.js** for secure password hashing.
* **Configuration**: All environment variables are managed with **dotenv** for seamless deployment and security.
* **Development Tools**: **Nodemon** provides a hot-reloading development environment for enhanced productivity.

---

### **Database Architecture**

The MongoDB database is designed for performance and scalability, ensuring the system can handle large numbers of participants.

* **Collections**: The data is organized into logical collections for `users`, `countries`, `inventories`, `notifications`, `promoCodes`, and `gameSettings`.
* **Indexing**: Advanced indexing is implemented on key fields like `username`, `timestamp`, `userId`, and `read` to guarantee that queries are fast and efficient, even with high usage.
* **Performance Optimization**: An automatic cleanup function regularly purges old notifications to maintain database health and performance over time.
