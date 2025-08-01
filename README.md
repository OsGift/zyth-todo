# zyth-todo

Zyth-Tasker | Your Ultimate Todo App
Zyth-Tasker is a comprehensive task management application designed to help users organize their daily tasks efficiently. With features like user authentication, detailed task management including checklists, and insightful dashboard analytics, Zyth-Tasker aims to streamline your productivity.

Features
User Authentication: Secure signup, login, and a robust "forgot password" and "reset password" flow.

Task Management:

Create, view, edit, and delete tasks.

Assign priority (High, Medium, Low) and due dates.

Track task status (Pending, In Progress, Completed).

Add detailed descriptions and notes on completion/non-completion.

Interactive Checklists: Break down tasks into smaller, manageable checklist items.

Automated Status Updates: Task status automatically updates based on checklist completion (e.g., task becomes "Completed" when all checklist items are done; task becomes "In Progress" if a completed task's checklist item is unchecked).

LIFO Task Display: Newest tasks appear at the top of your list for immediate visibility.

Advanced Filtering & Search:

Filter tasks by date (Today, Yesterday, This Week, This Month, This Year, Custom Range).

Filter by Priority (High, Medium, Low, All).

Filter by Status (Pending, In Progress, Completed, All).

Search tasks by title or description using keywords.

Instant Filtering: Filters apply immediately as you select them, no need for an "Apply" button.

Dashboard Analytics:

Visualize your productivity with charts showing tasks by priority and task volume over time.

Key performance indicators (KPIs) including total tasks, completed tasks, in-progress tasks, and average completion rate.

Quick Insights: Get immediate summaries of tasks due today, overdue tasks, and your last completed task.

CSV Export: Export your task data for external analysis or backup.

Responsive Design: Optimized for seamless experience across desktop and mobile devices, featuring a drawer-style sidebar on smaller screens.

Modern Notifications: Non-intrusive toast messages for user feedback instead of traditional browser alerts.

Technologies Used
Frontend
HTML5: Structure of the web application.

Tailwind CSS: Utility-first CSS framework for rapid UI development and responsive design.

JavaScript (Vanilla JS): Core logic for dynamic interactions, API calls, and DOM manipulation.

Chart.js: For rendering interactive data visualizations on the dashboard.

Backend
Go (Golang): High-performance backend API.

Gin Web Framework: Fast and flexible HTTP web framework for Go.

MongoDB: NoSQL database for storing user and task data.

MongoDB Go Driver: Official Go driver for MongoDB.

Bcrypt: For secure password hashing.

SMTP (net/smtp): For sending password reset emails.

Godotenv: For loading environment variables.

Setup and Installation
Prerequisites
Go (Golang) installed (version 1.18 or higher recommended)

MongoDB installed and running

Node.js and npm (for Tailwind CSS CLI, if you want to customize Tailwind, otherwise CDN is used)

Backend Setup
Clone the repository:

git clone <your-repo-url>
cd Zyth-Tasker-backend # Or wherever your main.go is located

Install Go dependencies:

go mod tidy

Create a .env file in the root of your backend directory and add the following environment variables:

MONGO_URI="mongodb://localhost:27017" # Or your MongoDB connection string
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_USER="your_email@example.com"
SMTP_PASSWORD="your_email_password"

Note: SMTP settings are optional for core app functionality but required for the "Forgot Password" feature.

Run the backend server:

go run main.go

The backend server will start on http://localhost:8080.

Frontend Setup
The frontend is a single HTML file (index.html) that uses CDN links for Tailwind CSS and Chart.js, so no separate build process is strictly required for basic usage.

Ensure index.html is in the same directory as your main.go or in a static folder that your Go server is configured to serve.

Open your web browser and navigate to http://localhost:8080.

Usage
Sign Up / Log In: Register a new account or log in with existing credentials.

My Tasks:

Click "Add Task" to create a new task. Fill in details like title, description, priority, and due date. You can also add checklist items.

Tasks are displayed in a "Last In, First Out" order.

Use the filter options (Date, Priority, Status, Keyword Search) at the top to narrow down your tasks.

Click the expand arrow on a task card to view its full details and checklist.

Mark checklist items as complete or in-progress. The task's overall status will update automatically.

Manually change a task's status using the "Set Task In Progress" or "Mark Task as Completed" buttons.

Edit or delete tasks using the respective icons.

Dashboard:

Navigate to the "Dashboard" view from the sidebar.

View analytics on your task completion, distribution by priority, and trends over time.

Check "Quick Insights" for a snapshot of your current task load.

Use the dashboard filter to view analytics for different time periods.

Click "Export CSV" to download your task data.

Contributing
Feel free to fork the repository, open issues, or submit pull requests.

License
[Specify your license here, e.g., MIT License]
