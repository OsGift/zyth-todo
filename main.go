package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// --- DATABASE CONNECTION ---
var client *mongo.Client

// --- MODELS ---

// ChecklistItem represents a single item in a todo's checklist
type ChecklistItem struct {
	Description string `json:"description,omitempty" bson:"description,omitempty"`
	Completed   bool   `json:"completed,omitempty" bson:"completed,omitempty"`
	InProgress  bool   `json:"in_progress,omitempty" bson:"in_progress,omitempty"`
}

// Todo represents a single todo task
type Todo struct {
	ID                   primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	UserID               primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	Title                string             `json:"title,omitempty" bson:"title,omitempty"`
	Description          string             `json:"description,omitempty" bson:"description,omitempty"`
	Priority             string             `json:"priority,omitempty" bson:"priority,omitempty"` // "High", "Medium", "Low"
	DueDate              time.Time          `json:"due_date,omitempty" bson:"due_date,omitempty"`
	Status               string             `json:"status,omitempty" bson:"status,omitempty"` // "Pending", "In Progress", "Completed"
	CompletionPercentage float64            `json:"completion_percentage,omitempty" bson:"completion_percentage,omitempty"`
	NotesOnCompletion    string             `json:"notes_on_completion,omitempty" bson:"notes_on_completion,omitempty"`
	NotesOnNonCompletion string             `json:"notes_on_non_completion,omitempty" bson:"notes_on_non_completion,omitempty"`
	ChecklistItems       []ChecklistItem    `json:"checklist_items,omitempty" bson:"checklist_items,omitempty"`
	CreatedAt            time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt            time.Time          `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
}

// User represents a user of the application
type User struct {
	ID                primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Email             string             `json:"email,omitempty" bson:"email,omitempty"`
	Password          string             `json:"password,omitempty" bson:"password,omitempty"`
	ResetToken        string             `json:"-" bson:"reset_token,omitempty"`
	ResetTokenExpires time.Time          `json:"-" bson:"reset_token_expires,omitempty"`
}

// AnalyticsData represents the structure for dashboard analytics
type AnalyticsData struct {
	TotalTasks            int                      `json:"total_tasks"`
	CompletedTasks        int                      `json:"completed_tasks"`
	InProgressTasks       int                      `json:"in_progress_tasks"`
	PendingTasks          int                      `json:"pending_tasks"`
	AverageCompletionRate float64                  `json:"average_completion_rate"`
	TasksByPriority       map[string]int           `json:"tasks_by_priority"`
	CompletedByPriority   map[string]int           `json:"completed_by_priority"`
	TasksOverTime         []map[string]interface{} `json:"tasks_over_time"`
}

// --- CONFIG ---
var (
	smtpHost     string
	smtpPort     string
	smtpUser     string
	smtpPassword string
	// frontendURL is no longer needed as the reset URL is generated dynamically
)

const emailTemplate = `
<!DOCTYPE html>
<html>
<head>
<style>
    body { font-family: Arial, sans-serif; }
    .container { padding: 20px; }
    .button { background-color: #4CAF50; color: white; padding: 14px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; border-radius: 12px; }
</style>
</head>
<body>
<div class="container">
    <h2>Password Reset Request</h2>
    <p>You are receiving this email because a password reset request was made for your account.</p>
    <p>Please click the button below to reset your password. This link will expire in 1 hour.</p>
    <a href="{{.URL}}" class="button">Reset Password</a>
    <p>If you did not request a password reset, please ignore this email.</p>
</div>
</body>
</html>
`

func loadTemplate(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --- MAIN FUNCTION ---
func main() {
	_ = godotenv.Load() // Load environment variables from .env file
	// --- LOAD CONFIG ---
	loadConfig()

	// --- DATABASE CONNECTION ---
	var err error
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
		log.Println("MONGO_URI environment variable not set, using default 'mongodb://localhost:27017'")
	}

	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")

	// --- GIN ROUTER SETUP ---
	router := gin.Default()
	router.Use(cors.Default())

	// --- API ROUTES ---
	api := router.Group("/api")
	{
		// --- AUTH ROUTES ---
		api.POST("/signup", signup)
		api.POST("/login", login)
		api.POST("/forgot-password", forgotPassword)
		api.POST("/reset-password", resetPassword)

		// --- TODO ROUTES ---
		todos := api.Group("/todos")
		todos.Use(AuthMiddleware())
		{
			todos.POST("/", createTodo)
			todos.GET("/", getTodos)
			todos.GET("/:id", getTodo)
			todos.PUT("/:id", updateTodo)
			todos.DELETE("/:id", deleteTodo)
			todos.PUT("/:id/status", updateTodoStatus)
		}

		// --- DASHBOARD ROUTES ---
		dashboard := api.Group("/dashboard")
		dashboard.Use(AuthMiddleware())
		{
			dashboard.GET("/analytics", getAnalytics)
			dashboard.GET("/export", exportAnalytics)
		}
	}

	// --- STATIC FILE SERVING ---
	// Serve index.html for the root path
	router.StaticFile("/", "./index.html")
	// Serve index.html for all other routes (SPA fallback)
	router.NoRoute(func(c *gin.Context) {
		c.File("./index.html")
	})

	// --- START SERVER ---
	log.Println("Starting server on :8080")
	router.Run(":8080")
}

func loadConfig() {
	smtpHost = os.Getenv("SMTP_HOST")
	smtpPort = os.Getenv("SMTP_PORT")
	smtpUser = os.Getenv("SMTP_USER")
	smtpPassword = os.Getenv("SMTP_PASSWORD")
	// frontendURL is no longer needed as the reset URL is generated dynamically
}

// --- MIDDLEWARE ---

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetHeader("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}
		objID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return
		}
		c.Set("user_id", objID)
		c.Next()
	}
}

// --- HANDLERS ---

// --- AUTH HANDLERS ---
func signup(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := client.Database("todoapp").Collection("users")
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)
	user.ID = primitive.NewObjectID()

	_, err = collection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	user.Password = ""
	c.JSON(http.StatusCreated, user)
}

func login(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := client.Database("todoapp").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": credentials.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	user.Password = ""
	c.JSON(http.StatusOK, user)
}

func forgotPassword(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	collection := client.Database("todoapp").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": payload.Email}).Decode(&user)
	if err != nil {
		// Don't reveal if user exists.
		c.JSON(http.StatusOK, gin.H{"message": "If a user with that email exists, a password reset link has been sent."})
		return
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Update user in DB
	update := bson.M{
		"$set": bson.M{
			"reset_token":         token,
			"reset_token_expires": time.Now().Add(1 * time.Hour),
		},
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save reset token"})
		return
	}

	// Send email
	// The resetURL is constructed dynamically based on the current request's host and scheme.
	host := c.Request.Host
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	resetURL := fmt.Sprintf("%s://%s/reset-password?reset_token=%s", scheme, host, token)

	templateContent, err := loadTemplate("templates/reset_password.html")
	if err != nil {
		log.Printf("Failed to load email template: %v", err)
		// Fallback: don't block user experience
	} else {
		err = sendEmail(user.Email, "Password Reset", templateContent, map[string]string{"URL": resetURL})
		if err != nil {
			log.Printf("Failed to send password reset email to %s: %v", user.Email, err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "If a user with that email exists, a password reset link has been sent."})
}

func resetPassword(c *gin.Context) {
	var payload struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token and new password are required"})
		return
	}

	collection := client.Database("todoapp").Collection("users")
	var user User
	filter := bson.M{
		"reset_token":         payload.Token,
		"reset_token_expires": bson.M{"$gt": time.Now()},
	}
	err := collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired password reset token"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"password": string(hashedPassword),
		},
		"$unset": bson.M{
			"reset_token":         "",
			"reset_token_expires": "",
		},
	}

	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully."})
}

// --- TODO HANDLERS ---
func createTodo(c *gin.Context) {
	var todo Todo
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	todo.UserID = userID.(primitive.ObjectID)
	todo.ID = primitive.NewObjectID()
	todo.CreatedAt = time.Now()
	todo.UpdatedAt = time.Now()
	todo.Status = "Pending"
	todo.CompletionPercentage = 0

	if len(todo.ChecklistItems) > 0 {
		completedCount := 0
		for _, item := range todo.ChecklistItems {
			if item.Completed {
				completedCount++
			}
		}
		todo.CompletionPercentage = (float64(completedCount) / float64(len(todo.ChecklistItems))) * 100
	}

	collection := client.Database("todoapp").Collection("todos")
	_, err := collection.InsertOne(context.TODO(), todo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create todo"})
		return
	}

	c.JSON(http.StatusCreated, todo)
}

func getTodos(c *gin.Context) {
	userID, _ := c.Get("user_id")
	filter := bson.M{"user_id": userID}

	dateFilter := c.Query("filter")
	now := time.Now()
	var startDate, endDate time.Time

	switch dateFilter {
	case "today":
		startDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		endDate = startDate.Add(24 * time.Hour)
	case "yesterday":
		yesterday := now.AddDate(0, 0, -1)
		startDate = time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, now.Location())
		endDate = startDate.Add(24 * time.Hour)
	case "this_week":
		weekday := int(now.Weekday())
		startDate = time.Date(now.Year(), now.Month(), now.Day()-weekday, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 0, 7)
	case "this_month":
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 1, 0)
	case "this_year":
		startDate = time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(1, 0, 0)
	case "custom":
		startStr := c.Query("start_date")
		endStr := c.Query("end_date")
		var err error
		startDate, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start_date format, use YYYY-MM-DD"})
			return
		}
		endDate, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end_date format, use YYYY-MM-DD"})
			return
		}
		endDate = endDate.Add(24 * time.Hour)
	}

	if !startDate.IsZero() && !endDate.IsZero() {
		filter["due_date"] = bson.M{"$gte": startDate, "$lt": endDate}
	}

	collection := client.Database("todoapp").Collection("todos")
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve todos"})
		return
	}
	defer cursor.Close(context.TODO())

	var todos []Todo
	if err = cursor.All(context.TODO(), &todos); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode todos"})
		return
	}
	if todos == nil {
		todos = []Todo{}
	}

	c.JSON(http.StatusOK, todos)
}

func getTodo(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	collection := client.Database("todoapp").Collection("todos")
	var todo Todo
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&todo)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	c.JSON(http.StatusOK, todo)
}

func updateTodo(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	var todoUpdate Todo
	if err := c.ShouldBindJSON(&todoUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Calculate completion percentage based on checklist items
	if len(todoUpdate.ChecklistItems) > 0 {
		completedCount := 0
		for _, item := range todoUpdate.ChecklistItems {
			if item.Completed {
				completedCount++
			}
		}
		todoUpdate.CompletionPercentage = (float64(completedCount) / float64(len(todoUpdate.ChecklistItems))) * 100
	} else {
		// If no checklist items, base completion on task status
		if todoUpdate.Status == "Completed" {
			todoUpdate.CompletionPercentage = 100
		} else {
			todoUpdate.CompletionPercentage = 0
		}
	}

	update := bson.M{
		"$set": bson.M{
			"title":                   todoUpdate.Title,
			"description":             todoUpdate.Description,
			"priority":                todoUpdate.Priority,
			"due_date":                todoUpdate.DueDate,
			"status":                  todoUpdate.Status,
			"completion_percentage":   todoUpdate.CompletionPercentage,
			"notes_on_completion":     todoUpdate.NotesOnCompletion,
			"notes_on_non_completion": todoUpdate.NotesOnNonCompletion,
			"checklist_items":         todoUpdate.ChecklistItems,
			"updated_at":              time.Now(),
		},
	}

	collection := client.Database("todoapp").Collection("todos")
	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update todo"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Todo updated successfully"})
}

func updateTodoStatus(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	var payload struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	collection := client.Database("todoapp").Collection("todos")
	var todo Todo
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&todo)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	completionPercentage := todo.CompletionPercentage
	if payload.Status == "Completed" {
		completionPercentage = 100
	} else if payload.Status == "In Progress" {
		// If setting task to In Progress, and it has checklist items, don't force 0%
		// Otherwise, if no checklist, set to 0% if it was completed before.
		if len(todo.ChecklistItems) == 0 && todo.Status == "Completed" {
			completionPercentage = 0
		}
	} else if payload.Status == "Pending" {
		completionPercentage = 0
	}

	update := bson.M{
		"$set": bson.M{
			"status":                payload.Status,
			"completion_percentage": completionPercentage,
			"updated_at":            time.Now(),
		},
	}

	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update todo status"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found or not owned by user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Todo status updated successfully"})
}

func deleteTodo(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	collection := client.Database("todoapp").Collection("todos")
	result, err := collection.DeleteOne(context.TODO(), bson.M{"_id": objID, "user_id": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete todo"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Todo deleted successfully"})
}

// --- DASHBOARD HANDLERS ---
func getAnalytics(c *gin.Context) {
	userID, _ := c.Get("user_id")
	filterPeriod := c.Query("filter")

	filter := bson.M{"user_id": userID}

	now := time.Now()
	var startDate, endDate time.Time

	switch filterPeriod {
	case "this_week":
		weekday := int(now.Weekday())
		startDate = time.Date(now.Year(), now.Month(), now.Day()-weekday, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 0, 7)
	case "this_month":
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 1, 0)
	case "this_quarter":
		quarter := (int(now.Month())-1)/3 + 1
		startDate = time.Date(now.Year(), time.Month((quarter-1)*3+1), 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(0, 3, 0)
	case "this_year":
		startDate = time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
		endDate = startDate.AddDate(1, 0, 0)
	case "custom":
		startStr := c.Query("start_date")
		endStr := c.Query("end_date")
		var err error
		startDate, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start_date format, use YYYY-MM-DD"})
			return
		}
		endDate, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end_date format, use YYYY-MM-DD"})
			return
		}
		endDate = endDate.Add(24 * time.Hour)
	}

	if !startDate.IsZero() && !endDate.IsZero() {
		filter["created_at"] = bson.M{"$gte": startDate, "$lt": endDate}
	}

	collection := client.Database("todoapp").Collection("todos")
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve todos for analytics"})
		return
	}
	defer cursor.Close(context.TODO())

	var todos []Todo
	if err = cursor.All(context.TODO(), &todos); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode todos for analytics"})
		return
	}

	analytics := AnalyticsData{
		TasksByPriority:     make(map[string]int),
		CompletedByPriority: make(map[string]int),
		TasksOverTime:       make([]map[string]interface{}, 0),
	}
	var totalCompletionPercentage float64
	tasksOverTimeMap := make(map[string]map[string]int)

	for _, todo := range todos {
		analytics.TotalTasks++
		totalCompletionPercentage += todo.CompletionPercentage

		switch todo.Status {
		case "Completed":
			analytics.CompletedTasks++
		case "In Progress":
			analytics.InProgressTasks++
		default: // Pending
			analytics.PendingTasks++
		}

		analytics.TasksByPriority[todo.Priority]++
		if todo.Status == "Completed" {
			analytics.CompletedByPriority[todo.Priority]++
		}

		dateStr := todo.CreatedAt.Format("2006-01-02")
		if _, ok := tasksOverTimeMap[dateStr]; !ok {
			tasksOverTimeMap[dateStr] = map[string]int{"completed": 0, "total": 0}
		}
		tasksOverTimeMap[dateStr]["total"]++
		if todo.Status == "Completed" {
			tasksOverTimeMap[dateStr]["completed"]++
		}
	}

	if analytics.TotalTasks > 0 {
		analytics.AverageCompletionRate = totalCompletionPercentage / float64(analytics.TotalTasks)
	}

	for date, data := range tasksOverTimeMap {
		analytics.TasksOverTime = append(analytics.TasksOverTime, map[string]interface{}{
			"date":      date,
			"completed": data["completed"],
			"total":     data["total"],
		})
	}

	c.JSON(http.StatusOK, analytics)
}

func exportAnalytics(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("todoapp").Collection("todos")
	cursor, err := collection.Find(context.TODO(), bson.M{"user_id": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data for export"})
		return
	}
	defer cursor.Close(context.TODO())

	var todos []Todo
	if err = cursor.All(context.TODO(), &todos); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode data for export"})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", `attachment; filename="todo_report.csv"`)

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	headers := []string{
		"Title", "Description", "Priority", "DueDate", "Status",
		"CompletionPercentage", "NotesOnCompletion", "NotesOnNonCompletion",
		"CreatedAt", "UpdatedAt",
	}
	if err := writer.Write(headers); err != nil {
		log.Println("Cannot write header to csv", err)
	}

	for _, todo := range todos {
		row := []string{
			todo.Title,
			todo.Description,
			todo.Priority,
			todo.DueDate.Format("2006-01-02"),
			todo.Status,
			fmt.Sprintf("%.2f", todo.CompletionPercentage),
			todo.NotesOnCompletion,
			todo.NotesOnNonCompletion,
			todo.CreatedAt.Format("2006-01-02 15:04:05"),
			todo.UpdatedAt.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(row); err != nil {
			log.Println("Cannot write row to csv", err)
		}
	}
}

// --- HELPERS ---
func sendEmail(to, subject, bodyTemplate string, data map[string]string) error {
	if smtpHost == "" {
		log.Println("SMTP not configured, skipping email send.")
		return nil // Don't return error if not configured, just log it.
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

	t, err := template.New("email").Parse(bodyTemplate)
	if err != nil {
		return err
	}

	var body strings.Builder
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n"
	body.Write([]byte(fmt.Sprintf("Subject: %s\n%s\n\n", subject, mimeHeaders)))

	err = t.Execute(&body, data)
	if err != nil {
		return err
	}
	return smtp.SendMail(addr, auth, smtpUser, []string{to}, []byte(body.String()))
}
