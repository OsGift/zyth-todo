package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
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
	FirstName         string             `json:"first_name,omitempty" bson:"first_name,omitempty"`
	LastName          string             `json:"last_name,omitempty" bson:"last_name,omitempty"`
	ProfilePictureURL string             `json:"profile_picture_url,omitempty" bson:"profile_picture_url,omitempty"`
	CreatedAt         time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt         time.Time          `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	ResetToken        string             `json:"-" bson:"reset_token,omitempty"`
	ResetTokenExpires time.Time          `json:"-" bson:"reset_token_expires,omitempty"`
}

// Resource represents a learning resource
type Resource struct {
	Name string `json:"name,omitempty" bson:"name,omitempty"`
	URL  string `json:"url,omitempty" bson:"url,omitempty"`
}

// Learning represents a single learning goal/entry
type Learning struct {
	ID              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	UserID          primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	Title           string             `json:"title,omitempty" bson:"title,omitempty"`
	Category        string             `json:"category,omitempty" bson:"category,omitempty"` // e.g., "Programming", "Design", "Language", "Skill"
	Status          string             `json:"status,omitempty" bson:"status,omitempty"`     // "Planned", "In Progress", "Completed", "Dropped"
	StartDate       time.Time          `json:"start_date,omitempty" bson:"start_date,omitempty"`
	CompletionDate  *time.Time         `json:"completion_date,omitempty" bson:"completion_date,omitempty"` // Nullable
	Resources       []Resource         `json:"resources,omitempty" bson:"resources,omitempty"`
	Notes           string             `json:"notes,omitempty" bson:"notes,omitempty"`
	Progress        float64            `json:"progress,omitempty" bson:"progress,omitempty"`                 // 0-100%
	Impact          string             `json:"impact,omitempty" bson:"impact,omitempty"`                     // How this learning helped
	KeyMilestones   []string           `json:"key_milestones,omitempty" bson:"key_milestones,omitempty"`     // New field for learning
	ChallengesFaced string             `json:"challenges_faced,omitempty" bson:"challenges_faced,omitempty"` // New field for learning
	NextSteps       string             `json:"next_steps,omitempty" bson:"next_steps,omitempty"`             // New field for learning
	CreatedAt       time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt       time.Time          `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
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

	cloudinaryCloudName string
	cloudinaryAPIKey    string
	cloudinaryAPISecret string
	cld                 *cloudinary.Cloudinary
)

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

	// Initialize Cloudinary
	var err error
	cld, err = cloudinary.NewFromParams(cloudinaryCloudName, cloudinaryAPIKey, cloudinaryAPISecret)
	if err != nil {
		log.Fatalf("Failed to initialize Cloudinary: %v", err)
	}

	// --- DATABASE CONNECTION ---
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

		// --- USER PROFILE ROUTES ---
		profile := api.Group("/profile")
		profile.Use(AuthMiddleware())
		{
			profile.GET("/", getProfile)
			profile.PUT("/", updateProfile)
			profile.POST("/upload-picture", uploadProfilePicture)
		}

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

		// --- LEARNING ROUTES ---
		learnings := api.Group("/learnings")
		learnings.Use(AuthMiddleware())
		{
			learnings.POST("/", createLearning)
			learnings.GET("/", getLearnings)
			learnings.GET("/:id", getLearning)
			learnings.PUT("/:id", updateLearning)
			learnings.DELETE("/:id", deleteLearning)
			learnings.PUT("/:id/status", updateLearningStatus)
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
	_ = godotenv.Load()
	smtpHost = os.Getenv("SMTP_HOST")
	smtpPort = os.Getenv("SMTP_PORT")
	smtpUser = os.Getenv("SMTP_USER")
	smtpPassword = os.Getenv("SMTP_PASSWORD")

	cloudinaryCloudName = os.Getenv("CLOUDINARY_CLOUD_NAME")
	cloudinaryAPIKey = os.Getenv("CLOUDINARY_API_KEY")
	cloudinaryAPISecret = os.Getenv("CLOUDINARY_API_SECRET")
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
	user.CreatedAt = time.Now() // Add CreatedAt for user for consistency
	user.UpdatedAt = time.Now() // Add UpdatedAt for user for consistency

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

// --- USER PROFILE HANDLERS ---
func getProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	objID := userID.(primitive.ObjectID)

	collection := client.Database("todoapp").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User profile not found"})
		return
	}

	user.Password = "" // Don't send password hash to frontend
	c.JSON(http.StatusOK, user)
}

func updateProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	objID := userID.(primitive.ObjectID)

	var userUpdate User
	if err := c.ShouldBindJSON(&userUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := client.Database("todoapp").Collection("users")

	// Only update allowed fields
	updateFields := bson.M{
		"first_name":          userUpdate.FirstName,
		"last_name":           userUpdate.LastName,
		"profile_picture_url": userUpdate.ProfilePictureURL,
		"updated_at":          time.Now(),
	}

	update := bson.M{"$set": updateFields}
	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

func uploadProfilePicture(c *gin.Context) {
	userID, _ := c.Get("user_id")
	objID := userID.(primitive.ObjectID)

	file, err := c.FormFile("profile_picture")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer func(src multipart.File) {
		err := src.Close()
		if err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}(src)

	// Upload image to Cloudinary
	uploadResult, err := cld.Upload.Upload(context.TODO(), src, uploader.UploadParams{
		Folder:   "zyth-tasker/profile_pictures",
		PublicID: objID.Hex(), // Use user ID as public ID for easy management
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to upload to Cloudinary: %v", err)})
		return
	}

	// Update user's profile picture URL in MongoDB
	collection := client.Database("todoapp").Collection("users")
	update := bson.M{
		"$set": bson.M{
			"profile_picture_url": uploadResult.SecureURL,
			"updated_at":          time.Now(),
		},
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save profile picture URL"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile picture uploaded successfully", "url": uploadResult.SecureURL})
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

	// Default status if not provided or invalid
	if todo.Status == "" {
		todo.Status = "Pending"
	}

	// Calculate completion percentage and update status based on checklist items
	todo.CompletionPercentage, todo.Status = calculateCompletionAndStatus(todo.ChecklistItems, todo.Status)

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

	// Date Filter
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
		filter["created_at"] = bson.M{"$gte": startDate, "$lt": endDate}
	}

	// Priority Filter
	priorityFilter := c.Query("priority")
	if priorityFilter != "" && priorityFilter != "all" {
		filter["priority"] = priorityFilter
	}

	// Status Filter
	statusFilter := c.Query("status")
	if statusFilter != "" && statusFilter != "all" {
		filter["status"] = statusFilter
	}

	// Keyword Search
	keyword := c.Query("keyword")
	if keyword != "" {
		// Case-insensitive search on Title and Description
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": primitive.Regex{Pattern: keyword, Options: "i"}}},
			{"description": bson.M{"$regex": primitive.Regex{Pattern: keyword, Options: "i"}}},
		}
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

	collection := client.Database("todoapp").Collection("todos")
	var existingTodo Todo
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&existingTodo)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	// Apply incoming updates to existing todo
	existingTodo.Title = todoUpdate.Title
	existingTodo.Description = todoUpdate.Description
	existingTodo.Priority = todoUpdate.Priority
	existingTodo.DueDate = todoUpdate.DueDate
	existingTodo.NotesOnCompletion = todoUpdate.NotesOnCompletion
	existingTodo.NotesOnNonCompletion = todoUpdate.NotesOnNonCompletion
	existingTodo.ChecklistItems = todoUpdate.ChecklistItems // Update checklist items directly

	// Handle status and completion percentage based on checklist items or manual status
	if todoUpdate.Status == "Completed" {
		// If task is manually set to completed, mark all checklist items as completed
		for i := range existingTodo.ChecklistItems {
			existingTodo.ChecklistItems[i].Completed = true
			existingTodo.ChecklistItems[i].InProgress = false
		}
		existingTodo.Status = "Completed"
		existingTodo.CompletionPercentage = 100
	} else {
		// Otherwise, calculate status and percentage based on checklist items
		existingTodo.CompletionPercentage, existingTodo.Status = calculateCompletionAndStatus(existingTodo.ChecklistItems, existingTodo.Status)
	}

	existingTodo.UpdatedAt = time.Now()

	update := bson.M{
		"$set": existingTodo, // Set the entire updated struct
	}

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

	// Apply new status
	todo.Status = payload.Status

	// Adjust checklist items and completion percentage based on new status
	if todo.Status == "Completed" {
		for i := range todo.ChecklistItems {
			todo.ChecklistItems[i].Completed = true
			todo.ChecklistItems[i].InProgress = false
		}
		todo.CompletionPercentage = 100
	} else {
		// If status is changed from Completed to something else, reset checklist items
		// and recalculate based on their current state.
		// If it was manually set to In Progress or Pending, we don't force checklist changes.
		if len(todo.ChecklistItems) > 0 && payload.Status != "Completed" {
			// If task was completed and now is not, uncheck all checklist items
			if todo.Status == "Completed" { // This check is against the *new* status, which is not "Completed"
				for i := range todo.ChecklistItems {
					todo.ChecklistItems[i].Completed = false
					todo.ChecklistItems[i].InProgress = false
				}
			}
		}
		todo.CompletionPercentage, _ = calculateCompletionAndStatus(todo.ChecklistItems, todo.Status) // Recalculate based on current checklist state
	}

	todo.UpdatedAt = time.Now()

	update := bson.M{
		"$set": bson.M{
			"status":                todo.Status,
			"completion_percentage": todo.CompletionPercentage,
			"checklist_items":       todo.ChecklistItems, // Ensure checklist items are saved
			"updated_at":            todo.UpdatedAt,
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

// --- LEARNING HANDLERS ---
func createLearning(c *gin.Context) {
	var learning Learning
	if err := c.ShouldBindJSON(&learning); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	learning.UserID = userID.(primitive.ObjectID)
	learning.ID = primitive.NewObjectID()
	learning.CreatedAt = time.Now()
	learning.UpdatedAt = time.Now()

	if learning.Status == "" {
		learning.Status = "Planned" // Default status for new learning
	}

	collection := client.Database("todoapp").Collection("learnings")
	_, err := collection.InsertOne(context.TODO(), learning)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create learning entry"})
		return
	}

	c.JSON(http.StatusCreated, learning)
}

func getLearnings(c *gin.Context) {
	userID, _ := c.Get("user_id")
	filter := bson.M{"user_id": userID}

	// Category Filter
	categoryFilter := c.Query("category")
	if categoryFilter != "" && categoryFilter != "all" {
		filter["category"] = categoryFilter
	}

	// Status Filter
	statusFilter := c.Query("status")
	if statusFilter != "" && statusFilter != "all" {
		filter["status"] = statusFilter
	}

	// Keyword Search
	keyword := c.Query("keyword")
	if keyword != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": primitive.Regex{Pattern: keyword, Options: "i"}}},
			{"notes": bson.M{"$regex": primitive.Regex{Pattern: keyword, Options: "i"}}},
		}
	}

	collection := client.Database("todoapp").Collection("learnings")
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve learning entries"})
		return
	}
	defer cursor.Close(context.TODO())

	var learnings []Learning
	if err = cursor.All(context.TODO(), &learnings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode learning entries"})
		return
	}
	if learnings == nil {
		learnings = []Learning{}
	}

	c.JSON(http.StatusOK, learnings)
}

func getLearning(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	collection := client.Database("todoapp").Collection("learnings")
	var learning Learning
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&learning)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found"})
		return
	}

	c.JSON(http.StatusOK, learning)
}

func updateLearning(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	var learningUpdate Learning
	if err := c.ShouldBindJSON(&learningUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := client.Database("todoapp").Collection("learnings")
	var existingLearning Learning
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&existingLearning)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found"})
		return
	}

	// Apply incoming updates to existing learning
	existingLearning.Title = learningUpdate.Title
	existingLearning.Category = learningUpdate.Category
	existingLearning.Status = learningUpdate.Status
	existingLearning.StartDate = learningUpdate.StartDate
	existingLearning.CompletionDate = learningUpdate.CompletionDate
	existingLearning.Resources = learningUpdate.Resources
	existingLearning.Notes = learningUpdate.Notes
	existingLearning.Progress = learningUpdate.Progress
	existingLearning.Impact = learningUpdate.Impact
	existingLearning.KeyMilestones = learningUpdate.KeyMilestones
	existingLearning.ChallengesFaced = learningUpdate.ChallengesFaced
	existingLearning.NextSteps = learningUpdate.NextSteps

	existingLearning.UpdatedAt = time.Now()

	update := bson.M{
		"$set": existingLearning,
	}

	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update learning entry"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Learning entry updated successfully"})
}

func updateLearningStatus(c *gin.Context) {
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

	collection := client.Database("todoapp").Collection("learnings")
	var learning Learning
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}).Decode(&learning)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found"})
		return
	}

	learning.Status = payload.Status
	learning.UpdatedAt = time.Now()

	// If status is completed, set completion date and progress to 100
	switch learning.Status {
	case "Completed":
		now := time.Now()
		learning.CompletionDate = &now
		learning.Progress = 100
	case "Dropped":
		// If dropped, clear completion date and set progress to 0
		learning.CompletionDate = nil
		learning.Progress = 0
	}

	update := bson.M{
		"$set": bson.M{
			"status":          learning.Status,
			"updated_at":      learning.UpdatedAt,
			"completion_date": learning.CompletionDate,
			"progress":        learning.Progress,
		},
	}

	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": objID, "user_id": userID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update learning status"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found or not owned by user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Learning status updated successfully"})
}

func deleteLearning(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}
	userID, _ := c.Get("user_id")

	collection := client.Database("todoapp").Collection("learnings")
	result, err := collection.DeleteOne(context.TODO(), bson.M{"_id": objID, "user_id": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete learning entry"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Learning entry not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Learning entry deleted successfully"})
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

	if filterPeriod != "all" && !startDate.IsZero() {
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

// calculateCompletionAndStatus determines the completion percentage and status based on checklist items.
// It takes the current checklist items and the existing status as input.
// It returns the calculated completion percentage and the new status.
func calculateCompletionAndStatus(checklist []ChecklistItem, currentStatus string) (float64, string) {
	if len(checklist) == 0 {
		// If no checklist items, status is determined by currentStatus (e.g., manually set)
		if currentStatus == "Completed" {
			return 100, "Completed"
		}
		return 0, currentStatus // Maintain current status if no checklist
	}

	completedCount := 0
	inProgressCount := 0
	for _, item := range checklist {
		if item.Completed {
			completedCount++
		}
		if item.InProgress && !item.Completed { // An item can be in progress but not yet completed
			inProgressCount++
		}
	}

	percentage := (float64(completedCount) / float64(len(checklist))) * 100

	newStatus := "Pending"
	if completedCount == len(checklist) {
		newStatus = "Completed"
	} else if inProgressCount > 0 || completedCount > 0 {
		// If at least one item is in progress, or some are completed but not all
		newStatus = "In Progress"
	}

	return percentage, newStatus
}

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
