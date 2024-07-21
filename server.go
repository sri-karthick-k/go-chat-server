package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/olahol/melody"
	"golang.org/x/crypto/bcrypt"
)

type Msg struct {
	SenderUsername   string `json:"sender_username"`
	ReceiverUsername string `json:"receiver_username"`
	Content          string `json:"content"`
}

type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Message struct {
	Id         int       `json:"id"`
	Body       string    `json:"body"`
	Media      []byte    `json:"media"`
	Modified   time.Time `json:"modified"`
	SenderId   int       `json:"sender_id"`
	ReceiverId int       `json:"receiver_id"`
}

func main() {
	router := gin.Default()
	m := melody.New()

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Authorization, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	dbURL := "sri:Spartan03@/chatDBTest?charset=utf8"
	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		panic(err)
	}

	router.GET("/", func(c *gin.Context) {
		http.ServeFile(c.Writer, c.Request, "./public/index.html")
	})

	// Registration endpoint
	router.POST("/register", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		if user.Username == "" || user.Email == "" || user.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide username, password, and email"})
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		var id int
		err = db.QueryRow("SELECT id FROM Users WHERE username=?", user.Username).Scan(&id)
		if err == sql.ErrNoRows {
			insertStmt, err := db.Prepare("INSERT INTO Users (username, email, password) VALUES (?, ?, ?)")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare statement"})
				return
			}
			_, err = insertStmt.Exec(user.Username, user.Email, hashedPassword)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
				return
			}
			db.QueryRow("SELECT id FROM Users WHERE username=?", user.Username).Scan(&id)
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
			return
		}

		user.Id = id
		user.Password = string(hashedPassword)
		c.JSON(200, gin.H{"user": user})
	})

	// Login endpoint
	router.POST("/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		if user.Username == "" || user.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide username and password"})
			return
		}

		var id int
		var hashedPassword string
		err := db.QueryRow("SELECT id, password FROM Users WHERE username=?", user.Username).Scan(&id, &hashedPassword)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// Compare hashed password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		c.JSON(200, gin.H{"user": User{Id: id, Username: user.Username}})
	})

	router.GET("/chatUsers", func(c *gin.Context) {
		userId := c.Query("userId")
		var users []User

		if userId == "" {
			fmt.Println("No userID")
			return
		}

		query := `
			SELECT DISTINCT u.id, u.username
			FROM Users u
			JOIN Messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
			WHERE u.id != ? AND (m.sender_id = ? OR m.receiver_id = ?)

		`

		rows, err := db.Query(query, userId, userId, userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}
		defer rows.Close()

		for rows.Next() {
			var user User
			err := rows.Scan(&user.Id, &user.Username)
			if err != nil {
				fmt.Println("Failed to scan user:", err)
				continue
			}
			users = append(users, user)
		}

		c.JSON(200, gin.H{"users": users})
	})

	// Fetch all messages
	router.GET("/messages", func(c *gin.Context) {
		senderId := c.Query("senderId")
		receiverId := c.Query("receiverId")

		var allMessages []Message
		rows, err := db.Query("SELECT id, body, media, modified, sender_id, receiver_id FROM Messages WHERE sender_id = ? AND receiver_id = ? ORDER BY modified ASC", senderId, receiverId)
		if err != nil {
			fmt.Println("Failed to query messages:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
			return
		}
		defer rows.Close()

		for rows.Next() {
			var message Message
			var modified []uint8
			err := rows.Scan(&message.Id, &message.Body, &message.Media, &modified, &message.SenderId, &message.ReceiverId)
			if err != nil {
				fmt.Println("Failed to scan message:", err)
				continue
			}

			message.Modified, err = time.Parse("2006-01-02 15:04:05", string(modified))
			if err != nil {
				fmt.Println("Failed to parse modified timestamp:", err)
				continue
			}

			allMessages = append(allMessages, message)
		}

		if err = rows.Err(); err != nil {
			fmt.Println("Error occurred while iterating over messages:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while iterating over messages"})
			return
		}

		c.JSON(200, gin.H{"messages": allMessages})
	})

	// WebSocket endpoint
	router.GET("/ws", func(c *gin.Context) {
		m.HandleRequest(c.Writer, c.Request)
	})

	m.HandleConnect(func(s *melody.Session) {
		s.Set("username", "")
	})

	m.HandleMessage(func(s *melody.Session, message []byte) {
		var msgData Msg
		err := json.Unmarshal(message, &msgData)
		if err != nil {
			fmt.Println(err)
			return
		}

		if msgData.Content == "" {
			s.Set("username", msgData.SenderUsername)
			return
		}

		var senderId, receiverId int
		err = db.QueryRow("SELECT id FROM Users WHERE username=?", msgData.SenderUsername).Scan(&senderId)
		if err != nil {
			fmt.Println("Error finding sender:", err)
			return
		}
		err = db.QueryRow("SELECT id FROM Users WHERE username=?", msgData.ReceiverUsername).Scan(&receiverId)
		if err != nil {
			fmt.Println("Error finding receiver:", err)
			return
		}

		insertStmt, err := db.Prepare("INSERT INTO Messages (body, media, modified, sender_id, receiver_id) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			fmt.Println("Error preparing statement:", err)
			return
		}
		_, err = insertStmt.Exec(msgData.Content, nil, time.Now(), senderId, receiverId)
		if err != nil {
			fmt.Println("Error inserting message:", err)
			return
		}

		messageResponse := map[string]interface{}{
			"body":       msgData.Content,
			"senderId":   senderId,
			"receiverId": receiverId,
		}

		msgJSON, _ := json.Marshal(messageResponse)

		m.BroadcastFilter(msgJSON, func(q *melody.Session) bool {
			username, _ := q.Get("username")
			return username == msgData.ReceiverUsername
		})
	})

	router.Run(":5000")
}
