package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/olahol/melody"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/bcrypt"
)

var (
	amqpURI  = "amqp://admin:admin@node1:5672/"
	exchange = "chat_exchange"
)

type Msg struct {
	SenderUsername   string `json:"sender_username"`
	ReceiverUsername string `json:"receiver_username"`
	Content          string `json:"content"`
	MediaBase64      string `json:"media_base64,omitempty"`
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

var jwtKey = []byte("secret_key_hehe")

type Claims struct {
	UserId   int    `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateJWT(userId int, username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserId:   userId,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func authenticateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, err := c.Cookie("token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userId", claims.UserId)
		c.Set("username", claims.Username)
		c.Next()
	}
}

func main() {
	router := gin.Default()
	m := melody.New()
	m.Config.MaxMessageSize = 1024 * 1024 * 100

	conn, err := amqp.Dial(amqpURI)
	if err != nil {
		panic("Failed to connect to RabbitMQ")
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		panic("Failed to open a channel")
	}
	defer ch.Close()

	// Declare exchange
	err = ch.ExchangeDeclare(
		exchange, // name
		"direct", // type
		false,    // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to declare an exchange: %v", err))
	}

	// Declare queues
	textQueue, err := ch.QueueDeclare(
		"text_messages", // queue name
		false,           // durable
		false,           // delete when unused
		false,           // exclusive
		false,           // no-wait
		nil,             // arguments
	)
	if err != nil {
		panic("Failed to declare a queue")
	}

	mediaQueue, err := ch.QueueDeclare(
		"media_messages", // queue name
		false,            // durable
		false,            // delete when unused
		false,            // exclusive
		false,            // no-wait
		nil,              // arguments
	)
	if err != nil {
		panic("Failed to declare a queue")
	}

	// Bind queues to the exchange
	err = ch.QueueBind(
		textQueue.Name, // queue name
		"text",         // routing key
		exchange,       // exchange
		false,
		nil,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to bind text queue: %v", err))
	}

	err = ch.QueueBind(
		mediaQueue.Name, // queue name
		"media",         // routing key
		exchange,        // exchange
		false,
		nil,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to bind media queue: %v", err))
	}

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Authorization, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// dbURL := "root:password@tcp(lb:3306)/chatDB?charset=utf8"
	dbURL := "sri:Spartan03@tcp(localhost:3306)/chatDB?charset=utf8"
	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		panic(err)
	}

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
				fmt.Println(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Email already exists"})
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

		tokenString, err := generateJWT(user.Id, user.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT token"})
			return
		}

		// Set the JWT token as an HttpOnly cookie
		c.SetCookie(
			"token",     // Cookie name
			tokenString, // Cookie value
			3600,        // Max age in seconds (1 hour)
			"/",         // Path
			"",          // Domain (empty for current domain)
			true,        // Secure (true if HTTPS)
			true,        // HttpOnly
		)

		c.JSON(200, gin.H{"message": "Register successful", "user": User{Id: id, Username: user.Username}})
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
		fmt.Println(user)
		tokenString, err := generateJWT(id, user.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT token"})
			return
		}

		// Set the JWT token as an HttpOnly cookie
		c.SetCookie(
			"token",     // Cookie name
			tokenString, // Cookie value
			3600,        // Max age in seconds (1 hour)
			"/",         // Path
			"",          // Domain (empty for current domain)
			true,        // Secure (true if HTTPS)
			true,        // HttpOnly
		)

		fmt.Println(user)

		c.JSON(200, gin.H{"message": "Login successful", "user": User{Id: id, Username: user.Username}})
	})

	router.GET("/logout", func(c *gin.Context) {
		// Set the cookie with an expiration date in the past to effectively delete it
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "token",
			Value:    "",
			Expires:  time.Unix(0, 0), // Set the expiration date in the past
			HttpOnly: true,
			Path:     "/",
		})

		// Send a response to indicate the user has been logged out
		c.JSON(http.StatusOK, gin.H{
			"message": "Logged out successfully",
		})
	})

	router.GET("/chatUsers", authenticateJWT(), func(c *gin.Context) {
		userId, exists := c.Get("userId")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		fmt.Println(userId)
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

	router.GET("/userByUsername", authenticateJWT(), func(c *gin.Context) {
		username := c.Query("username")

		var user User
		err := db.QueryRow("SELECT id, username FROM Users WHERE username=?", username).Scan(&user.Id, &user.Username)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		c.JSON(200, gin.H{"user": user})
	})

	// Fetch all messages
	router.GET("/messages", authenticateJWT(), func(c *gin.Context) {
		senderId, exists := c.Get("userId")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		receiverId := c.Query("receiverId")

		if senderId == "" || receiverId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide both senderId and receiverId"})
			return
		}

		var messages []Message

		query := `
		SELECT id, body, media, modified, sender_id, receiver_id
		FROM Messages
		WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
		ORDER BY modified ASC
	`
		rows, err := db.Query(query, senderId, receiverId, receiverId, senderId)
		if err != nil {
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

			messages = append(messages, message)
		}

		c.JSON(200, gin.H{"messages": messages})
	})

	// WebSocket endpoint
	router.GET("/ws", func(c *gin.Context) {
		m.HandleRequest(c.Writer, c.Request)
	})

	m.HandleConnect(func(s *melody.Session) {
		cookie, err := s.Request.Cookie("token")
		if err != nil {
			fmt.Println("Error retrieving token cookie:", err)
			s.Close()
			return
		}
		tokenStr := cookie.Value
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			s.Close()
			return
		}

		s.Set("userId", claims.UserId)
		s.Set("username", claims.Username)
		fmt.Println("New connection established")
	})

	m.HandleMessage(func(s *melody.Session, message []byte) {
		var msgData Msg
		err := json.Unmarshal(message, &msgData)
		if err != nil {
			fmt.Println("Error unmarshalling message:", err)
			return
		}

		if msgData.Content == "" && msgData.MediaBase64 == "" {
			s.Set("username", msgData.SenderUsername)
			return
		}

		if msgData.MediaBase64 != "" {
			// Publish to media queue
			err := ch.Publish(
				exchange,        // exchange
				mediaQueue.Name, // routing key
				false,           // mandatory
				false,           // immediate
				amqp.Publishing{
					ContentType: "text/plain",
					Body:        message,
				},
			)
			if err != nil {
				fmt.Println("Failed to publish message to media queue:", err)
			}
		} else {
			// Publish to text queue
			err := ch.Publish(
				exchange,       // exchange
				textQueue.Name, // routing key
				false,          // mandatory
				false,          // immediate
				amqp.Publishing{
					ContentType: "text/plain",
					Body:        message,
				},
			)
			if err != nil {
				fmt.Println("Failed to publish message to text queue:", err)
			}
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

		var media []byte
		if msgData.MediaBase64 != "" {
			media, err = base64.StdEncoding.DecodeString(msgData.MediaBase64)
			if err != nil {
				fmt.Println("Error decoding base64 media:", err)
				return
			}
		}

		insertStmt, err := db.Prepare("INSERT INTO Messages (body, media, modified, sender_id, receiver_id) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			fmt.Println("Error preparing statement:", err)
			return
		}
		_, err = insertStmt.Exec(msgData.Content, media, time.Now(), senderId, receiverId)
		if err != nil {
			fmt.Println("Error inserting message:", err)
			return
		}

		messageResponse := map[string]interface{}{
			"body":       msgData.Content,
			"senderId":   senderId,
			"receiverId": receiverId,
			"media":      msgData.MediaBase64,
		}

		msgJSON, err := json.Marshal(messageResponse)
		if err != nil {
			fmt.Println("Error marshalling response message:", err)
			return
		}

		fmt.Println("Broadcasting message:", string(msgJSON))

		m.BroadcastFilter(msgJSON, func(q *melody.Session) bool {
			username, _ := q.Get("username")
			return username == msgData.ReceiverUsername || username == msgData.SenderUsername
		})
	})

	router.Run(":5000")
}
