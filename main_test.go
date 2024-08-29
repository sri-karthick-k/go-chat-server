package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func generateRandomUser() User {
	rand.Seed(time.Now().UnixNano())
	username := "user" + strconv.Itoa(rand.Intn(1000000))
	email := username + "@example.com"
	password := "password"
	return User{Username: username, Email: email, Password: password}
}

var count int

func BenchmarkRegister(b *testing.B) {
	for i := 0; i < 10000; i++ {
		user := generateRandomUser()
		userJSON, _ := json.Marshal(user)

		resp, err := http.Post("http://localhost:5000/register", "application/json", bytes.NewBuffer(userJSON))
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func connectWebSocket(url string) (*websocket.Conn, error) {
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	return conn, err
}

func sendMessage(conn *websocket.Conn, msg Msg) error {
	messageJSON, _ := json.Marshal(msg)
	return conn.WriteMessage(websocket.TextMessage, messageJSON)
}

// go test -bench=BenchmarkWebSocketCommunication -count=5 -benchmem - runs 30 times
func BenchmarkWebSocketCommunication(b *testing.B) {
	url := "ws://localhost:5000/ws"

	// Connect two users
	user1Conn, err := connectWebSocket(url)
	if err != nil {
		b.Fatal("Failed to connect user 1:", err)
	}
	defer user1Conn.Close()

	user2Conn, err := connectWebSocket(url)
	if err != nil {
		b.Fatal("Failed to connect user 2:", err)
	}
	defer user2Conn.Close()

	if err := sendMessage(user1Conn, Msg{SenderUsername: "user439702", ReceiverUsername: "user118746", Content: ""}); err != nil {
		b.Fatal("Failed to send message from user 1:", err)
	}

	if err := sendMessage(user1Conn, Msg{SenderUsername: "user118746", ReceiverUsername: "user439702", Content: ""}); err != nil {
		b.Fatal("Failed to send message from user 1:", err)
	}
	// Simulate sending messages between the two users

	msg := Msg{
		SenderUsername:   "user439702",
		ReceiverUsername: "user118746",
		Content:          fmt.Sprintf("Hello from user1, message %d", count),
	}
	count++

	// Send message from user 1 to user 2
	if err := sendMessage(user1Conn, msg); err != nil {
		b.Fatal("Failed to send message from user 1:", err)
	}
}
