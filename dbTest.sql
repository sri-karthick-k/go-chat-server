CREATE DATABASE chatDB;

USE chatDB;

-- Users table to store user information
CREATE TABLE Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

-- Messages table to store messages
CREATE TABLE Messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    body TEXT,
    media BLOB,
    modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    sender_id INT,
    receiver_id INT,
    FOREIGN KEY (sender_id) REFERENCES Users(id),
    FOREIGN KEY (receiver_id) REFERENCES Users(id)
);