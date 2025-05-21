package main

import (
	"log"

	db "github.com/usama1031/golang-csrf/db"
	server "github.com/usama1031/golang-csrf/server"
	jwt "github.com/usama1031/golang-csrf/server/middleware/jwt"
)

var host = "localhost"
var port = "8020"

func main() {
	db.InitDB()
	jwtErr := jwt.InitJWT()

	if jwtErr != nil {
		log.Println("Error initializing the JWT")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)

	if serverErr != nil {
		log.Println("Error starting the server")
		log.Fatal(serverErr)
	}
}
