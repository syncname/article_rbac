package main

import (
	"fmt"
	casbin "github.com/casbin/casbin/v2"
	"log"
	"net/http"
)

func main() {

	enforcer, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatalf("не удалось создать enforcer: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		fmt.Fprintf(w, "Добро пожаловать на дашборд, %s!", user)
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		fmt.Fprintf(w, "Админ-панель. Привет, %s!", user)
	})

	// Оборачиваем весь mux в middleware
	handler := AuthorizationMiddleware(enforcer)(mux)

	log.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
