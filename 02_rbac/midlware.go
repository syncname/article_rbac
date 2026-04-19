package main

import (
	"github.com/casbin/casbin/v2"
	"net/http"
)

func AuthorizationMiddleware(enforcer *casbin.Enforcer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// В реальном проекте имя пользователя берётся из токена/сессии.
			// Здесь для простоты — из заголовка.
			user := r.Header.Get("X-User")
			if user == "" {
				http.Error(w, "пользователь не указан", http.StatusUnauthorized)
				return
			}

			// Маппинг HTTP-метода на действие
			act := methodToAction(r.Method)

			ok, err := enforcer.Enforce(user, r.URL.Path, act)
			if err != nil {
				http.Error(w, "ошибка проверки доступа", http.StatusInternalServerError)
				return
			}

			if !ok {
				http.Error(w, "доступ запрещён", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func methodToAction(method string) string {
	switch method {
	case http.MethodGet:
		return "read"
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return "write"
	case http.MethodDelete:
		return "delete"
	default:
		return "read"
	}
}
