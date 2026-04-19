package main

import (
	"testing"

	"github.com/casbin/casbin/v2"
)

// Табличные тесты для политик — раздел 6
func TestRBACPolicy(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	tests := []struct {
		name           string
		sub, obj, act  string
		want           bool
	}{
		// alice — admin
		{"admin читает /admin", "alice", "/admin", "read", true},
		{"admin пишет /admin", "alice", "/admin", "write", true},
		{"admin читает /dashboard", "alice", "/dashboard", "read", true},

		// bob — editor
		{"editor читает /dashboard", "bob", "/dashboard", "read", true},
		{"editor пишет /dashboard", "bob", "/dashboard", "write", true},
		{"editor не имеет доступа к /admin", "bob", "/admin", "read", false},

		// charlie — viewer
		{"viewer читает /dashboard", "charlie", "/dashboard", "read", true},
		{"viewer не может писать /dashboard", "charlie", "/dashboard", "write", false},
		{"viewer не имеет доступа к /admin", "charlie", "/admin", "read", false},

		// неизвестный пользователь
		{"без роли — доступ запрещён", "dave", "/dashboard", "read", false},

		// несуществующий ресурс
		{"несуществующий ресурс", "alice", "/secret", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Enforce(tt.sub, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("Enforce(%q, %q, %q) вернул ошибку: %v",
					tt.sub, tt.obj, tt.act, err)
			}
			if got != tt.want {
				t.Errorf("Enforce(%q, %q, %q) = %v, ожидалось %v",
					tt.sub, tt.obj, tt.act, got, tt.want)
			}
		})
	}
}
