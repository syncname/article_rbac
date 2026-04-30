package main

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func TestPolicyEffect(t *testing.T) {
	// 1. Описываем модель
	// e = some(where (p.eft == allow)) — это логическое ИЛИ.
	// Если есть хотя бы один allow, запрос разрешен.
	textModel := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(textModel)
	if err != nil {
		t.Fatalf("Ошибка создания модели: %v", err)
	}

	// 2. Инициализируем Enforcer без адаптера
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("Ошибка инициализации: %v", err)
	}

	// 3. Добавляем политики напрямую
	// Важно: так как в [policy_definition] у нас 4 поля (sub, obj, act, eft),
	// мы передаем 4 аргумента в AddPolicy.
	enforcer.AddPolicy("alice", "/posts", "delete", "deny")
	enforcer.AddPolicy("alice", "/posts", "delete", "allow")
	enforcer.AddPolicy("bob", "/posts", "read", "allow")

	tests := []struct {
		sub    string
		obj    string
		act    string
		expect bool
		msg    string
	}{
		{
			sub:    "alice",
			obj:    "/posts",
			act:    "delete",
			expect: true, // true, потому что есть один allow, который "перекрывает" deny
			msg:    "Должно быть разрешено (эффект 'some allow')",
		},
		{
			sub:    "bob",
			obj:    "/posts",
			act:    "read",
			expect: true,
			msg:    "Обычный доступ разрешен",
		},
		{
			sub:    "charlie",
			obj:    "/posts",
			act:    "read",
			expect: false,
			msg:    "Нет правил — доступ запрещен",
		},
	}

	for _, tt := range tests {
		ok, err := enforcer.Enforce(tt.sub, tt.obj, tt.act)
		if err != nil {
			t.Errorf("Ошибка при проверке %s: %v", tt.sub, err)
			continue
		}
		if ok != tt.expect {
			t.Errorf("Провал [%s]: получили %v, ожидали %v", tt.msg, ok, tt.expect)
		}
	}
}
