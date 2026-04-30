package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2"
)

// TestTypoIsSilentlyIgnoredAndLoadPolicyReloads проверяет два утверждения сразу:
//
//  1. Casbin не валидирует содержимое политик. Если в policy.csv опечатка
//     ("aice" вместо "alice"), Enforce для настоящей "alice" вернёт false
//     БЕЗ ошибки — просто молча. Это и есть тот самый коварный кейс при отладке.
//
//  2. После правки файла перезапускать процесс не нужно: достаточно вызвать
//     e.LoadPolicy(), и Casbin перечитает политику из адаптера.
//     Тот же самый Enforcer без пересоздания начнёт давать новый ответ.
func TestTypoIsSilentlyIgnoredAndLoadPolicyReloads(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "model.conf")
	policyPath := filepath.Join(dir, "policy.csv")

	model := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	if err := os.WriteFile(modelPath, []byte(model), 0o600); err != nil {
		t.Fatalf("write model: %v", err)
	}

	// Стартуем с опечаткой: aice вместо alice.
	broken := []byte("p, aice, /posts, read\n")
	if err := os.WriteFile(policyPath, broken, 0o600); err != nil {
		t.Fatalf("write broken policy: %v", err)
	}

	e, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}

	// (1) Проверяем, что Enforce возвращает (false, nil), а не ошибку.
	//     Если бы Casbin валидировал политики, ошибка вылезла бы здесь.
	ok, err := e.Enforce("alice", "/posts", "read")
	if err != nil {
		t.Fatalf("Enforce вернул ошибку, ожидался тихий false: %v", err)
	}
	if ok {
		t.Fatal(`Enforce("alice","/posts","read") = true до правки опечатки; ожидался false`)
	}

	// (2) Правим policy.csv "на лету" — без пересоздания Enforcer.
	fixed := []byte("p, alice, /posts, read\n")
	if err := os.WriteFile(policyPath, fixed, 0o600); err != nil {
		t.Fatalf("rewrite policy: %v", err)
	}

	// Без LoadPolicy старый кэш правил всё ещё в силе:
	// Enforcer не следит за файлом сам.
	ok, err = e.Enforce("alice", "/posts", "read")
	if err != nil {
		t.Fatalf("enforce до LoadPolicy: %v", err)
	}
	if ok {
		t.Fatal("Enforce увидел изменения файла без LoadPolicy — этого быть не должно")
	}

	// А теперь явно перечитываем политику.
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	ok, err = e.Enforce("alice", "/posts", "read")
	if err != nil {
		t.Fatalf("enforce после LoadPolicy: %v", err)
	}
	if !ok {
		t.Fatal(`Enforce("alice","/posts","read") = false после LoadPolicy; ожидался true — ` +
			`значит политика не перечиталась`)
	}
}
