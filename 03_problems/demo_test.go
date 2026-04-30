package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2"
)

// --- Раздел 5: проблемы ---

func TestTypos(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/broken_policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	// В политике "alce" вместо "alice" и "raed" вместо "read"
	tests := []struct {
		name          string
		sub, obj, act string
		want          bool
	}{
		{"alice /admin read — опечатка 'alce'", "alice", "/admin", "read", false},
		{"charlie /dashboard read — опечатка 'raed'", "charlie", "/dashboard", "read", false},
		{"bob /dashboard read — тут всё норм", "bob", "/dashboard", "read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Enforce(tt.sub, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("Enforce(%q, %q, %q) ошибка: %v", tt.sub, tt.obj, tt.act, err)
			}
			if got != tt.want {
				t.Errorf("Enforce(%q, %q, %q) = %v, ожидалось %v",
					tt.sub, tt.obj, tt.act, got, tt.want)
			}
		})
	}
}

func TestExtraSpaces(t *testing.T) {
	// В broken_policy.csv: "g,  charlie, viewer" — два пробела перед charlie
	e, err := casbin.NewEnforcer("config/model.conf", "config/broken_policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	// Casbin CSV-адаптер тримит пробелы, поэтому "  charlie" → "charlie"
	roles, _ := e.GetRolesForUser("charlie")
	if len(roles) != 1 || roles[0] != "viewer" {
		t.Errorf("роли 'charlie': %v, ожидалось [viewer] (CSV-адаптер тримит пробелы)", roles)
	}

	t.Logf("роли 'charlie': %v", roles)

	// а вот поиск с пробелом ничего не найдёт
	roles, _ = e.GetRolesForUser(" charlie")
	if len(roles) != 0 {
		t.Errorf("роли ' charlie': %v, ожидалось [] (нет такого пользователя)", roles)
	}

	t.Logf("роли ' charlie': %v", roles)
}

func TestPolicyWhitespace(t *testing.T) {
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
	cases := []struct {
		name   string
		policy string
		want   bool
	}{
		{"один пробел после запятой", "p, alice, /posts, read\n", true},
		{"два пробела после запятой", "p,  alice, /posts, read\n", true},
		{"таб после запятой", "p,\talice, /posts, read\n", true},
		{"пробел перед запятой", "p, alice ,/posts,read\n", false}, // ← ловушка
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mp := filepath.Join(dir, "model.conf")
			pp := filepath.Join(dir, "policy.csv")
			os.WriteFile(mp, []byte(model), 0o600)
			os.WriteFile(pp, []byte(tc.policy), 0o600)

			e, err := casbin.NewEnforcer(mp, pp)
			if err != nil {
				t.Fatalf("new enforcer: %v", err)
			}
			got, err := e.Enforce("alice", "/posts", "read")
			if err != nil {
				t.Fatalf("enforce: %v", err)
			}

			if got != tc.want {
				policy, _ := e.GetPolicy()
				t.Fatalf("Enforce = %v, want %v (политика сохранена как %q)",
					got, tc.want, policy)
			}
		})
	}
}

func TestWrongArgumentOrder(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	// правильно: sub, obj, act
	ok, err := e.Enforce("alice", "/admin", "read")
	if err != nil {
		t.Fatalf("Enforce ошибка: %v", err)
	}
	if !ok {
		t.Error("правильный порядок (sub, obj, act) должен дать true")
	}

	// obj и act перепутаны
	ok, err = e.Enforce("alice", "read", "/admin")
	if err != nil {
		t.Fatalf("Enforce ошибка: %v", err)
	}
	if ok {
		t.Error("перепутанный порядок (sub, act, obj) должен дать false")
	}
}

func TestBrokenMatcher(t *testing.T) {
	// В модели "p.sbu" вместо "p.sub"
	e, err := casbin.NewEnforcer("config/broken_model.conf", "config/policy.csv")
	if err != nil {
		t.Logf("NewEnforcer вернул ошибку (ожидаемо): %v", err)
		return
	}

	ok, err := e.Enforce("alice", "/admin", "read")
	if err != nil {
		t.Logf("Enforce вернул ошибку (ожидаемо): %v", err)
		return
	}
	if ok {
		t.Error("сломанный матчер не должен разрешать доступ")
	}
}

func TestLogging(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	e.EnableLog(true)

	_, err = e.Enforce("alice", "/dashboard", "read")
	if err != nil {
		t.Errorf("Enforce(alice, /dashboard, read) ошибка: %v", err)
	}

	_, err = e.Enforce("bob", "/admin", "read")
	if err != nil {
		t.Errorf("Enforce(bob, /admin, read) ошибка: %v", err)
	}

	e.EnableLog(false)
}

// --- Раздел 6: практики ---

func TestEnforceEx(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	tests := []struct {
		name          string
		sub, obj, act string
		wantOk        bool
		wantReason    bool // true — ожидаем непустой reason
	}{
		{"alice /admin read", "alice", "/admin", "read", true, true},
		{"bob /dashboard write", "bob", "/dashboard", "write", true, true},
		{"charlie /admin read", "charlie", "/admin", "read", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason, err := e.EnforceEx(tt.sub, tt.obj, tt.act)
			if err != nil {
				t.Fatalf("EnforceEx(%q, %q, %q) ошибка: %v", tt.sub, tt.obj, tt.act, err)
			}
			if ok != tt.wantOk {
				t.Errorf("EnforceEx(%q, %q, %q) ok=%v, ожидалось %v",
					tt.sub, tt.obj, tt.act, ok, tt.wantOk)
			}
			hasReason := len(reason) > 0
			if hasReason != tt.wantReason {
				t.Errorf("EnforceEx(%q, %q, %q) reason=%v, ожидалось непустой=%v",
					tt.sub, tt.obj, tt.act, reason, tt.wantReason)
			}
			if hasReason {
				t.Logf("  matched rule: %v", reason)
			}
		})
	}
}

func TestDynamicPolicies(t *testing.T) {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		t.Fatalf("не удалось создать enforcer: %v", err)
	}

	// dave без роли — доступ запрещён
	assertEnforce(t, e, "dave", "/dashboard", "read", false)

	// назначаем dave роль viewer
	if _, err := e.AddGroupingPolicy("dave", "viewer"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}
	assertEnforce(t, e, "dave", "/dashboard", "read", true)

	// меняем роль dave на editor
	if _, err := e.RemoveGroupingPolicy("dave", "viewer"); err != nil {
		t.Fatalf("RemoveGroupingPolicy: %v", err)
	}
	if _, err := e.AddGroupingPolicy("dave", "editor"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}
	assertEnforce(t, e, "dave", "/dashboard", "write", true)

	// добавляем новую политику для editor
	if _, err := e.AddPolicy("editor", "/reports", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	assertEnforce(t, e, "dave", "/reports", "read", true)
	assertEnforce(t, e, "bob", "/reports", "read", true)
}

// assertEnforce — хелпер для проверки результата Enforce
func assertEnforce(t *testing.T, e *casbin.Enforcer, sub, obj, act string, want bool) {
	t.Helper()
	got, err := e.Enforce(sub, obj, act)
	if err != nil {
		t.Fatalf("Enforce(%q, %q, %q) ошибка: %v", sub, obj, act, err)
	}
	if got != want {
		t.Errorf("Enforce(%q, %q, %q) = %v, ожидалось %v", sub, obj, act, got, want)
	}
}
