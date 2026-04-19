package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
)

func main() {
	fmt.Println("=== Раздел 5: проблемы ===")
	demo1_Typos()
	demo2_ExtraSpaces()
	demo3_WrongArgumentOrder()
	demo4_BrokenMatcher()
	demo5_Logging()

	fmt.Println("\n=== Раздел 6: практики ===")
	demo6_EnforceEx()
	demo7_DynamicPolicies()
}

func demo1_Typos() {
	fmt.Println("\n-- опечатки в policy.csv --")

	e, err := casbin.NewEnforcer("config/model.conf", "config/broken_policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	// В политике "alce" вместо "alice" и "raed" вместо "read"
	check(e, "alice", "/admin", "read")       // false — опечатка 'alce'
	check(e, "charlie", "/dashboard", "read") // false — опечатка 'raed'
	check(e, "bob", "/dashboard", "read")     // true — тут всё норм
}

func demo2_ExtraSpaces() {
	fmt.Println("\n-- лишние пробелы --")

	// В broken_policy.csv: "g,  charlie, viewer" — два пробела перед charlie
	e, err := casbin.NewEnforcer("config/model.conf", "config/broken_policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	roles, _ := e.GetRolesForUser("charlie")
	fmt.Printf("  роли 'charlie':  %v\n", roles)

	roles, _ = e.GetRolesForUser(" charlie")
	fmt.Printf("  роли ' charlie': %v\n", roles)
}

func demo3_WrongArgumentOrder() {
	fmt.Println("\n-- порядок аргументов --")

	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	check(e, "alice", "/admin", "read") // правильно: sub, obj, act
	check(e, "alice", "read", "/admin") // obj и act перепутаны
}

func demo4_BrokenMatcher() {
	fmt.Println("\n-- ошибка в матчере --")

	// В модели "p.sbu" вместо "p.sub"
	e, err := casbin.NewEnforcer("config/broken_model.conf", "config/policy.csv")
	if err != nil {
		fmt.Printf("  NewEnforcer: %v\n", err)
		return
	}

	ok, err := e.Enforce("alice", "/admin", "read")
	fmt.Printf("  Enforce -> ok=%v, err=%v\n", ok, err)
}

func demo5_Logging() {
	fmt.Println("\n-- EnableLog --")

	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	e.EnableLog(true)
	e.Enforce("alice", "/dashboard", "read")
	e.Enforce("bob", "/admin", "read")
	e.EnableLog(false)
}

func demo6_EnforceEx() {
	fmt.Println("\n-- EnforceEx --")

	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	checkEx(e, "alice", "/admin", "read")
	checkEx(e, "bob", "/dashboard", "write")
	checkEx(e, "charlie", "/admin", "read")
}

func demo7_DynamicPolicies() {
	fmt.Println("\n-- динамические политики --")

	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	check(e, "dave", "/dashboard", "read")

	e.AddGroupingPolicy("dave", "viewer")
	check(e, "dave", "/dashboard", "read")

	e.RemoveGroupingPolicy("dave", "viewer")
	e.AddGroupingPolicy("dave", "editor")
	check(e, "dave", "/dashboard", "write")

	e.AddPolicy("editor", "/reports", "read")
	check(e, "dave", "/reports", "read")
	check(e, "bob", "/reports", "read")
}

// Хелперы для компактного вывода

func check(e *casbin.Enforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	fmt.Printf("  %s %s %s -> %v\n", sub, act, obj, ok)
}

func checkEx(e *casbin.Enforcer, sub, obj, act string) {
	ok, reason, _ := e.EnforceEx(sub, obj, act)
	fmt.Printf("  %s %s %s -> %v  %v\n", sub, act, obj, ok, reason)
}
