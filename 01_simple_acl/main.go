package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
)

func main() {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatalf("ошибка при загрузке конфига: %v", err)
	}

	simpleCheck(e, "alice", "/posts", "read")
	simpleCheck(e, "alice", "/posts", "write")
	simpleCheck(e, "bob", "/posts", "read")
	simpleCheck(e, "bob", "/posts", "write")
}

func simpleCheck(e *casbin.Enforcer, sub, obj, act string) {
	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.Printf("внутренняя ошибка: %v", err)
		return
	}

	if ok {
		fmt.Printf("%s разрешено %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("%s запрещено %s %s\n", sub, act, obj)
	}
}
