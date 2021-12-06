package main

import (
	"math/rand"
	"time"

	"github.com/kralicky/post-init/pkg/postinit"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	postinit.Execute()
}
