package main

import (
	"net/http"

	"github.com/go-chi/chi"
)

func main() {
	router := chi.NewRouter()

	router.Get("/", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Welcome to GO"))
	})

	http.ListenAndServe(":3000", router)
}
