package main

import (
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/gocolly/colly"
	_ "github.com/lib/pq"
	"github.com/likexian/whois-go"
	whoisparser "github.com/likexian/whois-parser-go"
)

// Incoming message from json
type Incoming struct {
	Host      string           `json:"host"`
	Status    string           `json:"status"`
	StartTime int64            `json:"startTime"`
	Endpoints *json.RawMessage `json:"endpoints"`
}

// Body final response
type Body struct {
	Host             string    `json:"host"`
	Servers          []*Server `json:"endpoints"`
	ServersChanged   bool
	SslGrade         string
	previousSslGrade string
	Logo             string
	Title            string
	IsDown           bool
}

// Server structure from json endpoints
type Server struct {
	Address  string `json:"ipAddress"`
	SslGrade string `json:"grade"`
	Country  string
	Owner    string
}

func main() {
	// Create the router
	router := chi.NewRouter()
	// Basic CORS
	cors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
	})
	// Middlewares
	router.Use(cors.Handler)
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RealIP)

	router.Get("/", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Welcome to GO"))
	})

	router.Route("/servers", func(r chi.Router) {
		r.Get("/", getDomains)

		r.Route("/{domain}", func(r chi.Router) {
			r.Get("/", getDomainInfo)
		})
	})

	http.ListenAndServe(":3000", router)
}

func getDomains(res http.ResponseWriter, req *http.Request) {
	// Open the SQL Connection
	db, errdb := sql.Open("postgres", "postgresql://maxroach@localhost:26257/icango?sslmode=disable")
	if errdb != nil {
		log.Fatal("error connecting to the database: ", errdb)
	}
	// Save the items
	items := []Body{}
	// Let's search the items
	rows, err := db.Query("SELECT * FROM items")
	// If the error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}
	defer rows.Close()

	for rows.Next() {
		var bodyID int64
		body := Body{}
		var serverString string
		if err := rows.Scan(&bodyID, &body.Host, &serverString, &body.ServersChanged, &body.SslGrade, &body.previousSslGrade, &body.Logo, &body.Title, &body.IsDown); err != nil {
			panic(err)
		}
		// Parse the serverString to Servers
		if err := json.Unmarshal([]byte(serverString), &body.Servers); err != nil {
			panic(err)
		}
		items = append(items, body)
	}
	// Finally, Marshal the json body and response it
	response, err := json.Marshal(items)
	// If error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}

	defer res.Write([]byte(response))
}

func getDomainInfo(res http.ResponseWriter, req *http.Request) {
	// Open the SQL Connection
	db, errdb := sql.Open("postgres", "postgresql://maxroach@localhost:26257/icango?sslmode=disable")
	if errdb != nil {
		log.Fatal("error connecting to the database: ", errdb)
	} else {
		// Create the "items" table.
		if _, err := db.Exec(
			"CREATE TABLE IF NOT EXISTS items (id SERIAL PRIMARY KEY, host STRING, servers STRING, servers_changed BOOL, ssl_grade STRING, previous_ssl_grade STRING, logo STRING, title STRING, is_down BOOL)"); err != nil {
			log.Fatal(err)
		}
	}
	// Get the domain param
	domain := chi.URLParam(req, "domain")
	// Let's search the domain into database
	var itemID int64
	// Item is for save the result
	item := Body{}
	// This string save the servers
	var serverString string
	queryErr := db.QueryRow("SELECT * FROM items WHERE host = $1", domain).Scan(&itemID, &item.Host, &serverString, &item.ServersChanged, &item.SslGrade, &item.previousSslGrade, &item.Logo, &item.Title, &item.IsDown)
	// If the error is non nil
	if queryErr != nil {
		http.Error(res, http.StatusText(404), 404)
	}
	// Then, make the http get request with the domain param like host
	result, err := http.Get("https://api.ssllabs.com/api/v3/analyze?host=" + domain)
	// If error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}
	// When the function ends, let's close the body
	defer result.Body.Close()
	// Let's get the byte info from Body
	body, err := ioutil.ReadAll(result.Body)
	// If error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}
	// Here we save the json body
	var jsonBody Body
	var incoming Incoming
	// // Decode the body to jsonBody
	if err := json.Unmarshal(body, &jsonBody); err != nil {
		panic(err)
	}
	// Decode the body to incoming json
	if err := json.Unmarshal(body, &incoming); err != nil {
		panic(err)
	}
	// Let's verify if the domain is already be into database
	if itemID != 0 {
		// Parse the serverString to Servers
		if err := json.Unmarshal([]byte(serverString), &item.Servers); err != nil {
			panic(err)
		}
		// Let's prepare the body
		err := prepareBody(&incoming, &item)
		// Update the database
		if _, err := db.Exec(
			"UPDATE items SET servers = $1 WHERE id = $2", serverString, itemID); err != nil {
			panic(err)
		}
		// Finally, Marshal the json body and response it
		response, err := json.Marshal(item)
		// If error is non nil
		if err != nil {
			http.Error(res, http.StatusText(404), 404)
		}

		defer res.Write([]byte(response))
	} else {
		// Let's prepare the body
		err := prepareBody(&incoming, &jsonBody)
		// If error is non nil
		if err != nil {
			panic(err)
		}
		// Transform the servers for can save it into database
		servers, err := json.Marshal(jsonBody.Servers)
		// If error is non nil
		if err != nil {
			panic(err)
		}
		// Let's save the jsonBody
		if _, err := db.Exec("INSERT INTO items (host, servers, servers_changed, ssl_grade, previous_ssl_grade, logo, title, is_down) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", jsonBody.Host, servers, jsonBody.ServersChanged, jsonBody.SslGrade, jsonBody.previousSslGrade, jsonBody.Logo, jsonBody.Title, jsonBody.IsDown); err != nil {
			log.Fatal(err)
		}

		// Finally, Marshal the json body and response it
		response, err := json.Marshal(jsonBody)
		// If error is non nil
		if err != nil {
			http.Error(res, http.StatusText(404), 404)
		}

		defer res.Write([]byte(response))
	}
}

func prepareBody(incoming *Incoming, body *Body) (err error) {
	// If the status is "ERROR" then...
	if incoming.Status == "ERROR" {
		body.IsDown = true
	} else {
		body.IsDown = false
	}
	// Whois
	for _, value := range body.Servers {
		whoisRaw, err := whois.Whois(body.Host)
		if err != nil {
			return err
		}

		whoisParse, err := whoisparser.Parse(whoisRaw)
		if err != nil {
			return err
		}

		value.Country = whoisParse.Registrant.Country
		value.Owner = whoisParse.Registrant.Organization
	}
	// Use colly for get logo and title from domain
	c := colly.NewCollector()

	c.OnHTML("head title", func(e *colly.HTMLElement) {
		body.Title = e.Text
	})
	c.OnHTML("head link", func(e *colly.HTMLElement) {
		if strings.HasPrefix(e.Attr("type"), "image/") {
			body.Logo = e.Attr("href")
		}
	})
	// Now, let's create a string for visit that site
	c.Visit("http://" + body.Host)

	return nil
}
