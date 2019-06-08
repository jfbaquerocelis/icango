package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gocolly/colly"
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
	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RealIP)

	router.Get("/", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("Welcome to GO"))
	})

	router.Route("/servers", func(r chi.Router) {

		r.Route("/{domain}", func(r chi.Router) {
			r.Get("/", getDomainInfo)
		})
	})

	http.ListenAndServe(":3000", router)
}

func getDomainInfo(res http.ResponseWriter, req *http.Request) {
	// Get the domain param
	domain := chi.URLParam(req, "domain")
	// Let's create the request
	req, err := http.NewRequest("GET", "https://api.ssllabs.com/api/v3/analyze", nil)
	// If the error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}
	// Let's create the query
	query := req.URL.Query()
	query.Add("host", domain)
	req.URL.RawQuery = query.Encode()
	// Then, make the http get request with the domain param like host
	result, err := http.Get(req.URL.String())
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
	// If the status is not "READY" then...
	if incoming.Status == "ERROR" {
		jsonBody.IsDown = true
	}
	// Whois
	for _, value := range jsonBody.Servers {
		whoisRaw, err := whois.Whois(jsonBody.Host)
		if err != nil {
			http.Error(res, http.StatusText(404), 404)
		}

		whoisParse, err := whoisparser.Parse(whoisRaw)
		if err != nil {
			http.Error(res, http.StatusText(404), 404)
		}

		value.Country = whoisParse.Registrant.Country
		value.Owner = whoisParse.Registrant.Organization
	}
	// Use colly for get logo and title from domain
	c := colly.NewCollector()

	c.OnHTML("head title", func(e *colly.HTMLElement) {
		jsonBody.Title = e.Text
	})
	c.OnHTML("head link", func(e *colly.HTMLElement) {
		if strings.HasPrefix(e.Attr("type"), "image/") {
			jsonBody.Logo = e.Attr("href")
		}
	})
	// Now, let's create a string for visit that site
	str := []string{"http://", jsonBody.Host}
	c.Visit(strings.Join(str, ""))

	// Finally, Marshal the json body and response it
	response, err := json.Marshal(jsonBody)
	// If error is non nil
	if err != nil {
		http.Error(res, http.StatusText(404), 404)
	}

	defer res.Write([]byte(response))
}
