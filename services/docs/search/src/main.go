package main

import (
	"errors"
	"log"
	"os"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/search/query"
	"github.com/gofiber/fiber/v2"
)

type Document struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	OrgID   string `json:"org_id"`
}

type searchApp struct {
	index bleve.Index
}

func (app *searchApp) handleIndex(c *fiber.Ctx) error {
	var doc Document
	if err := c.BodyParser(&doc); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	if err := app.index.Index(doc.ID, doc); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusCreated)
}

func (app *searchApp) handleSearch(c *fiber.Ctx) error {
	qs := c.Queries()

	orgID := qs["org_id"]
	q := qs["q"]
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "org_id is required",
		})
	}

    orgIdQ := bleve.NewMatchQuery(orgID)
	orgIdQ.SetField("org_id")
	queries := []query.Query{
	    orgIdQ,
	}
    if q != "" {
    	queries = append(queries, bleve.NewMatchQuery(q))
	}


	searchRequest := bleve.NewSearchRequest(bleve.NewConjunctionQuery(queries...))
	searchResult, err := app.index.Search(searchRequest)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(searchResult)
}

func main() {
	// Create a new index
	mapping := bleve.NewIndexMapping()
	app := &searchApp{}
	var err error

	app.index, err = bleve.Open(os.Getenv("INDEX_FILE"))
	if err != nil && errors.Is(err, bleve.ErrorIndexPathDoesNotExist) {
		log.Printf("Index not found, creating new index %s", os.Getenv("INDEX_FILE"))
		app.index, err = bleve.New(os.Getenv("INDEX_FILE"), mapping)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer app.index.Close()

	fiber := fiber.New()

	fiber.Post("/index", app.handleIndex)
	fiber.Get("/search", app.handleSearch)

	log.Printf("Starting server on :8080")
	log.Fatal(fiber.Listen(":8080"))
}
