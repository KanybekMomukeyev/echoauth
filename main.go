package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const secretSigningKey = "secret132123123"

type jwtCustomClaims struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func login(c echo.Context) error {

	m := make(map[string]string)
	if err := c.Bind(&m); err != nil {
		return err
	}

	jsonValue, _ := json.Marshal(m)
	fmt.Printf("\n\n LOGIN REQ BODY JSON VALUE: %v\n", string(jsonValue))
	fmt.Printf("\n\n LOGIN REQ BODY MAP VALUE %v\n", m)

	if len(m["username"]) < 1 {
		return echo.NewHTTPError(http.StatusUpgradeRequired, "username not specified")
	}
	if len(m["password"]) < 1 {
		return echo.NewHTTPError(http.StatusUpgradeRequired, "password not specified")
	}

	username := m["username"]
	password := m["password"]

	if username != "pieter" || password != "claerhout" {
		return echo.NewHTTPError(http.StatusForbidden, "user not found")
	}

	claims := &jwtCustomClaims{
		Name:  "Pieter Claerhout",
		UUID:  "9E98C454-C7AC-4330-B2EF-983765E00547",
		Admin: true,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 30).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(secretSigningKey))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"token": t,
	})
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted1(c echo.Context) error {
	// --------- UNUSED STARTS --------- //
	m := make(map[string]string)
	if err := c.Bind(&m); err != nil {
		return err
	}
	jsonValue, _ := json.Marshal(m)
	fmt.Printf("\n\n RESTRICTED REQ BODY JSON VALUE: %v\n", string(jsonValue))
	fmt.Printf("\n\n RESTRICTED REQ BODY MAP VALUE: %v\n", m)
	// -------------------------------- //

	user := c.Get("user").(*jwt.Token)
	fmt.Printf("\n\n USER: %v\n\n", user)

	claims := user.Claims.(*jwtCustomClaims)
	fmt.Printf("\n\n CLAIMS: %v\n\n", claims)

	name := claims.Name
	uddid := claims.UUID
	fmt.Printf("\n\n %v %v\n\n", name, uddid)

	return c.JSON(http.StatusOK, claims)
}

func restricted2(c echo.Context) error {
	// --------- UNUSED STARTS --------- //
	m := make(map[string]string)
	if err := c.Bind(&m); err != nil {
		return err
	}
	jsonValue, _ := json.Marshal(m)
	fmt.Printf("\n\n RESTRICTED REQ BODY JSON VALUE: %v\n", string(jsonValue))
	fmt.Printf("\n\n RESTRICTED REQ BODY MAP VALUE: %v\n", m)
	// -------------------------------- //

	user := c.Get("user").(*jwt.Token)
	fmt.Printf("\n\n USER: %v\n\n", user)

	claims := user.Claims.(*jwtCustomClaims)
	fmt.Printf("\n\n CLAIMS: %v\n\n", claims)

	name := claims.Name
	uddid := claims.UUID
	fmt.Printf("\n\n %v %v\n\n", name, uddid)

	return c.JSON(http.StatusOK, claims)
}

func main() {
	//http://localhost:1111/
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	publicRoutes := e.Group("/v1")
	{
		publicRoutes.POST("/login", login)
		publicRoutes.GET("/", accessible)
	}

	protectedRoutes := e.Group("/v1")
	{
		config := middleware.JWTConfig{
			Claims:     &jwtCustomClaims{},
			SigningKey: []byte(secretSigningKey),
		}
		protectedRoutes.Use(middleware.JWTWithConfig(config))
		protectedRoutes.POST("/restricted1", restricted1)
		protectedRoutes.POST("/restricted2", restricted2)
	}

	e.Logger.Fatal(e.Start(":1111"))
}
