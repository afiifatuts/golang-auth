package authentication

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = "SECRET_KEY"

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) { return jwtKey, nil })

		if !token.Valid || err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("claims", claims)

		c.Next()
	}
}

func LoginHandler(c *gin.Context) {
	var user User
	//binding : langsung ke objectnya
	//kalau scan di mapping
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	//logic authentication(compare username dan password)
	if user.Username == "enigma" && user.Password == "12345" {
		//bikin code untuk generate token
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func ProfileHandler(c *gin.Context) {
	//ambil username dari jwt tokennya
	claims := c.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)
	//seharusnya response user dari db, tapi di contoh ini kita return usrname
	c.JSON(http.StatusOK, gin.H{"username": username})
}
