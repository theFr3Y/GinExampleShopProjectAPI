package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type CartItem struct {
	gorm.Model
	CartID    string
	ProductID uint
	Quantity  int
	Product   Product
}

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Product struct {
	gorm.Model
	Name  string `json:"name"`
	Price int    `json:"price"`
}

var db *gorm.DB

var store = cookie.NewStore([]byte("secret"))

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Product{})
	db.AutoMigrate(&CartItem{})
}

func main() {
	initDB()

	db, err1 := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err1 != nil {
		log.Fatal(err1)
	}

	sqlDB, err2 := db.DB()
	if err2 != nil {
		log.Fatal(err2)
	}
	defer sqlDB.Close()

	r := gin.Default()
	r.Use(sessions.Sessions("mysession", store))
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// routes ...
	r.POST("/register", register)
	r.POST("/login", login)
	r.GET("/users", GetUsers)
	r.POST("/users/delete/:id", deleteUser)
	r.GET("/users/:id", GetUser)
	r.PUT("/users/:id", updateUser)
	r.POST("/logout", logout)

	r.GET("/products", getProducts)
	r.GET("/products/:id", getProduct)
	r.POST("/products", createProduct)
	r.PUT("/products/:id", updateProduct)
	r.DELETE("/products/:id", deleteProduct)

	r.POST("/cart/add/:id", addToCart)
	r.GET("/cart", viewCart)

	r.GET("/", IndexView)

	r.Run(":8000")
}

func register(c *gin.Context) {
	var user User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	var existingUser User
	result := db.Where("username = ?", user.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	hashedPassword := hashPassword(user.Password)
	user.Password = hashedPassword
	err = db.Create(&user).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
}

func login(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	err := c.BindJSON(&input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	var user User
	result := db.Where("username = ?", input.Username).First(&user)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	if !verifyPassword(user.Password, input.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully"})
}

func hashPassword(password string) string {
	return password
}

func verifyPassword(hashedPassword string, password string) bool {
	return hashedPassword == password
}

func GetUsers(c *gin.Context) {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	var users []User
	db.Find(&users)

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")

	var user User
	result := db.Delete(&user, id)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	err := session.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func getProducts(c *gin.Context) {
	var products []Product
	if err1 := db.Find(&products).Error; err1 != nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.JSON(http.StatusOK, products)
	}
}

func getProduct(c *gin.Context) {
	var product Product
	if err := db.First(&product, c.Param("id")).Error; err != nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		c.JSON(http.StatusOK, product)
	}
}

func createProduct(c *gin.Context) {
	var product Product
	if err := c.ShouldBindJSON(&product); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
	} else {
		db.Create(&product)
		c.JSON(http.StatusCreated, product)
	}
}

func updateProduct(c *gin.Context) {
	var product Product
	if err := db.First(&product, c.Param("id")).Error; err != nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		if err := c.ShouldBindJSON(&product); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
		} else {
			db.Save(&product)
			c.JSON(http.StatusOK, product)
		}
	}
}

func deleteProduct(c *gin.Context) {
	var product Product
	if err := db.First(&product, c.Param("id")).Error; err != nil {
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		db.Delete(&product)
		c.Status(http.StatusOK)
	}
}

func addToCart(c *gin.Context) {
	id := c.Param("id")

	var product Product
	result := db.First(&product, id)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	session := sessions.Default(c)
	cartID := session.Get("cart_id")
	if cartID == nil {
		cartID = RandStringBytes(10)
		session.Set("cart_id", cartID)
		session.Save()
	}

	var cartItem CartItem
	result = db.Where("cart_id = ? AND product_id = ?", cartID, id).First(&cartItem)
	if result.RowsAffected > 0 {
		cartItem.Quantity++
		db.Save(&cartItem)
	} else {
		cartItem = CartItem{
			ProductID: product.ID,
			Quantity:  1,
			CartID:    cartID.(string),
		}
		db.Create(&cartItem)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Item added to cart"})
}

func viewCart(c *gin.Context) {
	session := sessions.Default(c)
	cartID := session.Get("cart_id")

	if cartID == nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "No items in cart",
		})
		return
	}

	var items []CartItem
	db.Where("cart_id = ?", fmt.Sprintf("%v", cartID)).Find(&items)

	if len(items) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No items in cart",
		})
		return
	}

	for i, item := range items {
		var product Product
		db.First(&product, item.ProductID)
		items[i].Product = product
	}

	c.JSON(http.StatusOK, items)
}

func init() {
	store.Options(sessions.Options{
		HttpOnly: true,
	})
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	return string(b)
}

func IndexView(c *gin.Context) {
	list := []string{"/users", "/products", "/products/:id", "/users/:id"}
	c.String(200, "all of routes: %v", list)
}

func GetUser(c *gin.Context) {
	id := c.Param("id")

	var user User
	result := db.First(&user, id)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
	id := c.Param("id")

	var user User
	result := db.First(&user, id)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	input := &User{}
	err := c.Bind(input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// update fields
	updates := map[string]interface{}{}
	if input.Username != "" {
		updates["username"] = input.Username
	}
	if input.Password != "" {
		hashedPassword := hashPassword(input.Password)
		updates["password"] = hashedPassword
	}

	result = db.Model(&user).Updates(updates)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, user)
}
