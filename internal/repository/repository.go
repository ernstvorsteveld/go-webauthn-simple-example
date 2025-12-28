package repository

import (
	"encoding/json"
	"log"
	"os"
	"sync" // Added missing import for sync.Mutex

	"go-oidc-example/internal/models"
)

var (
	userDB     = map[string]*models.User{}
	userDBFile = "users.json"
	userDBMu   sync.Mutex
)

// Init loads the users from the file
func Init() {
	loadUsers()
}

func loadUsers() {
	file, err := os.Open(userDBFile)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Fatal(err)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&userDB); err != nil {
		log.Fatal(err)
	}
}

// GetUser returns a user by username
func GetUser(username string) (*models.User, bool) {
	u, ok := userDB[username]
	return u, ok
}

// SaveUser saves or updates a user
func SaveUser(user *models.User) {
	userDBMu.Lock()
	defer userDBMu.Unlock()

	userDB[user.Username] = user
	saveFile()
}

func saveFile() {
	file, err := os.Create(userDBFile)
	if err != nil {
		log.Println("Error saving users:", err)
		return
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(userDB); err != nil {
		log.Println("Error encoding users:", err)
	}
}
