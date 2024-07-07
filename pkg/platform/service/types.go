package service

type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ServiceClaim struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

type AuthServicer interface {
	Login(userCredentials *UserCredentials) (bool, error)
}
