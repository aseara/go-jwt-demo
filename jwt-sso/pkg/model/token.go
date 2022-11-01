package model

type JWTToken struct {
	Token    string `json:"token"`
	Url      string `json:"url"`
	Describe string `json:"describe"`
}
