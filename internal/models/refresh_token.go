package models

import (
	_"time"
)

type RefreshToken struct {
	BaseModel
	UserID    int64     `db:"user_id" json:"user_id"`
	Token     string    `db:"token" json:"token"`
	Revoked   bool      `db:"revoked" json:"revoked"`
}