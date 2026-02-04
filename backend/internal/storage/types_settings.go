package storage

import "time"

// SystemSetting represents a dynamic application configuration.
type SystemSetting struct {
	Key         string      `json:"key"`
	Value       interface{} `json:"value"`
	Category    string      `json:"category"`
	IsSecret    bool        `json:"is_secret"`
	Description string      `json:"description"`
	UpdatedAt   time.Time   `json:"updated_at"`
}
