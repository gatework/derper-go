package config

import (
	"encoding/json"
	"errors"
	"time"
)

// Duration uses Go's familiar time syntax instead of ambiguous numeric units.
// A pointer distinguishes an omitted default from an explicit "0s".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var text string
	if json.Unmarshal(b, &text) != nil {
		return errors.New("时间间隔应使用字符串，例如 2s、15s 或 10m")
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return errors.New("时间间隔无效，例如 2s、15s 或 10m")
	}
	*d = Duration(value)
	return nil
}
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
func durationValue(value *Duration, fallback time.Duration) time.Duration {
	if value == nil {
		return fallback
	}
	return time.Duration(*value)
}
