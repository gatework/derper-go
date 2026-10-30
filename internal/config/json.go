package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("configuration values must not be null")
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				s = strings.ToLower(s)
				if seen[s] {
					return fmt.Errorf("duplicate configuration field %q", s)
				}
				seen[s] = true
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	return nil
}
