package cloudflare

import "errors"

type pageInfo struct {
	Page       *int `json:"page"`
	Count      *int `json:"count"`
	TotalPages *int `json:"total_pages"`
	TotalCount *int `json:"total_count"`
}
type pageTracker struct{ pages, count *int }

func (p *pageTracker) observe(info pageInfo, page, count int) (bool, error) {
	if info.Page != nil && *info.Page != page || info.Count != nil && *info.Count != count {
		return false, ErrProtocol
	}
	for _, pair := range []struct {
		previous **int
		next     *int
	}{{&p.pages, info.TotalPages}, {&p.count, info.TotalCount}} {
		if pair.next == nil {
			continue
		}
		if *pair.next < 0 || *pair.previous != nil && **pair.previous != *pair.next {
			return false, errors.New("cloudflare pagination statistics changed or are invalid")
		}
		*pair.previous = pair.next
	}
	if p.count != nil && *p.count == 0 && count != 0 {
		return false, ErrProtocol
	}
	if p.pages != nil {
		if *p.pages == 0 {
			if page != 1 || count != 0 {
				return false, ErrProtocol
			}
			return true, nil
		}
		if page > *p.pages || count == 0 && page < *p.pages {
			return false, errors.New("cloudflare pagination ended early")
		}
		return page == *p.pages || count == 0, nil
	}
	return count == 0, nil
}
func (p *pageTracker) complete(unique int) error {
	if p.count != nil && unique != *p.count {
		return errors.New("cloudflare pagination total does not match unique record count")
	}
	return nil
}
