package certmgr

import "github.com/gatework/derper-go/internal/cloudflare"

// record is the journal representation shared with the DNS API.
type record = cloudflare.Record
