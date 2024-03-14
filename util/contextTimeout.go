package util

import (
	"context"
	"time"
)

func CtxDone(ctx context.Context, sleeptimeout time.Duration) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(sleeptimeout):
	}
	return false
}
