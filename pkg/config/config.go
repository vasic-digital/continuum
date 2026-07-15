// Package config is continuum's decoupling surface (§11.4.28/§11.4.177).
//
// The engine carries ZERO project literals. Every project-specific value — the
// store location, the actor identity, tuning — is supplied here as DATA, from
// an explicit argument or an environment variable. When the store root cannot
// be resolved the engine FAILS CLOSED with an actionable message; it never
// guesses a project path (§11.4.6).
package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

// Env var names (the ONLY knobs the engine reads from the environment).
const (
	EnvStore  = "CONTINUUM_STORE" // required: absolute path to the store root
	EnvActor  = "CONTINUUM_ACTOR" // optional: who is writing (defaults to host:pid)
	EnvTTLSec = "CONTINUUM_LOCK_TTL_SECONDS"
)

// Config is the resolved runtime configuration.
type Config struct {
	Root    string        // store root (required)
	Actor   string        // writer identity for the ledger
	LockTTL time.Duration // provably-stale reap TTL for the advisory lock
}

// ErrNoRoot is returned when no store root can be resolved. Fail-closed.
var ErrNoRoot = errors.New(
	"continuum/config: store root unresolved — pass --store <path> or set CONTINUUM_STORE " +
		"(the engine never guesses a project path, §11.4.6/§11.4.177)")

// Resolve builds a Config from an explicit root (may be empty) plus the
// environment. explicitRoot takes precedence over EnvStore.
func Resolve(explicitRoot string) (Config, error) {
	root := explicitRoot
	if root == "" {
		root = os.Getenv(EnvStore)
	}
	if root == "" {
		return Config{}, ErrNoRoot
	}
	c := Config{
		Root:    root,
		Actor:   resolveActor(),
		LockTTL: 2 * time.Minute,
	}
	if v := os.Getenv(EnvTTLSec); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.LockTTL = time.Duration(n) * time.Second
		}
	}
	return c, nil
}

func resolveActor() string {
	if a := os.Getenv(EnvActor); a != "" {
		return a
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	return host + ":" + strconv.Itoa(os.Getpid())
}
