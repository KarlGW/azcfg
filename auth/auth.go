package auth

import "github.com/KarlGW/azcfg/internal/auth"

// Scopes contains the target scopes for getting Key Vault secrets.
var Scopes = auth.Scopes

// Token contains the access token and when it expires.
type Token = auth.Token

// Credential is the interface that wraps around method Token.
type Credential = auth.Credential

// AdaptorCredential is used when other credentials are provided than
// the built-in one.
type AdaptorCredential = auth.AdaptorCredential
