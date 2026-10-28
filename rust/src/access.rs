//! Verifying JWT access tokens (RFC 9068) for resource servers, e.g. an API
//! that receives `Authorization: Bearer …` from another service.

use crate::claims::AccessClaims;
use crate::client::Client;
use crate::error::Result;
use crate::jwt::{self, Expect, TYP_ACCESS};

impl Client {
    /// Verifies an access token locally (signature, `typ: at+jwt`, `iss`,
    /// `exp`/`iat`/`nbf`) and requires `aud` to contain `audience` (usually
    /// this client's id). Revocation is not visible locally: tokens live
    /// about 5 minutes; use the UserInfo endpoint where revocation must be
    /// honoured immediately. Check scopes with [`AccessClaims::has_scope`].
    pub async fn verify_access_token(&self, token: &str, audience: &str) -> Result<AccessClaims> {
        let expect = Expect {
            typ: TYP_ACCESS,
            issuer: &self.meta.issuer,
            audience,
            algs: &self.algs,
        };
        let raw = jwt::verify(token, &self.http, &self.jwks, &expect).await?;
        jwt::into_claims(raw)
    }
}
