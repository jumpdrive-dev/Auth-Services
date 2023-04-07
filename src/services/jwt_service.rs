use std::ops::Add;

use chrono::{Duration, Months, Utc};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use uuid::Uuid;
use crate::errors::jwt_error::JwtError;
use crate::models::jwt::jwt_claims::JwtClaims;
use crate::models::jwt::jwt_headers::JwtHeader;
use crate::models::jwt::jwt_token_type::JwtTokenType;

/// Service with functions to generate and verify JWT tokens
#[derive(Debug)]
pub struct JwtService {
    signing_key: SigningKey<Sha256>,
    access_token_seconds: u32,
    issuer: String,
    audience: String,
}

type Result<T> = std::result::Result<T, JwtError>;

impl JwtService {
    pub fn new(
        private_key: RsaPrivateKey,
        access_token_seconds: u32,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            signing_key: SigningKey::new_with_prefix(private_key),
            access_token_seconds,
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }

    pub fn get_access_token_seconds(&self) -> u32 {
        self.access_token_seconds
    }

    /// Creates a refresh token for the given grant and sets the [JwtHeader] and [JwtClaims]
    /// accordingly. A refresh token has an expire time of 15 minutes.
    pub fn create_access_token<T>(
        &self,
        subject: impl Into<String>,
        payload: T,
    ) -> Result<String>
    where
        T: Serialize
    {
        let header = JwtHeader {
            cty: JwtTokenType::Access,
            ..Default::default()
        };

        let claims = JwtClaims {
            iss: self.issuer.to_string(),
            aud: self.audience.to_string(),
            sub: subject.into(),
            exp: (Utc::now().add(Duration::seconds(self.access_token_seconds as i64))).timestamp(),
            nbf: Utc::now().timestamp(),
            iat: Utc::now().timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        self.create_token(header, claims, payload)
    }

    /// Creates a refresh token with the provided payload and sets the [JwtHeader] and [JwtClaims]
    /// accordingly. A refresh token has an expire time of three months.
    pub fn create_refresh_token<T>(
        &self,
        subject: impl Into<String>,
        payload: T,
    ) -> Result<String>
    where
        T: Serialize
    {
        let header = JwtHeader {
            cty: JwtTokenType::Refresh,
            ..Default::default()
        };

        let claims = JwtClaims {
            iss: self.issuer.to_string(),
            aud: self.audience.to_string(),
            sub: subject.into(),
            exp: (Utc::now().add(Months::new(3))).timestamp(),
            nbf: Utc::now().timestamp(),
            iat: Utc::now().timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        self.create_token(header, claims, payload)
    }

    /// Used to create a JWT token with custom a headers and claims.
    pub fn create_token<T>(
        &self,
        header: JwtHeader,
        claims: JwtClaims,
        payload: T,
    ) -> Result<String>
    where
        T: Serialize,
    {
        let payload_value = self.merge_claims_with_payload(claims, payload)?;

        let encoded_header = base64_url::encode(&serde_json::to_string(&header)?);
        let encoded_payload = base64_url::encode(&serde_json::to_string(&payload_value)?);
        let signature = self.sign_key(&encoded_header, &encoded_payload)?;

        Ok(format!(
            "{}.{}.{}",
            encoded_header, encoded_payload, signature
        ))
    }

    /// Merges the JSON representation for the [JwtClaims] with the payload for the token and
    /// returns a single JSON object to be used as the JWT payload.
    fn merge_claims_with_payload<T>(
        &self,
        claims: JwtClaims,
        payload: T,
    ) -> Result<Value>
    where
        T: Serialize,
    {
        let mut final_map: Map<String, Value> = Map::new();

        let Value::Object(claims_map) = serde_json::to_value(claims)? else {
            return Err(
                JwtError::PayloadNotAnObject
                    .into(),
            );
        };

        for (key, value) in claims_map {
            final_map.insert(key, value);
        }

        let Value::Object(payload_map) = serde_json::to_value(payload)? else {
            return Err(
                JwtError::PayloadNotAnObject
                    .into()
            );
        };

        for (key, value) in payload_map {
            final_map.insert(key, value);
        }

        Ok(Value::Object(final_map))
    }

    /// Takes the base64url encoded header and payload and creates a signature using HMAC HS256
    /// signing algorithm using the the environment variable `JWT_SIGNING_KEY` as the signing key.
    fn sign_key(
        &self,
        encoded_header: impl Into<String>,
        encoded_payload: impl Into<String>,
    ) -> Result<String> {
        let encoded_header = encoded_header.into();
        let encoded_payload = encoded_payload.into();

        let message_to_sign = format!("{}.{}", encoded_header, encoded_payload);

        let i = self.signing_key.sign(message_to_sign.as_ref());

        Ok(base64_url::encode(&i.to_bytes()))
    }

    /// Decodes the given access token and makes sure the token can be used at the current time.
    pub fn decode_access_token<T>(
        &self,
        token: impl Into<String>,
    ) -> Result<T>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (claims, payload) = self.decode_access_token_unchecked(token)?;
        JwtService::guard_claims(&claims)?;

        Ok(payload)
    }

    /// Decodes the given access token, but the only thing that is checked is the signature. Things
    /// like expire time etc should be checked by the caller.
    pub fn decode_access_token_unchecked<T>(
        &self,
        token: impl Into<String>,
    ) -> Result<(JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (header, claims, payload) = self.decode_jwt(token.into())?;

        if header.cty != JwtTokenType::Access {
            return Err(JwtError::NotAnAccessToken.into());
        }

        Ok((claims, payload))
    }

    /// Decodes the given refresh token and makes sure the token can be used at the current time.
    pub fn decode_refresh_token<T>(
        &self,
        token: impl Into<String>
    ) -> Result<T>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (claims, payload) = self.decode_refresh_token_unchecked(token)?;
        JwtService::guard_claims(&claims)?;

        Ok(payload)
    }

    /// Decodes the given refresh token, but the only thing that is checked is the signature. Things
    /// like expire time etc should be checked by the caller.
    pub fn decode_refresh_token_unchecked<T>(
        &self,
        token: impl Into<String>,
    ) -> Result<(JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (header, claims, payload) = self.decode_jwt(token.into())?;

        if header.cty != JwtTokenType::Refresh {
            return Err(JwtError::NotARefreshToken.into());
        }

        Ok((claims, payload))
    }

    /// Decodes the given JWT token and returns all the given important parts of the token. It
    /// doesn't perform any checks apart from checking the signature. All checks should done by
    /// the caller. If you created a token using either the [create_access_token] or
    /// [create_refresh_token] method, make sure to use decode methods for those instead of
    /// this one.
    pub fn decode_jwt<T>(
        &self,
        token: impl Into<String>,
    ) -> Result<(JwtHeader, JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
    {
        let token = token.into();

        let mut parts = token.split('.');
        let header_part = parts.next().ok_or(JwtError::MissingHeader)?;

        let payload_part = parts.next().ok_or(JwtError::MissingPayload)?;

        let signature = parts.next().ok_or(JwtError::MissingSignature)?;

        let signature_check = self.sign_key(header_part, payload_part)?;

        if signature_check != signature {
            return Err(JwtError::InvalidSignature.into());
        }

        let header_bytes = base64_url::decode(header_part)?;
        let payload_bytes = base64_url::decode(payload_part)?;

        let header_string = String::from_utf8(header_bytes)?;
        let payload_string = String::from_utf8(payload_bytes)?;

        let header = serde_json::from_str(&header_string)?;
        let payload = serde_json::from_str(&payload_string)?;

        let (claims, payload) = JwtService::split_payload(payload)?;

        Ok((header, claims, payload))
    }

    /// Takes the JWT payload as a raw JSON object and returns the claims and payload for
    /// that object.
    fn split_payload<T>(
        payload_value: Value,
    ) -> Result<(JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
    {
        let Value::Object(_) = payload_value else {
            return Err(
                JwtError::PayloadIsNotJson
                    .into()
            );
        };

        let claims = serde_json::from_value(payload_value.clone())?;
        let payload = serde_json::from_value(payload_value)?;

        Ok((claims, payload))
    }

    /// Checks the 'not before' and 'expire at' claims and returns an Err result if something does
    /// not match.
    pub fn guard_claims(
        claims: &JwtClaims,
    ) -> Result<()> {
        let now_timestamp = Utc::now().timestamp();

        if now_timestamp < claims.nbf {
            return Err(JwtError::UsedBeforeNotBeforeClaim.into());
        }

        if now_timestamp > claims.exp {
            return Err(JwtError::UsedAfterExpireClaim.into());
        }

        Ok(())
    }

    /// Returns true if all the 'not before' and 'expire at' claims are valid and returns false
    /// otherwise.
    pub fn check_claims(
        claims: &JwtClaims,
    ) -> bool {
        match JwtService::guard_claims(claims) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
