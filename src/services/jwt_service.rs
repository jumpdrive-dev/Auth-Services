use std::ops::Add;

pub use rsa::pkcs1::DecodeRsaPrivateKey;
pub use rsa::RsaPrivateKey;
pub use chrono::Duration;
use chrono::{Utc};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use uuid::Uuid;

use crate::errors::jwt_error::JwtError;
use crate::models::jwt::jwt_claims::JwtClaims;
use crate::models::jwt::jwt_headers::JwtHeader;
use crate::models::jwt::jwt_token_type::JwtTokenType;

/// Service with functions to generate and verify JWT tokens
pub struct JwtService {
    signing_key: SigningKey<Sha256>,
    access_token_duration: Duration,
    refresh_token_duration: Duration,
    issuer: String,
    audience: String,
}

type Result<T> = std::result::Result<T, JwtError>;

impl JwtService {
    pub fn new(
        private_key: RsaPrivateKey,
        access_token_duration: Duration,
        refresh_token_duration: Duration,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            signing_key: SigningKey::new(private_key),
            access_token_duration,
            refresh_token_duration,
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }

    pub fn get_access_token_seconds(&self) -> i64 {
        self.access_token_duration.num_seconds()
    }

    /// Creates a refresh token for the given grant and sets the [JwtHeader] and [JwtClaims]
    /// accordingly. A refresh token has an expire time of 15 minutes.
    pub fn create_access_token<T>(&self, subject: impl Into<String>, payload: T) -> Result<String>
    where
        T: Serialize,
    {
        let header = JwtHeader {
            cty: Some(JwtTokenType::Access),
            ..Default::default()
        };

        let claims = JwtClaims {
            iss: Some(self.issuer.to_string()),
            aud: Some(self.audience.to_string()),
            sub: Some(subject.into()),
            exp: Some(
                (Utc::now().add(self.access_token_duration)).timestamp(),
            ),
            nbf: Some(Utc::now().timestamp()),
            iat: Some(Utc::now().timestamp()),
            jti: Some(Uuid::new_v4().to_string()),
        };

        self.create_token(header, claims, payload)
    }

    /// Creates a refresh token with the provided payload and sets the [JwtHeader] and [JwtClaims]
    /// accordingly. A refresh token has an expire time of three months.
    pub fn create_refresh_token<T>(&self, subject: impl Into<String>, payload: T) -> Result<String>
    where
        T: Serialize,
    {
        let header = JwtHeader {
            cty: Some(JwtTokenType::Refresh),
            ..Default::default()
        };

        let claims = JwtClaims {
            iss: Some(self.issuer.to_string()),
            aud: Some(self.audience.to_string()),
            sub: Some(subject.into()),
            exp: Some((Utc::now().add(self.refresh_token_duration)).timestamp()),
            nbf: Some(Utc::now().timestamp()),
            iat: Some(Utc::now().timestamp()),
            jti: Some(Uuid::new_v4().to_string()),
        };

        self.create_token(header, claims, payload)
    }

    /// Used to create a JWT token with custom a headers and claims.
    pub fn create_token<T, H>(
        &self,
        header: JwtHeader<H>,
        claims: JwtClaims,
        payload: T,
    ) -> Result<String>
    where
        T: Serialize,
        for<'a> H: Serialize + Deserialize<'a>,
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
    fn merge_claims_with_payload<T>(&self, claims: JwtClaims, payload: T) -> Result<Value>
    where
        T: Serialize,
    {
        let mut final_map: Map<String, Value> = Map::new();

        let Value::Object(claims_map) = serde_json::to_value(claims)? else {
            return Err(
                JwtError::PayloadNotAnObject,
            );
        };

        for (key, value) in claims_map {
            final_map.insert(key, value);
        }

        let Value::Object(payload_map) = serde_json::to_value(payload)? else {
            return Err(
                JwtError::PayloadNotAnObject
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
    pub fn decode_access_token<T>(&self, token: impl Into<String>) -> Result<T>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (claims, payload) = self.decode_access_token_unchecked(token)?;
        self.guard_claims(&claims)?;

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
        let (header, claims, payload) = self.decode_jwt::<T, JwtTokenType>(token.into())?;

        let Some(token_type) = header.cty else {
            return Err(JwtError::NotAnAccessToken);
        };

        if token_type != JwtTokenType::Access {
            return Err(JwtError::NotAnAccessToken);
        }

        Ok((claims, payload))
    }

    /// Decodes the given refresh token and makes sure the token can be used at the current time.
    pub fn decode_refresh_token<T>(&self, token: impl Into<String>) -> Result<T>
    where
        for<'a> T: Deserialize<'a>,
    {
        let (claims, payload) = self.decode_refresh_token_unchecked(token)?;
        self.guard_claims(&claims)?;

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
        let (header, claims, payload) = self.decode_jwt::<T, JwtTokenType>(token.into())?;

        let Some(token_type) = header.cty else {
            return Err(JwtError::NotARefreshToken);
        };

        if token_type != JwtTokenType::Refresh {
            return Err(JwtError::NotARefreshToken);
        }

        Ok((claims, payload))
    }

    /// Decodes a JWT token and only returns the claims.
    pub fn decode_claims<H>(&self, token: impl Into<String>) -> Result<JwtClaims>
    where
        for<'a> H: Serialize + Deserialize<'a>,
    {
        let claims = self.decode_jwt::<(), H>(token)?.1;
        self.guard_claims(&claims)?;

        Ok(claims)
    }

    /// Decodes a JWT token and only returns the claims. Does not perform any checks other than
    /// checking the signature of the token.
    pub fn decode_claims_unchecked<H>(&self, token: impl Into<String>) -> Result<JwtClaims>
    where
        for<'a> H: Serialize + Deserialize<'a>,
    {
        Ok(self.decode_jwt::<(), H>(token)?.1)
    }

    /// Decodes the given JWT token and returns all the given important parts of the token. It
    /// doesn't perform any checks apart from checking the signature. All checks should done by
    /// the caller. If you created a token using either the [create_access_token] or
    /// [create_refresh_token] method, make sure to use decode methods for those instead of
    /// this one.
    pub fn decode_jwt<T, H>(&self, token: impl Into<String>) -> Result<(JwtHeader<H>, JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
        for<'a> H: Serialize + Deserialize<'a>,
    {
        let token = token.into();

        let mut parts = token.split('.');
        let header_part = parts.next().ok_or(JwtError::MissingHeader)?;

        let payload_part = parts.next().ok_or(JwtError::MissingPayload)?;

        let signature = parts.next().ok_or(JwtError::MissingSignature)?;

        let signature_check = self.sign_key(header_part, payload_part)?;

        if signature_check != signature {
            return Err(JwtError::InvalidSignature);
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

    pub fn decode_payload_against_claims<T, H>(
        &self,
        token: impl Into<String>,
        claims: &JwtClaims,
    ) -> Result<T>
    where
        for<'a> T: Deserialize<'a>,
        for<'a> H: Serialize + Deserialize<'a>,
    {
        Ok(self.decode_against_claims::<T, H>(token, claims)?.2)
    }

    pub fn decode_against_claims<T, H>(
        &self,
        token: impl Into<String>,
        claims: &JwtClaims,
    ) -> Result<(JwtHeader<H>, JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
        for<'a> H: Serialize + Deserialize<'a>,
    {
        let decoded = self.decode_jwt(token)?;
        self.guard_against_claims(&decoded.1, claims)?;

        Ok(decoded)
    }

    /// Takes the JWT payload as a raw JSON object and returns the claims and payload for
    /// that object.
    fn split_payload<T>(payload_value: Value) -> Result<(JwtClaims, T)>
    where
        for<'a> T: Deserialize<'a>,
    {
        let Value::Object(_) = payload_value else {
            return Err(
                JwtError::PayloadIsNotJson
            );
        };

        let claims = serde_json::from_value(payload_value.clone())?;
        let payload = serde_json::from_value(payload_value)?;

        Ok((claims, payload))
    }

    /// Checks the 'not before' and 'expire at' claims and returns an Err result if something does
    /// not match.
    pub fn guard_claims(&self, claims: &JwtClaims) -> Result<()> {
        self.guard_against_claims(
            claims,
            &JwtClaims {
                iss: Some(self.issuer.to_string()),
                ..JwtClaims::default()
            },
        )
    }

    /// Takes claims and compares the `iss`, `exp`, and `nbf` claims to the target claims.
    pub fn guard_against_claims(
        &self,
        claims: &JwtClaims,
        target_claims: &JwtClaims,
    ) -> Result<()> {
        if let Some(target_nbf) = target_claims.nbf {
            let Some(nbf) = claims.nbf else {
                return Err(JwtError::MissingNbfClaim);
            };

            if nbf < target_nbf {
                return Err(JwtError::UsedBeforeNotBeforeClaim);
            }
        }

        if let Some(target_exp) = target_claims.exp {
            let Some(exp) = claims.exp else {
                return Err(JwtError::MissingExpClaim);
            };

            if target_exp > exp {
                return Err(JwtError::UsedAfterExpireClaim);
            }
        }

        if let Some(target_aud) = &target_claims.aud {
            let Some(aud) = &claims.aud else {
                return Err(JwtError::MissingAudClaim);
            };

            if target_aud != aud {
                return Err(JwtError::MismatchedAudienceClaim);
            }
        }

        if let Some(target_iss) = &target_claims.iss {
            let Some(iss) = &claims.iss else {
                return Err(JwtError::MissingIssClaim);
            };

            if target_iss != iss {
                return Err(JwtError::MismatchedIssuerClaim);
            }
        }

        Ok(())
    }

    /// Returns true if all the 'not before' and 'expire at' claims are valid and returns false
    /// otherwise.
    pub fn check_claims(&self, claims: &JwtClaims) -> bool {
        self.guard_claims(claims).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rsa::{BigUint, RsaPrivateKey};
    use serde::{Deserialize, Serialize};

    use crate::errors::JwtError;
    use crate::models::jwt::{JwtClaims, JwtHeader, JwtTokenType};
    use crate::services::jwt_service::Duration;
    use crate::services::JwtService;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestPayload {
        username: String,
    }

    fn create_jwt_service() -> JwtService {
        JwtService::new(
            RsaPrivateKey::from_components(
                BigUint::from_str("74997830905646587139816226014144719862265627823949553374295905850158141318656719276313209175746760261055971134897398913479558563360202476134525738215443985213798786134947536321820103185111448036430087812065337288385932817127530120303914818733328961756008475729319280311987156480371871574865965853381575857139")
                    .unwrap(),
                BigUint::from(65537_u32),
                BigUint::from_str("45617567685304330426392636489339624454422611989351069566192497290154477430849944314077138980618476651150864051610769685643768298994884588952051505294448065757179269826950503958317081444597140993894151600136581876170515114272651619643521680297034232277886955997006233794078043072977551674990209356559104937817")
                    .unwrap(),
                vec![
                    BigUint::from_str("9944441522010244646787246177965507622037745736058678614688713158939513831023761630710456709828736517464244174020145137823187668945784719572371232406003647")
                        .unwrap(),
                    BigUint::from_str("7541683536441165394165027564769197112271246852984650020233604313173600283919646980685011266989909442158283534805756431333923018511568340875819132987922637")
                        .unwrap(),
                ],
            )
                .unwrap(),
            Duration::seconds(300),
            Duration::days(90),
            "tester",
            "internal-tests",
        )
    }

    fn create_jwt_claims() -> JwtClaims {
        JwtClaims {
            iss: Some(String::from("tester")),
            sub: Some(String::from("Testing")),
            aud: Some(String::from("internal-tests")),
            exp: Some(10),
            nbf: Some(20),
            iat: Some(30),
            jti: Some("".to_string()),
        }
    }

    #[test]
    fn jwt_token_can_be_generated() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_token::<TestPayload, JwtTokenType>(
                JwtHeader::default(),
                create_jwt_claims(),
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let parts = jwt_service
            .decode_jwt::<TestPayload, JwtTokenType>(token)
            .unwrap();

        assert_eq!(parts.0.typ, "JWT");
        assert_eq!(parts.0.alg, "RS256");
        assert_eq!(parts.1.exp, Some(10));
        assert_eq!(parts.1.nbf, Some(20));
        assert_eq!(parts.1.iat, Some(30));
        assert_eq!(parts.2.username, "Alice");
    }

    #[test]
    fn jwt_token_can_be_generated_with_borrowed_payload() {
        let jwt_service = create_jwt_service();

        let payload = TestPayload {
            username: "Alice".to_string(),
        };

        let token = jwt_service
            .create_token::<&TestPayload, JwtTokenType>(
                JwtHeader::default(),
                create_jwt_claims(),
                &payload,
            )
            .unwrap();

        let parts = jwt_service
            .decode_jwt::<TestPayload, JwtTokenType>(token)
            .unwrap();

        assert_eq!(parts.0.typ, "JWT");
        assert_eq!(parts.0.alg, "RS256");
        assert_eq!(parts.1.exp, Some(10));
        assert_eq!(parts.1.nbf, Some(20));
        assert_eq!(parts.1.iat, Some(30));
        assert_eq!(parts.2.username, "Alice");
    }

    #[test]
    fn jwt_access_token_can_be_generated() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_access_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let parts = jwt_service
            .decode_jwt::<TestPayload, JwtTokenType>(token)
            .unwrap();

        assert_eq!(parts.0.typ, "JWT");
        assert_eq!(parts.0.alg, "RS256");
        assert_eq!(parts.0.cty.unwrap(), JwtTokenType::Access);
        assert_eq!(parts.1.iss, Some("tester".to_string()));
        assert_eq!(parts.1.aud, Some("internal-tests".to_string()));
        assert_eq!(parts.2.username, "Alice");
    }

    #[test]
    fn jwt_refresh_token_can_be_generated() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_refresh_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let parts = jwt_service
            .decode_jwt::<TestPayload, JwtTokenType>(token)
            .unwrap();

        assert_eq!(parts.0.typ, "JWT");
        assert_eq!(parts.0.alg, "RS256");
        assert_eq!(parts.0.cty.unwrap(), JwtTokenType::Refresh);
        assert_eq!(parts.1.iss, Some("tester".to_string()));
        assert_eq!(parts.1.aud, Some("internal-tests".to_string()));
        assert_eq!(parts.2.username, "Alice");
    }

    #[test]
    fn payload_that_is_not_a_json_object_returns_err() {
        let result = create_jwt_service().create_access_token("Alice", "not-a-json-object");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), JwtError::PayloadNotAnObject);
    }

    #[test]
    fn jwt_access_token_can_be_decoded() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_access_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let payload: TestPayload = jwt_service.decode_access_token(token).unwrap();

        assert_eq!(payload.username, "Alice");
    }

    #[test]
    fn cannot_decode_refresh_token_as_access_token() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_refresh_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let result = jwt_service.decode_access_token::<TestPayload>(token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), JwtError::NotAnAccessToken);
    }

    #[test]
    fn jwt_refresh_token_can_be_decoded() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_refresh_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let payload: TestPayload = jwt_service.decode_refresh_token(token).unwrap();

        assert_eq!(payload.username, "Alice");
    }

    #[test]
    fn cannot_decode_access_token_as_refresh_token() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_access_token(
                "Alice",
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let result = jwt_service.decode_refresh_token::<TestPayload>(token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), JwtError::NotARefreshToken);
    }

    #[test]
    fn signature_is_checked_correctly() {
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFjY2VzcyJ9.eyJhdWQiOiJpbnRlcm5hbC10ZXN0cyIsImV4cCI6MTY4MDk2NzQwNCwiaWF0IjoxNjgwOTY3MTA0LCJpc3MiOiJ0ZXN0ZXIiLCJqdGkiOiJkNTA4NjYyYS1kZmVhLTQ2MWQtOWNhYy1jNDY1MTA4YmFmNWUiLCJuYmYiOjE2ODA5NjcxMDQsInN1YiI6IkFsaWNlIiwidXNlcm5hbWUiOiJBbGljZSJ9.abcdef";

        let result = create_jwt_service().decode_access_token::<TestPayload>(token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), JwtError::InvalidSignature);
    }

    #[test]
    fn aud_claim_is_checked_correctly() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_token::<_, JwtTokenType>(
                JwtHeader::default(),
                JwtClaims {
                    aud: Some("audience".to_string()),
                    ..JwtClaims::default()
                },
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let pass = jwt_service.decode_against_claims::<TestPayload, JwtTokenType>(
            &token,
            &JwtClaims {
                aud: Some("audience".to_string()),
                ..JwtClaims::default()
            },
        );

        let fail = jwt_service.decode_against_claims::<TestPayload, JwtTokenType>(
            &token,
            &JwtClaims {
                aud: Some("not-the-same".to_string()),
                ..JwtClaims::default()
            },
        );

        dbg!(&pass);
        assert!(pass.is_ok());
        assert!(fail.is_err());
    }

    #[test]
    fn missing_aud_claim_is_checked_correctly() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_token::<_, JwtTokenType>(
                JwtHeader::default(),
                JwtClaims {
                    aud: None,
                    ..JwtClaims::default()
                },
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let fail = jwt_service.decode_against_claims::<JwtTokenType, TestPayload>(
            &token,
            &JwtClaims {
                aud: Some("audience".to_string()),
                ..JwtClaims::default()
            },
        );

        assert!(fail.is_err());
    }

    #[test]
    fn iss_claim_is_checked_correctly() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_token::<_, JwtTokenType>(
                JwtHeader::default(),
                JwtClaims {
                    iss: Some("issuer".to_string()),
                    ..JwtClaims::default()
                },
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let pass = jwt_service.decode_against_claims::<TestPayload, JwtTokenType>(
            &token,
            &JwtClaims {
                iss: Some("issuer".to_string()),
                ..JwtClaims::default()
            },
        );

        let fail = jwt_service.decode_against_claims::<TestPayload, JwtTokenType>(
            &token,
            &JwtClaims {
                iss: Some("not-the-same".to_string()),
                ..JwtClaims::default()
            },
        );

        dbg!(&pass);
        assert!(pass.is_ok());
        assert!(fail.is_err());
    }

    #[test]
    fn missing_iss_claim_is_checked_correctly() {
        let jwt_service = create_jwt_service();

        let token = jwt_service
            .create_token::<_, JwtTokenType>(
                JwtHeader::default(),
                JwtClaims {
                    iss: None,
                    ..JwtClaims::default()
                },
                TestPayload {
                    username: "Alice".to_string(),
                },
            )
            .unwrap();

        let fail = jwt_service.decode_against_claims::<JwtTokenType, TestPayload>(
            &token,
            &JwtClaims {
                iss: Some("issuer".to_string()),
                ..JwtClaims::default()
            },
        );

        assert!(fail.is_err());
    }
}
