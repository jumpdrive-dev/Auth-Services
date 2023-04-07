use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtRefreshPayload {
    /// Id of the associated grant. A grant has to exist in order for the refresh token to be used.
    pub grant_id: String,
}
