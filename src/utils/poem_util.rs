use std::ops::{
    Deref,
    DerefMut,
};
use poem::{
    async_trait,
    FromRequest,
    IntoResponse,
    Response,
    error::ParseJsonError,
    Request,
    RequestBody,
};
use reqwest::StatusCode;
use serde::{
    de::DeserializeOwned,
    Serialize,
};

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Json<T>(pub T);

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait]
impl<'a, T: DeserializeOwned> FromRequest<'a> for Json<T> {
    async fn from_request(_req: &'a Request, body: &mut RequestBody) -> Result<Self, poem::Error> {
        Ok(Self(serde_json::from_slice(&body.take()?.into_bytes().await?).map_err(ParseJsonError::Parse)?))
    }
}

impl<T: Serialize + Send> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        let data = match serde_json::to_vec(&self.0) {
            Ok(data) => data,
            Err(err) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(err.to_string())
            },
        };
        Response::builder().body(data)
    }
}
