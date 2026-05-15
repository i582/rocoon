//! Types for `/v1/models`.

use async_openai::types::models::{
    ListModelResponse as OpenAiListModelResponse, Model as OpenAiModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ListModelResponse(OpenAiListModelResponse);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct Model(OpenAiModel);

impl Model {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(OpenAiModel {
            id: id.into(),
            object: "model".to_string(),
            created: 0,
            owned_by: "?".to_string(),
        })
    }
}

#[must_use]
pub fn make_response(models: impl IntoIterator<Item = Model>) -> ListModelResponse {
    ListModelResponse(OpenAiListModelResponse {
        object: "list".to_string(),
        data: models.into_iter().map(|model| model.0).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_response_builds_openai_model_list() {
        let response = make_response(["model-a", "model-b"].into_iter().map(Model::new));
        let response = serde_json::to_value(response).expect("models response should serialize");

        assert_eq!(response["object"], "list");
        assert_eq!(
            response["data"]
                .as_array()
                .expect("models response data should be an array")
                .len(),
            2
        );
        assert_eq!(response["data"][0]["id"], "model-a");
        assert_eq!(response["data"][0]["object"], "model");
        assert_eq!(response["data"][0]["owned_by"], "?");
    }
}
