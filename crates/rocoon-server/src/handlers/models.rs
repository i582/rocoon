use rocoon_openai::models::{self as openai_models, Model};

use crate::ServerState;
use crate::http::{Error as HttpError, ServerResponse, json_response};

/// Handles `GET /v1/models`.
pub fn handle(state: &ServerState) -> std::result::Result<ServerResponse, HttpError> {
    let models = state
        .client
        .lock()
        .map_err(|_| HttpError::message(500, "Cocoon client mutex poisoned"))?
        .get_worker_types_v2()
        .map_err(|error| HttpError::new(502, &error))?;

    let response =
        openai_models::make_response(models.into_iter().map(|model| Model::new(model.id)));
    json_response(200, &response, Vec::new()).map_err(|error| HttpError::new(500, &error))
}
