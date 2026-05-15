use std::net::TcpStream;

use rocoon_openai::models::{self as openai_models, Model};

use crate::ServerState;
use crate::http::{Error as HttpError, write_json};

/// Handles `GET /v1/models`.
pub fn handle(stream: &mut TcpStream, state: &ServerState) -> std::result::Result<(), HttpError> {
    let models = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .get_worker_types_v2()
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, &error))?;

    let response =
        openai_models::make_response(models.into_iter().map(|model| Model::new(model.id)));
    write_json(stream, 200, &response, Vec::new())
        .map_err(|error| HttpError::new(None, 500, &error))
}
