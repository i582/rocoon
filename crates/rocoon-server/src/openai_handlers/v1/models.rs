use rocoon_openai::models::{self as openai_models, ListModelResponse, Model};

use crate::ServerState;
use crate::http::{HandlerResult, Json, bad_gateway};

/// Handles `GET /v1/models`.
pub fn handle(state: &ServerState) -> HandlerResult<Json<ListModelResponse>> {
    let models = state.client()?.get_worker_types_v2().map_err(bad_gateway)?;

    let response =
        openai_models::make_response(models.into_iter().map(|model| Model::new(model.id)));
    Ok(Json::ok(response))
}
