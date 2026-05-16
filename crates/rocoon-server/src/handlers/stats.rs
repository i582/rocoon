use crate::ServerState;
use crate::http::{HandlerResult, Json};
use crate::stats::StatsResponse;

/// Handles `GET /stats`, `GET /jsonstats`, and `GET /v1/stats`.
pub fn handle(state: &ServerState) -> HandlerResult<Json<StatsResponse>> {
    let client_status = state.client()?.status();
    let stats_response = {
        let server_stats = state.stats()?;
        server_stats.to_response(&client_status)
    };
    Ok(Json::ok(stats_response))
}
