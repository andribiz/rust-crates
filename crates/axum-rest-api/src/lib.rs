pub mod errors;
pub mod routes;
use anyhow::Result;
use axum::{
    error_handling::HandleErrorLayer, handler::Handler, http::StatusCode, response::IntoResponse,
    BoxError, Router,
};
use std::{net::SocketAddr, time::Duration};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

pub struct ApiGateway<'a> {
    port: u16,
    root_path: &'a str,
}

impl<'a> ApiGateway<'a> {
    pub fn new(port: u16, root_path: &'a str) -> Self {
        Self { port, root_path }
    }

    pub async fn serve(&self, routes: Router, timeout: i64) -> Result<()> {
        let middleware = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::permissive())
            .layer(HandleErrorLayer::new(handle_error))
            .timeout(Duration::from_secs(timeout))
            .load_shed()
            .into_inner();

        let app = Router::new()
            .nest(self.root_path, routes)
            .fallback(handler_404.into_service())
            .layer(middleware);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        axum::Server::bind(&addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

pub async fn handle_error(error: BoxError) -> (StatusCode, String) {
    let mut code = StatusCode::INTERNAL_SERVER_ERROR;

    if error.is::<tower::timeout::error::Elapsed>() {
        code = StatusCode::REQUEST_TIMEOUT;
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        code = StatusCode::SERVICE_UNAVAILABLE;
    }

    (code, "Internal Error".to_owned())
}

pub async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}
