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
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct ApiGateway;

impl ApiGateway {
    pub async fn serve(port: u16, routes: Router) -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "LOG=debug,tower_http=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();

        let middleware = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::permissive())
            .layer(HandleErrorLayer::new(handle_error))
            .timeout(Duration::from_secs(30))
            .load_shed()
            .into_inner();

        let app = routes
            .fallback(handler_404.into_service())
            .layer(middleware);

        info!("Starting Server...");
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
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