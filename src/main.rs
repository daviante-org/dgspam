#[tokio::main]
async fn main() {
    let code = dgspamguard::cli::run_from_env().await;
    std::process::exit(code);
}
