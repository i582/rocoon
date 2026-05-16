use anyhow::{Context, Result};
use rocoon_client::ModelInfo;
use rocoon_config::{RuntimeConfig, color::OwoColorize};

pub fn list(config: &RuntimeConfig) -> Result<()> {
    let models = fetch(config)?;
    print_list(&models);
    Ok(())
}

pub fn inspect(config: &RuntimeConfig, model_id: &str) -> Result<()> {
    let models = fetch(config)?;
    let Some(model) = models.iter().find(|model| model.id == model_id) else {
        anyhow::bail!(
            "model {} was not found. Run {} to see available models.",
            model_id.cyan().bold(),
            "rocoon models list".cyan().bold()
        );
    };
    print_model(model);
    Ok(())
}

fn fetch(config: &RuntimeConfig) -> Result<Vec<ModelInfo>> {
    let mut client = crate::connect_cocoon_interactive(config)?;
    println!("{} Fetching models", ">".cyan().bold());
    client.get_worker_types_v2().context("fetch Cocoon models")
}

fn print_list(models: &[ModelInfo]) {
    if models.is_empty() {
        println!("{} No models available", "✓".green().bold());
        return;
    }

    println!(
        "{} Available models: {}",
        "✓".green().bold(),
        models.len().to_string().cyan().bold()
    );
    for model in models {
        println!("{}", model.id.cyan().bold());
    }
}

fn print_model(model: &ModelInfo) {
    println!("{} Model {}", "✓".green().bold(), model.id.cyan().bold());
    println!("{} {}", "workers:".cyan().bold(), model.workers.len());
    if model.workers.is_empty() {
        return;
    }

    println!(
        "{:<6} {:>12} {:>12}",
        "#".cyan().bold(),
        "coefficient".cyan().bold(),
        "active/max".cyan().bold()
    );
    for (index, worker) in model.workers.iter().enumerate() {
        println!(
            "{:<6} {:>12} {:>12}",
            index + 1,
            worker.coefficient,
            format!("{}/{}", worker.active_requests, worker.max_active_requests)
        );
    }
}
