use color_eyre::eyre::OptionExt;

use super::Run;

#[derive(clap::Parser)]
pub struct Reset {}

impl Run for Reset {
    async fn run(self) -> Result<(), color_eyre::Report> {
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae")
            .ok_or_eyre("could not determine internal storage directory")?;

        // Remove the storage directory:
        let storage_dir = directories.data_local_dir();
        if storage_dir.exists() {
            println!("Removing storage directory: {}", storage_dir.display());
            tokio::fs::remove_dir_all(storage_dir).await?;
        } else {
            println!(
                "Storage directory does not exist: {}",
                storage_dir.display()
            );
        }

        Ok(())
    }
}
