use std::{
    io,
    env,
    path::Path,
    time::Instant,};
use log::{info, error};
use chrono::Local;
use missing_file_finder::{setup_logger, find_missing_files, write_report};


// -----------------------------------------------------------
// Main
// -----------------------------------------------------------
fn main() -> io::Result<()> {
    // Setup logging
    setup_logger().expect("Failed to initialize logger");

    // Parse args
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        println!(
            "Usage: {} <source_dir> <target_dir> <compare_mode: name|hash>\n\n\
            Compares files between a source and target directory to detect missing files.\n\n\
            Options:\n\
            --help, -h          Show this help message\n\
            <compare_mode>      'name' identifies missing files based on file names, 'hash' identifies missing files based on file contents\n\n\
            Example:\n\
            {} /path/to/source /path/to/target name",
            args[0], args[0]
        );
        return Ok(());
    }
    if args.len() != 4 {
        eprintln!("Invalid arguments. Use --help for usage instructions.");
        return Ok(());
    }

    let source_dir = Path::new(&args[1]);
    let target_dir = Path::new(&args[2]);
    let compare_mode = args[3].as_str();

    // Validate directories
    if !source_dir.is_dir() || !target_dir.is_dir() {
        eprintln!("Both arguments must be valid directories.");
        return Ok(());
    }

    let start_time = Instant::now();
    let start_timestamp = Local::now();

    info!(
        "Starting comparison between {:?} and {:?} using '{}' mode",
        source_dir, target_dir, compare_mode
    );

    // We'll collect missing files differently depending on compare mode.
    let (missing_files, found_files) = match find_missing_files(source_dir, target_dir, compare_mode) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("Error: {}", e);
            error!("Error: {}", e);
            return Err(e);
        }
    };

    if missing_files.is_empty() {
        info!("No missing files found.");
    } else {
        info!("{} missing files found.", missing_files.len());
    }

    let end_timestamp = Local::now();
    let duration = start_time.elapsed();

    let report_filename = "missing_files_report.txt";
    let user = env::var("USER")
    .or_else(|_| env::var("USERNAME")) // Fallback for Windows
    .unwrap_or_else(|_| "Unknown".into());

    info!("Writing report to '{}'", report_filename);
    write_report(
        report_filename,
        &user,
        &start_timestamp,
        &end_timestamp,
        &duration,
        source_dir,
        target_dir,
        compare_mode,
        &missing_files,
        &found_files,
    )?;

    info!("Comparison completed. {} missing files found.", missing_files.len());
    info!("Report saved to {}", report_filename);

    info!(
        "Comparison completed in {:.2?} seconds.",
        duration.as_secs_f64()
    );

    Ok(())
}