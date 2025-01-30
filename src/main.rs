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
    // exit case
    if !matches!(args.len(), 2 | 4 | 5)  {
        eprintln!("Invalid arguments. Use --help for usage instructions.");
        return Ok(());
    }
    // user wants help
    if args.len() == 2 {
        if args[1] == "--help" || args[1] == "-h" {
            println!(
                "------------------------------------------------------------
Missing File Finder v1.1.0
------------------------------------------------------------
Usage:
    {} <source_dir> <target_dir> <compare_mode: name|hash> [output_file]

Description:
    This tool compares files in a source directory against a target directory
    to identify files that are missing in the target.

Options:
    --help, -h          Show this help message
    <compare_mode>      'name'  -> Compare based on file names
                        'hash'  -> Compare based on file contents
    [output_file]       (Optional) Path to output file (default: missing_files_report.txt)

Example:
    {} /home/user/source /home/user/backup hash
------------------------------------------------------------",
                args[0], args[0]
            ); 
        }
        else {
            eprintln!("Invalid arguments. Use --help for usage instructions.");
        }
        return Ok(());
    }
    
    // valid input
    let output_file = if args.len() == 5 {
        Path::new(&args[4]).to_path_buf() // Use user-specified output file
    } else {
        Path::new("missing_files_report.txt").to_path_buf() // Default output file
    };

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

    let report_filename = output_file.to_str().unwrap_or("missing_files_report.txt");

    let user = env::var("USER")
    .or_else(|_| env::var("USERNAME")) // Fallback for Windows
    .unwrap_or_else(|_| "Unknown".into());

    info!("Writing report to '{}'", report_filename);
    match write_report(
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
    ){
        Ok(_) => info!("Report saved to {}", report_filename),
        Err(e) => {
            error!("Critical Error writing report: {}", e);
            panic!("Error writing report: {}", e);
        }
    }

    info!("Comparison completed. {} missing files found.", missing_files.len());
    info!("Report saved to {}", report_filename);

    info!(
        "Comparison completed in {:.2?} seconds.",
        duration.as_secs_f64()
    );

    Ok(())
}