use std::{collections::HashSet, env, fs, io::{self, Write}, path::{Path, PathBuf}, time::Instant};
use chrono::{Local, DateTime};
use walkdir::WalkDir;
use fern::Dispatch;
use log::{info, error};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

fn setup_logger() -> Result<(), fern::InitError> {
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!("{} [{}] - {}", Local::now().format("%Y-%m-%d %H:%M:%S"), record.level(), message))
        })
        .level(log::LevelFilter::Info)
        .chain(std::fs::File::create("compare_directories.log")?)
        .apply()?;
    Ok(())
}

fn collect_files(root: &Path, use_hashing: bool) -> io::Result<HashSet<String>> {
    let mut files = HashSet::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            if let Ok(relative) = entry.path().strip_prefix(root) {
                let file_identifier = if use_hashing {
                    match compute_hash(entry.path()) {
                        Ok(hash) => hash,
                        Err(_) => continue,
                    }
                } else {
                    relative.to_string_lossy().to_string()
                };
                files.insert(file_identifier);
            }
        }
    }
    Ok(files)
}

fn compute_hash(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 8192];
    let mut hasher = Sha256::new();

    let bytes_read = file.read(&mut buffer)?;
    hasher.update(&buffer[..bytes_read]);
    
    if bytes_read == 8192 {
        let mut remaining_bytes = vec![];
        file.read_to_end(&mut remaining_bytes)?;
        hasher.update(&remaining_bytes);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn write_report(report_filename: &str, user: &str, start_timestamp: &DateTime<Local>, end_timestamp: &DateTime<Local>, duration: &std::time::Duration, source_dir: &Path, target_dir: &Path, compare_mode: &str, missing_files: &[PathBuf]) -> io::Result<()> {
    let mut report = fs::File::create(report_filename)?;
    writeln!(report, "User: {}", user)?;
    writeln!(report, "Start Time: {}", start_timestamp.format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(report, "End Time: {}", end_timestamp.format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(report, "Duration: {:.2?}", duration)?;
    writeln!(report, "Source Directory: {:?}", source_dir)?;
    writeln!(report, "Target Directory: {:?}", target_dir)?;
    writeln!(report, "Comparison Method: {}\n", compare_mode)?;
    writeln!(report, "Files present in source directory, but not the target directory:")?;
    if missing_files.is_empty() {
        writeln!(report, "None")?;
    } else {
        for file in missing_files {
            writeln!(report, "{}", file.display())?;
        }
    } 
    
    Ok(())
}

fn main() -> io::Result<()> {
    setup_logger().expect("Failed to initialize logger");
    
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <source_dir> <target_dir> <compare_mode: name|hash>", args[0]);
        return Ok(());
    }
    
    let source_dir = Path::new(&args[1]);
    let target_dir = Path::new(&args[2]);
    let compare_mode = &args[3];
    let use_hashing = compare_mode == "hash";
    
    if !source_dir.is_dir() || !target_dir.is_dir() {
        eprintln!("Both arguments must be valid directories.");
        return Ok(());
    }
    
    let start_time = Instant::now();
    let start_timestamp: DateTime<Local> = Local::now();
    
    info!("Starting comparison between {:?} and {:?} using {:?} mode", source_dir, target_dir, compare_mode);
    
    let source_files = collect_files(source_dir, use_hashing)?;
    let target_files = collect_files(target_dir, use_hashing)?;
    
    let missing_files: Vec<PathBuf> = source_files.difference(&target_files)
        .map(|file| source_dir.join(file))
        .collect();
    
    let end_timestamp: DateTime<Local> = Local::now();
    let duration = start_time.elapsed();
    
    let report_filename = "missing_files_report.txt";
    write_report(report_filename, &env::var("USER").unwrap_or_else(|_| "Unknown".into()), &start_timestamp, &end_timestamp, &duration, source_dir, target_dir, compare_mode, &missing_files)?;
    
    info!("Comparison completed. {} missing files found.", missing_files.len());
    info!("Report saved to {}", report_filename);
    
    Ok(())
}