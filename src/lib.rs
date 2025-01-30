use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    path::{Path},
};
use chrono::{Local, DateTime};
use fern::Dispatch;
use log::{error, info};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;
use rayon::prelude::*; // for parallel iterators

// -----------------------------------------------------------
// Logging Setup
// -----------------------------------------------------------
pub fn setup_logger() -> Result<(), fern::InitError> {
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(std::fs::File::create("missing_file_finder.log")?)
        .chain(std::io::stdout()) // Log to console
        .apply()?;
    Ok(())
}

// -----------------------------------------------------------
// Helpers for collecting file names or file hashes
// -----------------------------------------------------------

/// Collects file hashes in parallel, returning a `HashMap<hash, Vec<relative_path>>`.
fn collect_file_hashes_parallel(root: &Path) -> io::Result<HashMap<String, Vec<String>>> {
    use indicatif::{ProgressBar, ProgressStyle};
    // 1) Gather all file entries
    let paths: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .collect();
    #[cfg(not(test))]
    let pb = ProgressBar::new(paths.len() as u64);
    #[cfg(not(test))]
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} files ({eta})")
        .unwrap()
        .progress_chars("##-"));
    // 2) Compute hashes in parallel
    //    For each file, return Some((hash, relative_filename)) or None on error
    let hashed_entries: Vec<(String, String)> = paths
        .par_iter()
        .filter_map(|entry| {
            #[cfg(not(test))]
            pb.inc(1); // Increment progress bar
            let rel_path = match entry.path().strip_prefix(root) {
                Ok(rp) => rp.to_string_lossy().replace('\\', "/"),
                Err(_) => return None,
            };

            match compute_hash(entry.path()) {
                Ok(h) => Some((h, rel_path)),
                Err(e) => {
                    // you can log or handle error as needed
                    error!("Failed to hash file {:?}: {}", entry.path(), e);
                    None
                }
            }
        })
        .collect();
    #[cfg(not(test))]
    pb.finish_with_message("Hash computation complete");
    // 3) Group by hash in a standard HashMap
    let mut hash_map: HashMap<String, Vec<String>> = HashMap::new();

    for (hash, path_str) in hashed_entries {
        hash_map.entry(hash).or_default().push(path_str);
    }

    let file_count: usize = hash_map.values().map(Vec::len).sum();
    info!("Collected {} unique hashes covering {} files from {:?}", hash_map.len(), file_count, root);

    Ok(hash_map)
}

/// Collects file names (relative paths) as a `HashSet`.
fn collect_file_names(root: &Path) -> io::Result<HashSet<String>> {
    let mut names = HashSet::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            if let Ok(relative) = entry.path().strip_prefix(root) {
                // Normalize path separators
                let file_str = relative.to_string_lossy().replace('\\', "/");
                names.insert(file_str);
            }
        }
    }
    let count = names.len();
    info!("Collected {} file names from {:?}", count, root);

    Ok(names)
}

/// Computes SHA-256 hash of the file.
fn compute_hash(path: &Path) -> io::Result<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!("Cannot open file {:?}: {}", path, e);
            return Err(e);
        }
    };

    let mut buffer = [0; 8192];
    let mut hasher = Sha256::new();

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read file {:?}: {}", path, e);
                return Err(e);
            }
        };
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}


// -----------------------------------------------------------
// Missing-files extraction function
// -----------------------------------------------------------

/// Given a source directory, target directory, and a compare mode ("name" or "hash"),
/// returns a list of files in `source_dir` that are *not* present in `target_dir`.
/// 
/// - **"name"** mode: We compare relative filenames, ignoring content.
/// - **"hash"** mode: We compare file content (hashes). 
///   If a file’s content from source is not found in target (by hash), 
///   that file is considered missing.
/// 
/// The returned `Vec<String>` will list missing entries. In `hash` mode,
/// each missing file is listed as `"relative_path (hash)"`.
pub fn find_missing_files(
    source_dir: &Path,
    target_dir: &Path,
    compare_mode: &str,
) -> io::Result<(Vec<String>, Vec<String>)> {
    match compare_mode {
        "name" => {
            // single-threaded is fine for collecting names
            let source_names = collect_file_names(source_dir)?;
            let target_names = collect_file_names(target_dir)?;
            let missing_files: Vec<String> = source_names.difference(&target_names).cloned().collect();
            let found_files: Vec<String> = source_names.intersection(&target_names).cloned().collect();
            info!("{} files found, {} files missing using name comparison) between {:?} and {:?}", found_files.len(), missing_files.len(), source_dir, target_dir);
            Ok((missing_files, found_files))
        }
        "hash" => {
            // now use the new parallel version
            info!("Collecting source directory hashes.");
            let source_hashes = collect_file_hashes_parallel(source_dir)?;
            info!("Collecting target directory hashes.");
            let target_hashes = collect_file_hashes_parallel(target_dir)?;

            let source_keys: HashSet<_> = source_hashes.keys().cloned().collect();
            let target_keys: HashSet<_> = target_hashes.keys().cloned().collect();

            let missing_hashes = source_keys.difference(&target_keys);
            let mut results = Vec::new();
            for mh in missing_hashes {
                if let Some(file_list) = source_hashes.get(mh) {
                    // We'll format each missing file as "relative_path (hash)"
                    for f in file_list {
                        results.push(format!("{} ({})", f, mh));
                    }
                }
            }
            info!("Found {} missing files (hash comparison) between {:?} and {:?}", results.len(), source_dir, target_dir);
            let found_hashes: Vec<String> = source_keys.intersection(&target_keys).cloned().collect();
            let found_files: Vec<String> = found_hashes.iter()
                .filter_map(|hash| source_hashes.get(hash))
                .flatten()
                .cloned()
                .collect();

            Ok((results, found_files))
        }
        _ => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid compare mode '{}'. Use 'name' or 'hash'.", compare_mode),
            ))
        }
    }
}


// -----------------------------------------------------------
// Reporting
// -----------------------------------------------------------

/// Writes the final report.
pub fn write_report(
    report_filename: &str,
    user: &str,
    start_timestamp: &DateTime<Local>,
    end_timestamp: &DateTime<Local>,
    duration: &std::time::Duration,
    source_dir: &Path,
    target_dir: &Path,
    compare_mode: &str,
    missing_files: &[String],
    found_files: &[String],
) -> io::Result<()> {
    let mut report = fs::File::create(report_filename)?;
    writeln!(report, "User: {}", user)?;
    writeln!(report, "Start Time: {}", start_timestamp.format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(report, "End Time: {}", end_timestamp.format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(report, "Duration: {:.2?}", duration)?;
    writeln!(report, "Source Directory: {:?}", source_dir)?;
    writeln!(report, "Target Directory: {:?}", target_dir)?;
    writeln!(report, "Comparison Method: {}\n", compare_mode)?;

    writeln!(
        report,
        "Files present in source directory, but not in target directory:"
    )?;
    if missing_files.is_empty() {
        writeln!(report, "None")?;
    } else {
        for file in missing_files {
            writeln!(report, "{}", file)?;
        }
    }
    writeln!(report, "\nFiles found in both source and target directory:")?;
    if found_files.is_empty() {
        writeln!(report, "None")?;
    } else {
        for file in found_files {
            let full_path = source_dir.join(file);
            writeln!(report, "{} -> {:?}", file, full_path)?;
        }
    }
    Ok(())
}

// -----------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::{self, File};

    #[test]
    fn test_collect_file_names() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        fs::create_dir_all(root.join("sub"))?;
        File::create(root.join("file1.txt"))?.sync_all()?;
        File::create(root.join("sub/file2.txt"))?.sync_all()?;

        let names = collect_file_names(root)?;

        assert_eq!(names.len(), 2);
        assert!(names.contains("file1.txt"));
        assert!(names.contains("sub/file2.txt"));
        Ok(())
    }

    #[test]
    fn test_collect_file_hashes_parallel() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();
        fs::create_dir_all(root.join("sub"))?;
        {
            let mut f1 = File::create(root.join("file1.txt"))?;
            write!(f1, "Hello World!")?;
        }
        {
            let mut f2 = File::create(root.join("sub/file2.txt"))?;
            write!(f2, "This is a test!")?;
        }
        let hash_map = collect_file_hashes_parallel(root)?;
        assert_eq!(hash_map.len(), 2, "Should have two distinct hashes.");
        let mut total_files = 0;
        for list in hash_map.values() {
            total_files += list.len();
        }
        assert_eq!(total_files, 2);
        let all_filenames: Vec<&String> = hash_map.values().flatten().collect();
        assert!(all_filenames.contains(&&"file1.txt".to_string()));
        assert!(all_filenames.contains(&&"sub/file2.txt".to_string()));
        Ok(())
    }

    #[test]
    fn test_compute_hash_same_content() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        // Write two files with the same content
        let content = b"SAME_CONTENT";
        let file_a = root.join("a.txt");
        let file_b = root.join("b.txt");

        fs::write(&file_a, content)?;
        fs::write(&file_b, content)?;

        let hash_a = compute_hash(&file_a)?;
        let hash_b = compute_hash(&file_b)?;

        assert_eq!(hash_a, hash_b, "Files with the same content must have the same hash");
        Ok(())
    }

    #[test]
    fn test_compute_hash_diff_content() -> io::Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        // Write two files with different content
        let file_a = root.join("a.txt");
        let file_b = root.join("b.txt");

        fs::write(&file_a, b"CONTENT_A")?;
        fs::write(&file_b, b"CONTENT_B")?;

        let hash_a = compute_hash(&file_a)?;
        let hash_b = compute_hash(&file_b)?;

        assert_ne!(hash_a, hash_b, "Files with different content must not have the same hash");
        Ok(())
    }

    #[test]
    fn test_name_comparison_no_missing() -> io::Result<()> {
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::create_dir_all(src_root.join("sub"))?;
        fs::create_dir_all(tgt_root.join("sub"))?;

        fs::write(src_root.join("file1.txt"), b"Hello")?;
        fs::write(src_root.join("sub/file2.txt"), b"Hello")?;

        fs::write(tgt_root.join("file1.txt"), b"World")?;
        fs::write(tgt_root.join("sub/file2.txt"), b"World")?;

        let source_names = collect_file_names(src_root)?;
        let target_names = collect_file_names(tgt_root)?;
        let missing: Vec<String> = source_names.difference(&target_names).cloned().collect();

        assert!(missing.is_empty(), "Expected no missing files by name comparison.");
        Ok(())
    }

    #[test]
    fn test_name_comparison_some_missing() -> io::Result<()> {
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"A")?;
        fs::write(src_root.join("file2.txt"), b"B")?;
        fs::write(tgt_root.join("file1.txt"), b"A")?;

        let source_names = collect_file_names(src_root)?;
        let target_names = collect_file_names(tgt_root)?;
        let missing: Vec<String> = source_names.difference(&target_names).cloned().collect();

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "file2.txt");
        Ok(())
    }

    #[test]
    fn test_hash_comparison_no_missing() -> io::Result<()> {
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("a.txt"), b"IDENTICAL_CONTENT")?;
        fs::write(src_root.join("b.txt"), b"ANOTHER_CONTENT")?;
        fs::write(tgt_root.join("x.txt"), b"IDENTICAL_CONTENT")?;
        fs::write(tgt_root.join("y.txt"), b"ANOTHER_CONTENT")?;

        let src_hashes = collect_file_hashes_parallel(src_root)?;
        let tgt_hashes = collect_file_hashes_parallel(tgt_root)?;

        let src_keys: HashSet<_> = src_hashes.keys().cloned().collect();
        let tgt_keys: HashSet<_> = tgt_hashes.keys().cloned().collect();
        let missing_keys = src_keys.difference(&tgt_keys);

        assert_eq!(missing_keys.count(), 0, "No hash should be missing.");
        Ok(())
    }

    #[test]
    fn test_hash_comparison_some_missing() -> io::Result<()> {
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"SRC_CONTENT_1")?;
        fs::write(src_root.join("file2.txt"), b"SRC_CONTENT_2")?;
        fs::write(tgt_root.join("fileA.txt"), b"SRC_CONTENT_1")?;

        let src_hashes = collect_file_hashes_parallel(src_root)?;
        let tgt_hashes = collect_file_hashes_parallel(tgt_root)?;

        let src_keys: HashSet<_> = src_hashes.keys().cloned().collect();
        let tgt_keys: HashSet<_> = tgt_hashes.keys().cloned().collect();
        let missing_keys: Vec<_> = src_keys.difference(&tgt_keys).cloned().collect();

        assert_eq!(missing_keys.len(), 1, "Expect exactly 1 missing hash.");
        let missing_hash = missing_keys[0].as_str();
        let missing_files_for_hash = &src_hashes[missing_hash];
        assert_eq!(missing_files_for_hash.len(), 1);
        assert_eq!(missing_files_for_hash[0], "file2.txt");

        Ok(())
    }

    #[test]
    fn test_hash_comparison_same_hash_different_filenames() -> io::Result<()> {
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"COMMON_CONTENT")?;
        fs::write(src_root.join("file2.txt"), b"COMMON_CONTENT")?;
        fs::write(tgt_root.join("target_file1.txt"), b"COMMON_CONTENT")?;

        let src_hashes = collect_file_hashes_parallel(src_root)?;
        let tgt_hashes = collect_file_hashes_parallel(tgt_root)?;

        let src_keys: HashSet<_> = src_hashes.keys().cloned().collect();
        let tgt_keys: HashSet<_> = tgt_hashes.keys().cloned().collect();
        let missing_keys: Vec<_> = src_keys.difference(&tgt_keys).cloned().collect();

        assert!(missing_keys.is_empty(), "Should have no missing hash.");
        Ok(())
    }
    #[test]
    fn test_find_missing_files_name_no_missing() -> io::Result<()> {
        // Both directories have the same filenames, so no missing files.
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::create_dir_all(src_root.join("sub"))?;
        fs::create_dir_all(tgt_root.join("sub"))?;

        fs::write(src_root.join("file1.txt"), b"Hello")?;
        fs::write(src_root.join("sub/file2.txt"), b"Hello")?;

        fs::write(tgt_root.join("file1.txt"), b"World")?;
        fs::write(tgt_root.join("sub/file2.txt"), b"World")?;

        // Compare by name
        let (missing, found) = find_missing_files(src_root, tgt_root, "name")?;
        
        // Since all files are present, missing should be empty
        assert!(missing.is_empty(), "Expected no missing files by name comparison.");

        // Found files should contain both file1.txt and sub/file2.txt
        assert_eq!(found.len(), 2);
        assert!(found.contains(&"file1.txt".to_string()));
        assert!(found.contains(&"sub/file2.txt".to_string()));

        Ok(())
    }


    #[test]
    fn test_find_missing_files_name_some_missing() -> io::Result<()> {
        // Source has an extra file not in target
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"A")?;
        fs::write(src_root.join("file2.txt"), b"B")?;
        fs::write(tgt_root.join("file1.txt"), b"A")?;

        let (missing, found) = find_missing_files(src_root, tgt_root, "name")?;
        
        // We expect one missing file: "file2.txt"
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "file2.txt");

        // Found files should contain "file1.txt"
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], "file1.txt");

        Ok(())
    }


    #[test]
    fn test_find_missing_files_hash_no_missing() -> io::Result<()> {
        // If content is the same, the files should not be considered missing in hash mode
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;
    
        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();
    
        fs::write(src_root.join("a.txt"), b"IDENTICAL_CONTENT")?;
        fs::write(src_root.join("b.txt"), b"ANOTHER_CONTENT")?;
    
        fs::write(tgt_root.join("x.txt"), b"IDENTICAL_CONTENT")?;
        fs::write(tgt_root.join("y.txt"), b"ANOTHER_CONTENT")?;
    
        let (missing, found) = find_missing_files(src_root, tgt_root, "hash")?;
        
        // We expect no missing files since the contents are identical
        assert!(missing.is_empty(), "Expected no missing files by hash comparison.");
    
        // Found files should contain both "a.txt" and "b.txt"
        assert_eq!(found.len(), 2);
        Ok(())
    }
    

    #[test]
    fn test_find_missing_files_hash_some_missing() -> io::Result<()> {
        // Source has file2.txt that doesn't match anything in target
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"SRC_CONTENT_1")?;
        fs::write(src_root.join("file2.txt"), b"SRC_CONTENT_2")?;
        fs::write(tgt_root.join("target1.txt"), b"SRC_CONTENT_1")?;

        let (missing, found) = find_missing_files(src_root, tgt_root, "hash")?;
        
        // We expect exactly 1 missing file: "file2.txt"
        assert_eq!(missing.len(), 1);
        assert!(missing[0].contains("file2.txt"));
        
        // Found should contain "file1.txt"
        assert_eq!(found.len(), 1);
        Ok(())
    }


    #[test]
    fn test_find_missing_files_hash_same_hash_multiple_filenames() -> io::Result<()> {
        // Two files in source share the same hash, but target has only one
        // with that content. Because the hash is present, none are missing.
        let dir_src = TempDir::new()?;
        let dir_tgt = TempDir::new()?;

        let src_root = dir_src.path();
        let tgt_root = dir_tgt.path();

        fs::write(src_root.join("file1.txt"), b"COMMON_CONTENT")?;
        fs::write(src_root.join("file2.txt"), b"COMMON_CONTENT")?;
        fs::write(tgt_root.join("target_file.txt"), b"COMMON_CONTENT")?;

        let (missing, _) = find_missing_files(src_root, tgt_root, "hash")?;
        assert!(
            missing.is_empty(),
            "If the hash is present in the target, none should be missing."
        );
        Ok(())
    }

    #[test]
    fn test_find_missing_files_invalid_mode() {
        let dir_src = TempDir::new().unwrap();
        let dir_tgt = TempDir::new().unwrap();

        let result = find_missing_files(dir_src.path(), dir_tgt.path(), "invalid_mode");
        
        // Ensure function fails when an invalid mode is given
        assert!(result.is_err(), "Invalid mode should return an Err.");
    }

}