# Missing File Finder

## Overview
This Rust application compares a source and target directory to identify files that exist in the source but are missing from the target. The target directory may have additional parent directories, and matches are detected accordingly. The tool can compare files by name or by hash for accuracy and efficiency.

## Features
- Compare directories by file name or content hash.
- Efficient hashing mechanism to avoid unnecessary full file hashing.
- Generates a report listing missing files with detailed metadata.
- Logs operations using the `fern` logging library.


## Installation
Ensure you have Rust installed. If not, install it via [Rustup](https://rustup.rs/):
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository and build the project:
```sh
git clone <https://github.com/Andrewsimsd/missing-file-finder>
cd <repository_name>
cargo build --release
```

## Usage
Run the application from the command line:
```sh
./target/release/missing_file_finder <source_directory> <target_directory> <comparison_method>
```

**Arguments:**
- `<source_directory>`: Path to the source directory. (The directory that contains the files you want to check for)
- `<target_directory>`: Path to the target directory. (The directory that you want to check if the files exist in)
- `<comparison_method>`: Either `name` for filename-based comparison or `hash` for content-based comparison.

### Example:
```sh
./missing_file_finder /home/user/source /mnt/backup name
```

## Output
The application generates a `missing_files_report.txt` with the following details:
- User who ran the report.
- Start and end timestamps.
- Duration of execution.
- Directories compared.
- Comparison method used.
- List of missing files with full paths from the source.

## Logging
Logs are saved in `compare_directories.log` with timestamps and operation details.

## License
This project is licensed under the MIT License. See `LICENSE` for details.

## Contributions
Contributions are welcome! Feel free to submit issues and pull requests.


