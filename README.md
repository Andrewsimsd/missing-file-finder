# 🔍 Missing File Finder

**Version:** 1.1.0  
**Author:** Andrew Sims   
**License:** MIT  

## 📌 Overview

**Missing File Finder** is a Rust-based command-line tool designed to compare files between a **source** and **target** directory. It identifies files present in the source directory but missing in the target, based on either:
- **Filename** comparison (simple and fast)
- **File hash** comparison (content-based, ensuring true uniqueness)

This tool is **highly efficient**, featuring:
✅ **Parallel processing** (using Rayon)  
✅ **Real-time progress indicators**  
✅ **Logging to both file and console**  
✅ **Customizable output reports**  

---

## 🚀 Usage

Run the application from the command line:

```sh
missing_file_finder <source_dir> <target_dir> <compare_mode> [output_file]
```

### **Arguments**
| Argument       | Description                                      | Required | Example                    |
|---------------|--------------------------------------------------|----------|----------------------------|
| `<source_dir>` | Path to the source directory                    | ✅        | `/home/user/source`        |
| `<target_dir>` | Path to the target directory                    | ✅        | `/home/user/backup`        |
| `<compare_mode>` | `name` (filename-based) OR `hash` (content-based) | ✅        | `name` or `hash`           |
| `[output_file]` | Optional output report filename (default used if omitted) | ❌        | `missing_files_report.txt` |

---

### **Example Usage**
#### **Compare by Filename**
```sh
missing_file_finder /home/user/source /home/user/backup name
```
#### **Compare by Hash**
```sh
missing_file_finder /home/user/source /home/user/backup hash
```
#### **Specify Output Report File**
```sh
missing_file_finder /home/user/source /home/user/backup hash custom_report.txt
```
#### **Display Help Message**
```sh
missing_file_finder --help
```

---

## 📊 Features

✅ **Multi-threaded Execution:** Uses **Rayon** for parallel hashing.  
✅ **Real-time Progress Bar:** Uses **indicatif** to track processing.  
✅ **Log Output:** All operations are logged to `missing_file_finder.log`.  
✅ **Customizable Report Output:** Generates a structured `.txt` report.  
✅ **Error Handling:** Gracefully handles invalid inputs and access issues.  

---

## 📄 Report Format

The report includes:
- User information
- Start and end timestamps
- Duration of execution
- Source and target directory details
- Comparison method used
- List of missing files (if any)
- List of found files (if applicable)

Example:
```
User: johndoe
Start Time: 2025-01-30 14:15:00
End Time: 2025-01-30 14:15:05
Duration: 5.02s
Source Directory: /home/user/source
Target Directory: /home/user/backup
Comparison Method: hash

Files present in source directory, but not in target directory:
- documents/report.pdf (e3b0c4...)
- projects/code.rs (b4ef6d...)

Files found in both source and target directory:
- images/photo1.jpg -> /home/user/source/images/photo1.jpg
- music/song.mp3 -> /home/user/source/music/song.mp3
```

---

## ⚙️ Development & Testing

### **Run Tests**
The project includes unit tests for hash generation, filename collection, and file comparison. Run tests using:

```sh
cargo test
```

### **Debug Logging**
To enable debug logs while running:

```sh
RUST_LOG=debug cargo run --release -- <source_dir> <target_dir> hash
```


## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🛠️ Dependencies

- [**walkdir**](https://crates.io/crates/walkdir) - Recursive file traversal  
- [**rayon**](https://crates.io/crates/rayon) - Parallel computation  
- [**sha2**](https://crates.io/crates/sha2) - SHA-256 hashing  
- [**fern**](https://crates.io/crates/fern) - Logger backend  
- [**indicatif**](https://crates.io/crates/indicatif) - Progress bar  

---

