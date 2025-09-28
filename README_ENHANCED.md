# BitBucket Secret Scanner - Enhanced Version with Discord Alerts

A high-performance Go implementation with **Discord webhook integration** and **weekly diff tracking** for continuous monitoring of BitBucket repositories.

## 🚨 NEW FEATURES

### 📅 Weekly Diff Tracking
- **`--weekly`** flag compares current scan with previous scan
- Only reports **NEW secrets** found since last run  
- Perfect for continuous monitoring and automation
- Stores scan history in `scanner_data/{target}/` directory

### 🚨 Discord Webhook Alerts
- **`--discord`** flag sends rich alerts to Discord channel
- Beautiful embeds with repository links and secret details
- Shows verification status (✅ Verified secrets highlighted)
- Includes clickable repository URLs
- Groups findings by repository for easy analysis

### 💾 Persistent Storage
- Target-specific data storage prevents cross-contamination
- Historical scan data for trend analysis
- Unique hash-based deduplication prevents duplicate alerts
- Automatic cleanup of old data

## 🚀 Usage Examples

### Regular Scan
```bash
./bin/bitbucket-scanner -t microsoft
```

### Weekly Monitoring with Discord Alerts
```bash
./bin/bitbucket-scanner -t microsoft --weekly --discord "YOUR_WEBHOOK_URL"
```

### Using the Enhanced Run Script
```bash
# Regular scan
./run.sh microsoft

# Weekly scan with Discord alerts (uses built-in webhook)
./run.sh microsoft --weekly --discord

# Custom options
./run.sh google --weekly --discord -c 5 -m 30
```

## 📋 Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-t` | Target organization (required) | `-t microsoft` |
| `-o` | Output directory | `-o results/custom` |
| `-m` | Maximum repositories | `-m 50` |
| `-c` | Concurrent scans | `-c 3` |
| `--weekly` | Compare with previous scan | `--weekly` |
| `--discord` | Discord webhook URL | `--discord "https://discord.com/..."` |
| `-v` | Verbose logging | `-v` |

## 🎯 Perfect for Bug Bounty Automation

### Set Up Weekly Monitoring
```bash
# First scan (all secrets will be "new")
./bin/bitbucket-scanner -t microsoft --weekly --discord "YOUR_WEBHOOK"

# Future scans (only new secrets reported)
./bin/bitbucket-scanner -t microsoft --weekly --discord "YOUR_WEBHOOK"
```

### Automated Cron Job
```bash
# Edit crontab
crontab -e

# Add weekly scan every Monday at 9 AM
0 9 * * 1 /path/to/bitbucket-scanner/weekly_scan.sh
```

## 🚨 Discord Alert Features

### Rich Embed Format
- **Title**: Target organization and new secret count
- **Fields**: Grouped by repository with clickable links
- **Verification**: ✅ for verified secrets  
- **File paths**: Exact location of secrets
- **Timestamps**: When scan was performed
- **Color coding**: Red for alerts, green for no new findings

### Sample Discord Alert
```
🚨 New Secrets Found - microsoft
Found 3 new secrets across 2 repositories

🔑 2 secrets in vscode
microsoft/vscode
- AWS Access Key ✅
📁 config/aws.conf
- Generic API Key  
📁 src/main.py

🔑 1 secret in azure-cli
microsoft/azure-cli  
- Database Password
📁 tests/config.py
```

## 📁 Directory Structure

```
bitbucket-scanner/
├── bin/
│   └── bitbucket-scanner           # Compiled binary
├── results/
│   └── {target}/
│       └── {timestamp}/
│           ├── full_report.json
│           ├── summary_report.txt
│           ├── weekly_diff.json    # NEW
│           └── weekly_diff.txt     # NEW
├── scanner_data/                   # NEW
│   └── {target}/
│       ├── latest_scan.json       # For comparison
│       └── scan_{timestamp}.json  # Historical data
├── main.go
├── build.sh
├── run.sh                         # Enhanced
└── weekly_scan.sh                 # NEW - Cron example
```

## ⚙️ Setup & Installation

### Quick Setup
```bash
# Install and build
chmod +x setup_go.sh && ./setup_go.sh

# Test regular scan
./run.sh microsoft

# Test weekly scan with Discord
./run.sh microsoft --weekly --discord
```

### Configure Discord Webhook
1. Go to your Discord server settings
2. Navigate to Integrations → Webhooks
3. Create new webhook for your channel
4. Copy the webhook URL
5. Use with `--discord "YOUR_WEBHOOK_URL"`

## 🔄 How Weekly Mode Works

### First Scan
- All found secrets are considered "new"
- Full Discord alert sent with all findings
- Scan data saved to `scanner_data/{target}/latest_scan.json`

### Subsequent Weekly Scans
- Compares current findings with `latest_scan.json`
- Only NEW secrets (not seen before) trigger alerts
- Uses SHA256 hash for deduplication
- Updates stored scan data for next comparison

### Hash-Based Deduplication
Each secret gets a unique hash based on:
- Repository name
- File path  
- Rule/detector ID
- Secret content

This prevents duplicate alerts even if files move or formatting changes.

## 🎯 Bug Bounty Workflow

### 1. Initial Setup
```bash
# Scan major targets and establish baseline
./run.sh microsoft --weekly --discord
./run.sh google --weekly --discord  
./run.sh apple --weekly --discord
```

### 2. Weekly Monitoring
```bash
# Add to crontab for automated scanning
0 9 * * 1 /path/to/scanner/weekly_scan.sh
```

### 3. Instant Alerts
- New secrets automatically posted to Discord
- Click repository links to investigate
- Verified secrets (✅) are high-confidence findings
- File paths show exact location for reporting

## 🚨 Alert Management

### Reducing Noise
- Only NEW secrets trigger alerts (not duplicates)
- Verified secrets highlighted for priority
- Grouped by repository for context
- File paths included for quick investigation

### Managing Volume
- Set reasonable repository limits with `-m`
- Focus on high-value targets initially
- Use concurrent scanning (`-c`) for efficiency
- Regular cleanup of old historical data

## 🔧 Advanced Configuration

### Custom Output Directory Structure
```bash
./bin/bitbucket-scanner -t microsoft -o "scans/$(date +%Y-%m)/microsoft"
```

### High-Performance Scanning
```bash
# Aggressive settings for large targets
./bin/bitbucket-scanner -t microsoft -c 8 -m 100 --weekly --discord "WEBHOOK"
```

### Multiple Webhook Integration
```bash
# Different webhooks for different targets
./bin/bitbucket-scanner -t microsoft --weekly --discord "WEBHOOK_MSRC"
./bin/bitbucket-scanner -t google --weekly --discord "WEBHOOK_GOOGLE"
```

## 🛡️ Security & Privacy

- **Public repos only**: No authentication needed or used
- **Local processing**: Secrets analyzed locally, not sent externally
- **Discord webhooks**: Only send metadata and locations, not actual secrets
- **Automatic cleanup**: Temporary files removed after scanning
- **Hash-based storage**: Actual secrets not stored in scan data

## 📈 Performance & Scaling

### Optimized for Continuous Use
- **Incremental scanning**: Weekly mode only processes new findings
- **Efficient storage**: Hash-based deduplication reduces data size
- **Concurrent processing**: Parallel repository scanning
- **Rate limiting**: Built-in delays prevent API blocking
- **Memory efficient**: Streams large datasets without loading everything

### Resource Usage
- **Memory**: ~50MB average during scanning
- **Storage**: ~1-10MB per target per scan (historical data)
- **Network**: Respects Bitbucket API rate limits
- **CPU**: Scales with concurrent workers (`-c` flag)

## 🎉 Perfect for Professional Bug Bounty

This enhanced version transforms the scanner from a one-time tool into a **continuous monitoring system** perfect for:

- **Professional bug bounty hunters** running ongoing campaigns
- **Security teams** monitoring their organization's repositories  
- **Researchers** tracking secret exposure trends over time
- **Automated security pipelines** with instant alerting

**Get instant Discord notifications when new secrets appear in your target organizations!** 🚨

---

**Ready to start continuous monitoring? Set up your Discord webhook and run your first weekly scan!** 🎯
