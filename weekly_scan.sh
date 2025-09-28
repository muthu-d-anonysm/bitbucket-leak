#!/bin/bash
# Example cron job script for weekly BitBucket scanning
# Add to crontab with: crontab -e
# 0 9 * * 1 /path/to/bitbucket-scanner/weekly_scan.sh

# Set working directory
cd /path/to/bitbucket-scanner

# Define targets to scan
TARGETS=("microsoft" "google" "apple" "facebook" "netflix" "uber")

# Discord webhook URL
DISCORD_WEBHOOK="https://discord.com/api/webhooks/1421839809634111560/cBIXvnYvZ3KLrMEEDwqBiXlxmRI-IH0gzio-V_871Kz_dw3qP7CExS8iYFBcsGueVKSJ"

echo "🚀 Starting weekly BitBucket scans..."
echo "📅 $(date)"

# Scan each target
for target in "${TARGETS[@]}"; do
    echo ""
    echo "🎯 Scanning $target..."

    # Create timestamp-based output directory
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="results/${target}/${TIMESTAMP}"

    # Run weekly scan with Discord alerts
    ./bin/bitbucket-scanner -t "$target" -o "$OUTPUT_DIR" --weekly --discord "$DISCORD_WEBHOOK" -c 4 -m 40

    if [ $? -eq 0 ]; then
        echo "✅ $target scan completed"
    else
        echo "❌ $target scan failed"
    fi

    # Add delay between targets to avoid rate limiting
    sleep 30
done

echo ""
echo "🎉 All weekly scans completed!"
echo "📅 $(date)"

# Optional: Clean up old scan results (keep last 30 days)
find results/ -name "20*" -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
find scanner_data/ -name "scan_*.json" -mtime +30 -delete 2>/dev/null || true

echo "🧹 Cleaned up old scan data"
