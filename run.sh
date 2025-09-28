#!/bin/bash
# Enhanced run script for BitBucket Scanner with Discord webhook support

if [ ! -f "bin/bitbucket-scanner" ]; then
    echo "⚠️  Binary not found. Building first..."
    ./build.sh
fi

if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <target> [options]"
    echo ""
    echo "Examples:"
    echo "  ./run.sh microsoft                     # Regular scan"
    echo "  ./run.sh microsoft --weekly            # Weekly diff scan"
    echo "  ./run.sh microsoft --weekly --discord  # Weekly with Discord alerts"
    echo "  ./run.sh google -c 5 -m 30             # Custom concurrency and repo limit"
    echo ""
    echo "Options:"
    echo "  --weekly     Only show new results compared to previous scan"
    echo "  --discord    Send Discord webhook alerts (uses default webhook)"
    echo "  -c N         Concurrent scans (default: 3)"
    echo "  -m N         Maximum repositories (default: 50)"
    echo "  -v           Verbose logging"
    echo ""
    exit 1
fi

TARGET=$1
shift  # Remove first argument

# Default Discord webhook (your provided webhook)
DISCORD_WEBHOOK="https://discord.com/api/webhooks/1421839809634111560/cBIXvnYvZ3KLrMEEDwqBiXlxmRI-IH0gzio-V_871Kz_dw3qP7CExS8iYFBcsGueVKSJ"

# Parse arguments to check for --discord flag
ARGS=()
USE_DISCORD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --discord)
            USE_DISCORD=true
            ARGS+=("--discord" "$DISCORD_WEBHOOK")
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="results/${TARGET}/${TIMESTAMP}"

echo "🎯 Scanning $TARGET..."
echo "📁 Output: $OUTPUT_DIR"

if $USE_DISCORD; then
    echo "🚨 Discord alerts enabled"
fi

# Check if this is a weekly scan
if [[ " ${ARGS[@]} " =~ " --weekly " ]]; then
    echo "📅 Weekly mode: Will compare with previous scan"
fi

echo ""

# Run the scanner with all arguments
./bin/bitbucket-scanner -t "$TARGET" -o "$OUTPUT_DIR" "${ARGS[@]}"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Scan completed!"
    echo "📋 Summary: $OUTPUT_DIR/summary_report.txt"
    echo "🔍 Full report: $OUTPUT_DIR/full_report.json"

    # Show weekly diff if it exists
    if [ -f "$OUTPUT_DIR/weekly_diff.txt" ]; then
        echo "📅 Weekly diff: $OUTPUT_DIR/weekly_diff.txt"
        echo ""
        echo "🔥 New Findings Summary:"
        head -30 "$OUTPUT_DIR/weekly_diff.txt"
    elif [ -f "$OUTPUT_DIR/summary_report.txt" ]; then
        echo ""
        echo "🔥 Quick Summary:"
        head -20 "$OUTPUT_DIR/summary_report.txt"
    fi

    # Show scanner data location
    echo ""
    echo "💾 Historical data stored in: scanner_data/$TARGET/"

else
    echo "❌ Scan failed!"
fi
