#!/bin/bash
#
# Setup Training Environment for GEPA Optimization
# 
# This script configures system resources to handle long-running
# GEPA optimization without hitting file descriptor limits.
#

set -e

echo "======================================================================="
echo "  GEPA Training Environment Setup"
echo "======================================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check current ulimit
CURRENT_ULIMIT=$(ulimit -n)
echo "📊 Current file descriptor limit: $CURRENT_ULIMIT"

# Recommended minimum
RECOMMENDED=4096

if [ "$CURRENT_ULIMIT" -lt "$RECOMMENDED" ]; then
    echo -e "${YELLOW}⚠️  WARNING: File descriptor limit is below recommended value${NC}"
    echo "   Current: $CURRENT_ULIMIT"
    echo "   Recommended: $RECOMMENDED"
    echo ""
    echo "🔧 Attempting to increase limit..."
    
    # Try to increase for current session
    ulimit -n $RECOMMENDED 2>/dev/null && {
        echo -e "${GREEN}✅ Successfully increased to $(ulimit -n) for this session${NC}"
    } || {
        echo -e "${RED}❌ Could not increase automatically${NC}"
        echo ""
        echo "Please run manually:"
        echo "   ulimit -n $RECOMMENDED"
        echo ""
        echo "Or for permanent change, add to your shell config:"
        
        # Detect shell
        if [ -n "$ZSH_VERSION" ]; then
            CONFIG_FILE="$HOME/.zshrc"
            echo "   echo 'ulimit -n $RECOMMENDED' >> ~/.zshrc"
        elif [ -n "$BASH_VERSION" ]; then
            CONFIG_FILE="$HOME/.bash_profile"
            echo "   echo 'ulimit -n $RECOMMENDED' >> ~/.bash_profile"
        else
            echo "   (Add 'ulimit -n $RECOMMENDED' to your shell config)"
        fi
        
        echo ""
        read -p "Would you like to add this to your shell config? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ -n "$CONFIG_FILE" ]; then
                echo "ulimit -n $RECOMMENDED" >> "$CONFIG_FILE"
                echo -e "${GREEN}✅ Added to $CONFIG_FILE${NC}"
                echo "   Please restart your shell or run: source $CONFIG_FILE"
            fi
        fi
    }
else
    echo -e "${GREEN}✅ File descriptor limit is adequate${NC}"
fi

echo ""
echo "======================================================================="
echo "  System Information"
echo "======================================================================="

# Check available memory
if command -v free &> /dev/null; then
    echo "💾 Memory:"
    free -h | grep -E "Mem:|Swap:"
elif command -v vm_stat &> /dev/null; then
    # macOS
    echo "💾 Memory (macOS):"
    vm_stat | head -5
fi

echo ""

# Check disk space
echo "💿 Disk space for threat_detector_optimized:"
if [ -d "threat_detector_optimized" ]; then
    du -sh threat_detector_optimized
else
    echo "   Directory not yet created"
fi

echo ""
echo "======================================================================="
echo "  Training Tips"
echo "======================================================================="
echo ""
echo "1. 🧹 Clean up old training runs to save disk space:"
echo "   rm -rf threat_detector_optimized/v_OLD_TIMESTAMP"
echo ""
echo "2. 📊 Monitor resource usage during training:"
echo "   watch -n 5 'lsof -p \$(pgrep -f train_gepa) | wc -l'"
echo "   watch -n 5 'ps aux | grep train_gepa'"
echo ""
echo "3. 🔄 If training fails, you can resume by running again"
echo "   (The script will create a new version)"
echo ""
echo "4. ⚡ For faster training, reduce max_iterations:"
echo "   Edit TRAINING_CONFIG in src/trust/core/config.py"
echo ""
echo "======================================================================="
echo "  Ready to Train!"
echo "======================================================================="
echo ""
echo "Run training with:"
echo "   python src/trust/optimizer/train_gepa.py"
echo ""
