#!/bin/bash
# Documentation Cleanup Script
# 
# This script organizes documentation by:
# 1. Archiving session progress reports
# 2. Removing obsolete files
# 3. Consolidating duplicate quickstarts
# 
# IMPORTANT: Review docs/CLEANUP_PLAN.md before running!
# RECOMMENDED: Commit your changes before running this script

set -e  # Exit on error

echo "================================"
echo "Documentation Cleanup Script"
echo "================================"
echo ""

# Confirm before proceeding
read -p "Have you reviewed docs/CLEANUP_PLAN.md and committed your changes? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Exiting. Please review the plan and commit changes first."
    exit 1
fi

echo ""
echo "Starting cleanup..."
echo ""

# Create archive directories
echo "📁 Creating archive directories..."
mkdir -p docs/archive/session_reports
mkdir -p docs/archive/old_quickstarts
mkdir -p docs/archive/technical_details
mkdir -p docs/archive/deployment_reports

# ============================================================================
# CATEGORY 1: Archive Session Progress Reports
# ============================================================================
echo ""
echo "📦 Archiving session progress reports..."

SESSION_REPORTS=(
    "docs/ENHANCEMENTS_COMPLETE.md"
    "docs/IMPLEMENTATION_COMPLETE.txt"
    "docs/IMPLEMENTATION_SUMMARY.md"
    "docs/PERFORMANCE_COMPLETE.md"
    "docs/PERFORMANCE_IMPLEMENTATION_SUMMARY.md"
    "docs/SECURITY_COMPLETE.md"
    "docs/CODE_QUALITY_COMPLETION_SUMMARY.md"
    "docs/SESSION_SUMMARY.md"
    "docs/CROSS_LANGUAGE_ENHANCEMENT_SUMMARY.md"
    "docs/OPTION_A_PROGRESS_SUMMARY.md"
    "docs/TEST_FIXES_SUMMARY.md"
    "docs/PHASE1_CODE_QUALITY_COMPLETE.md"
)

for file in "${SESSION_REPORTS[@]}"; do
    if [ -f "$file" ]; then
        echo "  → Moving $file"
        git mv "$file" "docs/archive/session_reports/" 2>/dev/null || mv "$file" "docs/archive/session_reports/"
    fi
done

# Archive deployment summaries
if [ -f "deployment/DEPLOYMENT_FIXES.md" ]; then
    echo "  → Moving deployment/DEPLOYMENT_FIXES.md"
    git mv "deployment/DEPLOYMENT_FIXES.md" "docs/archive/deployment_reports/" 2>/dev/null || mv "deployment/DEPLOYMENT_FIXES.md" "docs/archive/deployment_reports/"
fi

if [ -f "deployment/SUMMARY.md" ]; then
    echo "  → Moving deployment/SUMMARY.md"
    git mv "deployment/SUMMARY.md" "docs/archive/deployment_reports/" 2>/dev/null || mv "deployment/SUMMARY.md" "docs/archive/deployment_reports/"
fi

# ============================================================================
# CATEGORY 2: Delete Obsolete TODO Files
# ============================================================================
echo ""
echo "🗑️  Removing obsolete TODO/action files..."

TODO_FILES=(
    "docs/NEXT_STEPS.md"
    "docs/CODE_QUALITY_ACTION_ITEMS.md"
)

for file in "${TODO_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  → Deleting $file (replaced by Shopify_showcase/ROADMAP.md)"
        git rm "$file" 2>/dev/null || rm "$file"
    fi
done

# Archive or delete current_progress
if [ -d "current_progress" ]; then
    echo "  → Archiving current_progress/plan.md"
    if [ -f "current_progress/plan.md" ]; then
        git mv "current_progress/plan.md" "docs/archive/session_reports/" 2>/dev/null || mv "current_progress/plan.md" "docs/archive/session_reports/"
    fi
    rmdir "current_progress" 2>/dev/null || echo "  ⚠️  current_progress/ not empty, skipping removal"
fi

# ============================================================================
# CATEGORY 3: Archive Duplicate Quickstarts
# ============================================================================
echo ""
echo "📦 Archiving duplicate quickstart guides..."

QUICKSTART_FILES=(
    "docs/QUICKSTART_ML.md"
    "docs/CODE_QUALITY_QUICKSTART.md"
    "docs/ENHANCEMENTS_QUICKSTART.md"
    "docs/CODE_QUALITY_SETUP.md"
)

for file in "${QUICKSTART_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  → Moving $file"
        git mv "$file" "docs/archive/old_quickstarts/" 2>/dev/null || mv "$file" "docs/archive/old_quickstarts/"
    fi
done

# ============================================================================
# CATEGORY 4: Archive Old Technical Docs
# ============================================================================
echo ""
echo "📦 Archiving old technical documentation..."

TECH_DOCS=(
    "docs/RESEARCH_ENHANCEMENTS.md"
    "docs/SECURITY_ENHANCEMENTS.md"
    "docs/PERFORMANCE_OPTIMIZATIONS.md"
)

for file in "${TECH_DOCS[@]}"; do
    if [ -f "$file" ]; then
        echo "  → Moving $file"
        git mv "$file" "docs/archive/technical_details/" 2>/dev/null || mv "$file" "docs/archive/technical_details/"
    fi
done

# ============================================================================
# CATEGORY 5: Clean Up Other Directories
# ============================================================================
echo ""
echo "🧹 Cleaning up other directories..."

# Remove .bak files
if [ -f "src/trust/validators/missinformation.py.bak" ]; then
    echo "  → Deleting src/trust/validators/missinformation.py.bak"
    rm "src/trust/validators/missinformation.py.bak"
fi

# Handle duplicate failures_production.json
if [ -f "examples/failures_production.json" ] && [ -f "failures_production.json" ]; then
    echo "  → Checking if examples/failures_production.json is duplicate..."
    if cmp -s "examples/failures_production.json" "failures_production.json"; then
        echo "  → Deleting duplicate examples/failures_production.json"
        rm "examples/failures_production.json"
    else
        echo "  ⚠️  Files differ, keeping both"
    fi
fi

# Archive enhanced README in examples
if [ -f "examples/README_ENHANCED.md" ]; then
    echo "  → Archiving examples/README_ENHANCED.md"
    git mv "examples/README_ENHANCED.md" "docs/archive/old_quickstarts/" 2>/dev/null || mv "examples/README_ENHANCED.md" "docs/archive/old_quickstarts/"
fi

# ============================================================================
# CATEGORY 6: Create Archive Index
# ============================================================================
echo ""
echo "📝 Creating archive index..."

cat > docs/archive/README.md << 'EOF'
# Documentation Archive

This directory contains historical documentation from the project's development.

## Purpose

These documents are **archived for historical reference** but are no longer part of the active documentation. They represent:
- Session progress reports from different development phases
- Old versions of quickstart guides
- Previous technical implementation docs
- Deployment fix reports

## Archive Structure

### `session_reports/`
Progress summaries from different work sessions (2024):
- Enhancement implementation reports
- Performance optimization summaries
- Code quality completion reports
- Security implementation summaries

### `old_quickstarts/`
Previous versions of getting started guides:
- ML-specific quickstarts
- Code quality setup guides
- Feature enhancement quickstarts

### `technical_details/`
Old technical implementation documentation:
- Research enhancement details
- Security implementation specifics
- Performance optimization details

### `deployment_reports/`
Deployment fixes and summaries from earlier phases.

## Current Documentation

For **current, user-facing documentation**, see:
- `/docs/` - Core documentation (README, QUICKSTART, ARCHITECTURE, etc.)
- `/Shopify_showcase/` - Latest comprehensive documentation (SHOWCASE, SECURITY_SYSTEM, ROADMAP)

## Note

These archived files are kept for:
1. Historical reference
2. Understanding project evolution
3. Potential content mining for future docs

If you need to reference implementation details, check here first before asking questions!
EOF

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "================================"
echo "✅ Cleanup Complete!"
echo "================================"
echo ""
echo "Summary:"
echo "  📦 Archived: ~21 files"
echo "  🗑️  Deleted: ~3 files"
echo "  📁 Created: docs/archive/ structure"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git status"
echo "  2. Check docs/README.md still links correctly"
echo "  3. Update main README.md to reference Shopify_showcase/"
echo "  4. Commit: git commit -m 'docs: organize documentation, archive historical files'"
echo ""
echo "Current active docs:"
echo "  → docs/ (9 core files)"
echo "  → Shopify_showcase/ (3 showcase files)"
echo "  → docs/archive/ (historical reference)"
echo ""
