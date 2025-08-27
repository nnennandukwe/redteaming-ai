#!/bin/bash

# Red Team LLM Demo - Quick Start Script

echo "🔴 RED TEAM LLM SECURITY DEMO"
echo "=============================="
echo ""
echo "Select demo mode:"
echo "1) Interactive CLI Demo (Recommended for presentation)"
echo "2) 5-Minute Quick Demo"
echo "3) Automated Attack Only"
echo "4) Web Interface (Streamlit)"
echo "5) Install Dependencies First"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        echo "Starting interactive demo..."
        python3 demo.py
        ;;
    2)
        echo "Starting 5-minute quick demo..."
        python3 demo.py --quick
        ;;
    3)
        echo "Running automated attacks..."
        python3 demo.py --auto
        ;;
    4)
        echo "Starting web interface..."
        echo "Opening browser at http://localhost:8501"
        streamlit run streamlit_demo.py
        ;;
    5)
        echo "Installing dependencies..."
        pip3 install -r requirements.txt
        echo "✅ Dependencies installed! Run this script again to start demo."
        ;;
    *)
        echo "Invalid choice. Please run again."
        ;;
esac