# Cybersecurity Network Monitoring Tool

A Python-based tool for analyzing network traffic from PCAP files and live capture, visualizing IP connections with geolocation, heatmaps, and real-time threat detection.

## Features

- Analyze offline and live network traffic (PCAP files)
- IP geolocation mapping to show source and destination globally
- Interactive visualizations with heatmaps and connection lines
- Real-time threat detection and alerting
- Web interface built with Flask and Streamlit for easy interaction
- Export network paths in KML format for Google Earth visualization

## Technologies Used

- Python
- Scapy (packet capture and analysis)
- GeoIP (IP geolocation)
- Flask & Streamlit (web interface)
- Wireshark (PCAP analysis)
- KML generation for geospatial visualization

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Palla-Sindhu/cybersecurity-network-monitor.git
2.Create and activate a virtual environment:
  python -m venv .venv
  source .venv/bin/activate      # On Linux/macOS
  .venv\Scripts\activate         # On Windows
3.Install dependencies:
  pip install -r requirements.txt
4.Run the application:
  python app.py
  
## Usage
  Upload PCAP files or start live capture to analyze network traffic.
  
  View interactive maps with traffic heatmaps and connection lines.
  
  Monitor real-time threat alerts based on traffic patterns.
  
  Export visualizations as KML files for Google Earth.

