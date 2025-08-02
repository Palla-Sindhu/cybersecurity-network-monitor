import os
import sys
import socket
import dpkt
import folium
import webbrowser
import geoip2.database
from scapy.all import IP, sniff
from datetime import datetime
from collections import defaultdict
from plyer import notification
from folium.plugins import HeatMap
import winsound

def get_most_active_regions(coord_counts, ip_info, top_n=5):
    most_active = sorted(coord_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    print("\nTop Active Regions in Heatmap:")
    for i, ((lat, lon), count) in enumerate(most_active, 1):
        ip, country = ip_info.get((lat, lon), ("Unknown", "Unknown"))
        print(f"{i}. {ip} ({country}) at ({lat:.2f}, {lon:.2f}) - {count} packets")

def ensure_geoip_db():
    if not os.path.exists("GeoLite2-City.mmdb"):
        print("[!] GeoLite2-City.mmdb not found.")
        print("Download it from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        sys.exit(1)

def load_blacklist(path='blacklist.txt'):
    return set(ip.strip() for ip in open(path)) if os.path.exists(path) else set()

def alert(ip, country):
    print(f"[!!!] Threat Detected: {ip} ({country})")
    notification.notify(
        title="⚠️ Threat Alert",
        message=f"{ip} - {country}",
        timeout=4
    )
    for _ in range(4):
        winsound.Beep(1000, 300)
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()} ALERT: {ip} ({country})\n")

def process_packet(packet, blacklist, reader, alerted_ips):
    if IP in packet:
        for ip in [packet[IP].src, packet[IP].dst]:
            if ip in blacklist and ip not in alerted_ips:
                try:
                    country = reader.city(ip).country.name
                except:
                    country = "Unknown"
                alert(ip, country)
                alerted_ips.add(ip)

def run_realtime_sniffing():
    ensure_geoip_db()
    reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    blacklist = load_blacklist()
    alerted_ips = set()

    print("[*] Real-time sniffing started...")
    sniff(filter="ip", prn=lambda pkt: process_packet(pkt, blacklist, reader, alerted_ips), store=False)

def process_pcap(pcap, reader):
    kml_data = ''
    coord_counts = defaultdict(int)
    ip_info = {}
    lines = []

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue

            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            try:
                src_record = reader.city(src_ip)
                src_lat = src_record.location.latitude
                src_lon = src_record.location.longitude
                src_country = src_record.country.name
            except:
                src_lat = src_lon = src_country = None

            try:
                dst_record = reader.city(dst_ip)
                dst_lat = dst_record.location.latitude
                dst_lon = dst_record.location.longitude
                dst_country = dst_record.country.name
            except:
                dst_lat = dst_lon = dst_country = None

            if src_lat and src_lon:
                ip_info[(src_lat, src_lon)] = (src_ip, src_country)
                coord_counts[(src_lat, src_lon)] += 1
                kml_data += f'''
<Placemark>
  <name>{src_ip} ({src_country})</name><extrude>1</extrude>
  tessellate>1</tessellate>
  <styleUrl>#transBluePoly</styleUrl>
  <LineString>
  <coordinates>%6f,%6f
  %6f,%6f</coordinates>
    </LineString>
  <Point><coordinates>{dst_lon},{dst_lat}</coordinates></Point>
</Placemark>'''%(dst_ip,dst_lon,dst_lat,src_lon,src_lat)


            if dst_lat and dst_lon:
                ip_info[(dst_lat, dst_lon)] = (dst_ip, dst_country)
                coord_counts[(dst_lat, dst_lon)] += 1
                kml_data += f'''
<Placemark>
  <name>{dst_ip} ({dst_country})</name>
  <extrude>1</extrude>
  tessellate>1</tessellate>
  <styleUrl>#transBluePoly</styleUrl>
  <LineString>
  <coordinates>%6f,%6f
  %6f,%6f</coordinates>
    </LineString>
  <Point><coordinates>{dst_lon},{dst_lat}</coordinates></Point>
</Placemark>'''%(dst_ip,dst_lon,dst_lat,src_lon,src_lat)

            if None not in (src_lat, src_lon, dst_lat, dst_lon):
                print(f"[*] Drawing line from {src_ip} → {dst_ip}")
                kml_data += f'''
<Placemark>
  <name>{src_ip} → {dst_ip}</name>
  <Style>
    <LineStyle><color>ff0000ff</color><width>2</width></LineStyle>
  </Style>
  <LineString>
    <coordinates>{src_lon},{src_lat},0 {dst_lon},{dst_lat},0</coordinates>
  </LineString>
</Placemark>'''
                lines.append(((src_lat, src_lon), (dst_lat, dst_lon)))

        except Exception:
            continue

    if ip_info:
        all_coords = " ".join(f"{lon},{lat},0" for (lat, lon) in ip_info.keys())
        kml_data += f'''
<Placemark>
  <name>All Connections</name>
  <Style>
    <LineStyle><color>ff00ff00</color><width>3</width></LineStyle>
  </Style>
  <LineString>
    <coordinates>{all_coords}</coordinates>
  </LineString>
</Placemark>'''

    return kml_data, coord_counts, ip_info, lines

def generate_heatmap(coords, ip_info, lines, output='heatmap.html'):
    m = folium.Map(location=[20, 0], zoom_start=2)
    heat_data = [[lat, lon, count] for (lat, lon), count in coords.items()]
    HeatMap(heat_data).add_to(m)

    for (lat, lon), (ip, country) in ip_info.items():
        folium.Marker([lat, lon], popup=f"{ip} - {country}").add_to(m)

    for point1, point2 in lines:
        folium.PolyLine([point1, point2], color="red", weight=2.5, opacity=0.6).add_to(m)

    m.save(output)
    webbrowser.open(output)

def run_offline_analysis(pcap_file='cyberglobe.pcap'):
    ensure_geoip_db()
    reader = geoip2.database.Reader("GeoLite2-City.mmdb")

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        kml, coords, ip_info, lines = process_pcap(pcap, reader)

        kml_header = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<Style id="transBluePoly">
  <LineStyle><width>2</width><color>501400E6</color></LineStyle>
</Style>
'''
        kml_footer = '''
</Document>
</kml>'''

        kmldoc = kml_header + kml + kml_footer
        with open("output.kml", "w", encoding='utf-8') as out:
            out.write(kmldoc)

        print("KML output saved to 'output.kml'")

        if coords:
            generate_heatmap(coords, ip_info, lines)
            get_most_active_regions(coords, ip_info)  
        else:
            print("[!] No geo coordinates found.")

def print_usage():
    print("Usage:")
    print("  python project.py sniff     ")
    print("  python project.py analyze   ")

def main():
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode == "sniff":
            run_realtime_sniffing()
        elif mode == "analyze":
            run_offline_analysis()
        else:
            print_usage()
    else:
        print_usage()

if __name__ == "__main__":
    main()
