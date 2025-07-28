import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, IP, TCP, UDP
import csv
from fpdf import FPDF
import time
from collections import Counter
import winsound
from sklearn.ensemble import IsolationForest
import numpy as np
import threading
import sqlite3
import os
import matplotlib.pyplot as plt
import queue




# ----------------- Utility Functions -----------------
def clean_text(text):
    """
    تحذف أو تستبدل الرموز غير المدعومة في PDF أو CSV
    """
    replacements = {
        "⚠": "[ALERT]",
        "🚨": "[WARNING]",
        "✅": "",
        "➡": "->",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


# ----------------- Main Variables -----------------
root = tk.Tk()
root.title("Smart Network Packet Analyzer")
root.geometry("1200x650")
root.configure(bg="#121212")

capturing = False
data_list = []
protocol_counter = Counter()
ip_counter_src = Counter()
ip_counter_dst = Counter()
port_counter_src = Counter()
port_counter_dst = Counter()
country_counter_src = Counter()
country_counter_dst = Counter()
attacks_list = []
packet_queue = queue.Queue()


# AI Model
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
features_list = []

# ================== الإعدادات الإضافية ==================
SAFE_PORTS = [53, 67, 68, 5353]  # DNS, DHCP, mDNS
SAFE_PROTOCOLS = ["UDP"]  # يمكن إضافة بروتوكولات آمنة هنا

start_time = time.time()  # بداية التشغيل لحساب الزمن

# DB Setup
conn = sqlite3.connect("network_reports.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    total_packets INTEGER,
    suspicious_ratio REAL,
    top_sources TEXT,
    top_destinations TEXT,
    attacks TEXT,
    pdf_path TEXT
)
""")
conn.commit()
# جدول بيانات التدريب
cursor.execute("""
CREATE TABLE IF NOT EXISTS ai_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    length INTEGER,
    src_ip_count INTEGER,
    proto_score INTEGER
)
""")
conn.commit()

# ----------------- UI Design -----------------
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#1e1e2f", foreground="white",
                fieldbackground="#1e1e2f", rowheight=25, font=("Arial", 10))
style.map("Treeview", background=[("selected", "#00ffcc")])

dashboard = tk.Frame(root, bg="#1e1e2f", height=50)
dashboard.pack(fill="x")

stats_label = tk.Label(dashboard, text="Packets: 0 | TCP: 0 | UDP: 0",
                       font=("Arial", 14, "bold"), fg="white", bg="#1e1e2f")
stats_label.pack(side=tk.LEFT, padx=20, pady=10)

frame = tk.Frame(root, bg="#121212")
frame.pack(fill="both", expand=True, padx=10, pady=10)

columns = ("Time", "Src IP", "Src MAC","Src Port", "Dst IP", "Dst MAC","Dst Port", "Protocol", "Length","TTL", "Status")
tree = ttk.Treeview(frame, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

scroll_y = tk.Scrollbar(frame, orient="vertical", command=tree.yview)
scroll_x = tk.Scrollbar(frame, orient="horizontal", command=tree.xview)
tree.configure(yscroll=scroll_y.set, xscroll=scroll_x.set)
scroll_y.pack(side="right", fill="y")
scroll_x.pack(side="bottom", fill="x")
tree.pack(fill="both", expand=True)

# ----------------- AI Analysis -----------------
def ai_analyze_packet(packet_length, src_ip_count, proto_score):
    features = np.array([[packet_length, src_ip_count, proto_score]])
    if len(features_list) >= 20:  # تدريب بعد 50 باكيت فقط
        model.fit(features_list)
        prediction = model.predict(features)[0]
        return "⚠ Suspicious" if prediction == -1 else "Normal"
    else:
        return "Normal"
        
def continuous_training():
    while True:
        time.sleep(20)  # كل 20 ثانية يحدث التدريب
        local_cursor = conn.cursor()
        local_cursor.execute("SELECT length, src_ip_count, proto_score FROM ai_data ORDER BY id DESC LIMIT 50000")
        rows = local_cursor.fetchall()
        if len(rows) > 100:  # لازم يكون في بيانات كافية للتدريب
            X = np.array(rows)
            model.fit(X)  # تدريب الموديل
            print(f"[AI] Model retrained with {len(rows)} samples")
       



# ================== دالة تحليل الحزم ==================
def packet_callback(packet):
    if capturing and IP in packet:
        packet_queue.put(packet)  # أضف الحزمة للطابور

        
        
        
def process_packets():
    global features_list
    while True:
        packet = packet_queue.get()
        if packet is None:  # لإيقاف المعالجة عند الضغط على Stop
            break

        # === نفس التحليل الموجود سابقًا لكن هنا ===
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else str(packet[IP].proto))
        length = len(packet)

        src_mac = getattr(packet, "src", "-")
        dst_mac = getattr(packet, "dst", "-")
        src_port = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else "-")
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else "-")
        ttl = packet[IP].ttl if packet.haslayer(IP) else "-"

        # تجاهل المنافذ الآمنة
        if src_port in SAFE_PORTS or dst_port in SAFE_PORTS or proto in SAFE_PROTOCOLS:
            packet_queue.task_done()
            continue

        # تحديث العدادات
        ip_counter_src[src_ip] += 1
        ip_counter_dst[dst_ip] += 1

        elapsed_time = (time.time() - start_time) / 60
        proto_score = 1 if proto == "TCP" else 2 if proto == "UDP" else 3

        # تخزين البيانات في القائمة
        local_cursor = conn.cursor()
        local_cursor.execute("INSERT INTO ai_data (length, src_ip_count, proto_score) VALUES (?, ?, ?)",
        (length, ip_counter_src[src_ip], proto_score))
        conn.commit()


        # تحليل AI
        status_ai = ai_analyze_packet(length, ip_counter_src[src_ip], proto_score)
        status = "Normal"

        # القواعد التقليدية
        if ip_counter_src[src_ip] / max(elapsed_time, 1) > 1000:
            status = "⚠ DDoS Attack Detected"

        if src_port != "-" and isinstance(src_port, int):
            port_counter_src[src_port] += 1
            if port_counter_src[src_port] > 1000:
                status = "⚠ Port Scan Detected"

        # الدمج مع AI
        if status_ai == "⚠ Suspicious" and status != "Normal":
            status = "⚠ Confirmed Attack"
        elif status_ai == "⚠ Suspicious":
            status = "⚠ Suspicious Traffic"

        if "⚠" in status:
            attack_msg = f"{status}: {src_ip} → {dst_ip} ({proto})"
            if attack_msg not in attacks_list:
                attacks_list.append(attack_msg)
            winsound.Beep(1500, 500)

        # تحديث الواجهة من الثريد الرئيسي
        root.after(0, lambda:update_ui(timestamp, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, proto, length, ttl, status))


        packet_queue.task_done()



def update_ui(timestamp, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, proto, length, ttl, status):
    tree.insert("", "end",
                values=(timestamp, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, proto, length, ttl, status),
                tags=("threat" if "⚠" in status else "safe"))
    tree.tag_configure("threat", background="#ff5555", foreground="white")
    tree.tag_configure("safe", background="#1e1e2f", foreground="white")

    data_list.append([timestamp, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, proto, length, ttl, status])
    protocol_counter[proto] += 1
    stats_label.config(text=f"Packets: {len(data_list)} | TCP: {protocol_counter['TCP']} | UDP: {protocol_counter['UDP']}")
    tree.yview_moveto(1)




        
def clean_text(text):
    """إزالة أي رموز غير مدعومة للـ PDF"""
    return ''.join(ch for ch in text if ch.isalnum() or ch.isspace() or ch in ":,.-_")

def generate_pdf():
        if not data_list:
            messagebox.showwarning("Warning", "No data to export!")
            return

        # ========== الإحصائيات الأساسية ==========
        total_packets = len(data_list)
        avg_length = sum(int(row[8]) for row in data_list) / total_packets if total_packets else 0
        total_bytes = sum(int(row[8]) for row in data_list)
        bandwidth = (total_bytes / (len(data_list) if len(data_list) else 1)) / 1024
        suspicious_count = len([r for r in data_list if "⚠" in r[10]])
        suspicious_ratio = (suspicious_count / total_packets) * 100 if total_packets else 0

        top_src_ips = ip_counter_src.most_common(3)
        top_dst_ips = ip_counter_dst.most_common(3)

        # ✅ نافذة اختيار مكان حفظ الملف
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save PDF Report As"
        )
        if not file_path:
            return

        # ========== إنشاء الرسوم ==========
        img_files = []

        # Pie chart for protocols
        if protocol_counter:
            plt.figure(figsize=(5, 5))
            protocols = list(protocol_counter.keys())
            protocol_values = list(protocol_counter.values())
            plt.pie(protocol_values, labels=protocols, autopct='%1.1f%%', colors=['#00ffcc', '#ffaa00', '#ff5555'])
            plt.title("Protocol Distribution")
            plt.savefig("protocol_chart.png")
            img_files.append("protocol_chart.png")
            plt.close()

        # Bar chart for top source IPs
        if top_src_ips:
            plt.figure(figsize=(6, 4))
            ips, counts = zip(*top_src_ips)
            plt.bar(ips, counts, color='#00cc66')
            plt.title("Top Source IPs")
            plt.savefig("top_src_ips.png")
            img_files.append("top_src_ips.png")
            plt.close()

        # Bar chart for top destination IPs
        if top_dst_ips:
            plt.figure(figsize=(6, 4))
            ips, counts = zip(*top_dst_ips)
            plt.bar(ips, counts, color='#ffaa00')
            plt.title("Top Destination IPs")
            plt.savefig("top_dst_ips.png")
            img_files.append("top_dst_ips.png")
            plt.close()

    

        # ========== إنشاء PDF ==========
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 18)
        pdf.cell(200, 10, "Smart Network Packet Analyzer Report", ln=True, align="C")
        pdf.set_font("Arial", '', 12)
        pdf.cell(200, 10, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)

        # معلومات عامة
        pdf.cell(200, 10, f"Total Packets: {total_packets}", ln=True)
        pdf.cell(200, 10, f"Avg Packet Size: {avg_length:.2f} bytes", ln=True)
        pdf.cell(200, 10, f"Bandwidth: {bandwidth:.2f} KB/s", ln=True)
        pdf.cell(200, 10, f"Suspicious Traffic: {suspicious_ratio:.2f}%", ln=True)
        pdf.ln(10)

        # ✅ إدراج الرسوم
        for img in img_files:
            if os.path.exists(img):
                pdf.image(img, x=50, w=100)
                pdf.ln(10)

        # ✅ الهجمات والتوصيات
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, "Detected Attacks & Recommendations:", ln=True)
        pdf.set_font("Arial", '', 12)

        recommendations = {
            "DDoS": "Recommendation: Enable rate limiting, deploy a WAF (Web Application Firewall), and use anti-DDoS protection.",
            "Port Scan": "Recommendation: Block suspicious IP addresses using a firewall and enable port scan detection.",
            "Suspicious Traffic": "Recommendation: Inspect logs, run antivirus scans, and block malicious IP addresses."
        }

        if attacks_list:
            for attack in attacks_list:
                clean_attack = clean_text(attack)  # ← مسح الرموز
                pdf.multi_cell(0, 10, f"Attack: {clean_attack}")

                for key, rec in recommendations.items():
                    if key in attack:
                        pdf.set_text_color(0, 128, 0)
                        pdf.multi_cell(0, 10, clean_text(rec))
                        pdf.set_text_color(0, 0, 0)
                        break
                pdf.ln(5)
        else:
            pdf.cell(200, 10, "No attacks detected", ln=True)

        # ✅ حفظ PDF
        try:
            pdf.output(file_path)
            messagebox.showinfo("Success", f"PDF saved successfully at:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving PDF:\n{e}")
            return  # لو حصل خطأ في حفظ PDF نوقف الدالة

        # ✅ حذف الصور المؤقتة
        for img in img_files:
            if os.path.exists(img):
                os.remove(img)

        # ✅ حفظ في قاعدة البيانات
        try:
            
            local_cursor = conn.cursor()
            local_cursor.execute("""
            INSERT INTO reports (timestamp, total_packets, suspicious_ratio, top_sources, top_destinations, attacks, pdf_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
            time.strftime('%Y-%m-%d %H:%M:%S'),
            total_packets,
            suspicious_ratio,
            str(top_src_ips),
            str(top_dst_ips),
            "\n".join(attacks_list),
            file_path
            ))
            conn.commit()

        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to save in DB:\n{e}")
        



# ----------------- حفظ CSV -----------------
def save_csv():
    if not data_list:
        messagebox.showwarning("Warning", "No data to save!")
        return

    # ✅ نافذة اختيار مكان الحفظ
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save CSV Report As"
    )
    if not file_path:
        return

    try:
        # ✅ كتابة الأعمدة الجديدة
        headers = ["Time", "Src IP", "Src MAC", "Src Port", "Dst IP", "Dst MAC", "Dst Port", "Protocol", "Length", "TTL", "Status"]

        # ✅ لو الملف موجود، نضيف البيانات بدون مسح القديم
        file_exists = os.path.isfile(file_path)

        with open(file_path, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(headers)  # يكتب الأعمدة أول مرة فقط

            for row in data_list:
                cleaned_row = [clean_text(str(item)) for item in row]  # ← تنظيف كل عنصر
                writer.writerow(cleaned_row)

        messagebox.showinfo("Success", f"Data saved successfully at:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save CSV:\n{e}")




# ----------------- عرض التحليل -----------------
def show_analysis():
    analysis_win = tk.Toplevel(root)
    analysis_win.title("Traffic Analysis")
    analysis_win.geometry("850x700")
    analysis_win.configure(bg="#1e1e2f")

    # ====== العنوان ======
    tk.Label(analysis_win, text="📊 Network Traffic Analysis", font=("Arial", 16, "bold"),
             fg="#00ffcc", bg="#1e1e2f").pack(pady=10)

    # ✅ الأزرار تحت العنوان مباشرة
    btn_frame = tk.Frame(analysis_win, bg="#1e1e2f")
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="⬅ Back", command=analysis_win.destroy,
              bg="#ffaa00", fg="black", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=10)
    tk.Button(btn_frame, text="Save PDF", command=generate_pdf,
              bg="#00cc66", fg="white", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=10)
   
    # ====== Scrollable Frame ======
    canvas = tk.Canvas(analysis_win, bg="#1e1e2f", highlightthickness=0)
    scrollbar = tk.Scrollbar(analysis_win, orient="vertical", command=canvas.yview)
    scroll_frame = tk.Frame(canvas, bg="#1e1e2f")

    scroll_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True, pady=10)
    scrollbar.pack(side="right", fill="y")

    # ====== Top IPs ======
    stats_frame = tk.Frame(scroll_frame, bg="#1e1e2f")
    stats_frame.pack(pady=10)

    left_frame = tk.Frame(stats_frame, bg="#1e1e2f")
    left_frame.pack(side="left", padx=20)
    tk.Label(left_frame, text="🌍 Top Sources", fg="#00ffcc", bg="#1e1e2f", font=("Arial", 12, "bold")).pack(anchor="w")
    if ip_counter_src:
        for ip, count in ip_counter_src.most_common(5):
            tk.Label(left_frame, text=f"{ip}: {count}", fg="white", bg="#1e1e2f").pack(anchor="w")
    else:
        tk.Label(left_frame, text="No Source IPs detected", fg="gray", bg="#1e1e2f").pack(anchor="w")

    right_frame = tk.Frame(stats_frame, bg="#1e1e2f")
    right_frame.pack(side="right", padx=20)
    tk.Label(right_frame, text="🌍 Top Destinations", fg="#ffaa00", bg="#1e1e2f", font=("Arial", 12, "bold")).pack(anchor="w")
    if ip_counter_dst:
        for ip, count in ip_counter_dst.most_common(5):
            tk.Label(right_frame, text=f"{ip}: {count}", fg="white", bg="#1e1e2f").pack(anchor="w")
    else:
        tk.Label(right_frame, text="No Destination IPs detected", fg="gray", bg="#1e1e2f").pack(anchor="w")

    # ====== Ports ======
    ports_frame = tk.Frame(scroll_frame, bg="#1e1e2f")
    ports_frame.pack(pady=10)

    left_ports_frame = tk.Frame(ports_frame, bg="#1e1e2f")
    left_ports_frame.pack(side="left", padx=20)
    tk.Label(left_ports_frame, text="🔌 Top Source Ports", fg="#00ffcc", bg="#1e1e2f", font=("Arial", 12, "bold")).pack(anchor="w")
    if port_counter_src:
        for port, count in port_counter_src.most_common(5):
            tk.Label(left_ports_frame, text=f"Port {port}: {count} times", fg="white", bg="#1e1e2f").pack(anchor="w")
    else:
        tk.Label(left_ports_frame, text="No Source Ports detected", fg="gray", bg="#1e1e2f").pack(anchor="w")

    right_ports_frame = tk.Frame(ports_frame, bg="#1e1e2f")
    right_ports_frame.pack(side="right", padx=20)
    tk.Label(right_ports_frame, text="🔌 Top Destination Ports", fg="#ffaa00", bg="#1e1e2f", font=("Arial", 12, "bold")).pack(anchor="w")
    if port_counter_dst:
        for port, count in port_counter_dst.most_common(5):
            tk.Label(right_ports_frame, text=f"Port {port}: {count} times", fg="white", bg="#1e1e2f").pack(anchor="w")
    else:
        tk.Label(right_ports_frame, text="No Destination Ports detected", fg="gray", bg="#1e1e2f").pack(anchor="w")

    # ====== الهجمات ======
    tk.Label(scroll_frame, text="\n⚠ Detected Attacks", fg="red", bg="#1e1e2f", font=("Arial", 14, "bold")).pack(pady=10)
    if attacks_list:
        for attack in attacks_list:
            tk.Label(scroll_frame, text=attack, fg="white", bg="#1e1e2f", wraplength=800, justify="left").pack(anchor="w", padx=20)
    else:
        tk.Label(scroll_frame, text="No attacks detected", fg="white", bg="#1e1e2f").pack(anchor="center")




# ----------------- Capture Control -----------------
def capture_packets():
    sniff(prn=packet_callback, store=False, stop_filter=lambda x: not capturing)

def start_capture():
    global capturing
    capturing = True
    threading.Thread(target=lambda: sniff(prn=packet_callback, store=False), daemon=True).start()
    threading.Thread(target=process_packets, daemon=True).start()
    messagebox.showinfo("Info", "Packet capturing started.")

def stop_and_analyze():
    global capturing
    capturing = False
    packet_queue.put(None)  # إشارة لإنهاء process_packets
    messagebox.showinfo("Info", "Packet capturing stopped.")

    # ✅ تحقق من وجود بيانات قبل التحليل
    if not data_list:
        messagebox.showwarning("Warning", "No captured data available for analysis!")
        return

    # ✅ افتح نافذة التحليل مباشرة
    show_analysis()






# ----------------- الأزرار الأساسية -----------------
btn_frame = tk.Frame(root, bg="#121212")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Start", command=start_capture, bg="#00ffcc", fg="black", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=15)
tk.Button(btn_frame, text="Stop & Analyze", command=stop_and_analyze, bg="#ff5555", fg="white", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=15)
tk.Button(btn_frame, text="Save CSV", command=save_csv, bg="#ffaa00", fg="black", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=15)

threading.Thread(target=continuous_training, daemon=True).start()



root.mainloop()


