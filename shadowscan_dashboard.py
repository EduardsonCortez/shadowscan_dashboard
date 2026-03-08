import tkinter as tk
from tkinter import filedialog
import pytesseract
from PIL import Image
import re
from urllib.parse import urlparse
import socket
import whois
from datetime import datetime
import cv2
from pyzbar.pyzbar import decode

# Tesseract path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# suspicious keywords
scam_keywords = [
    "free","win","cashback","bonus","iphone",
    "prize","gift","claim","limited","offer"
]


def analyze_url(url):

    warnings = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # HTTPS check
    if not url.startswith("https://"):
        warnings.append("Not using HTTPS")

    # keyword detection
    for word in scam_keywords:
        if word in url.lower():
            warnings.append(f"Keyword detected: {word}")

    # IP lookup
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unknown"

    # Domain age
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            age = (datetime.now() - creation).days
        else:
            age = "Unknown"

    except:
        age = "Unknown"

    # Result logic
    if len(warnings) >= 2:
        result = "HIGH RISK"
    elif len(warnings) >= 1:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    output.delete("1.0", tk.END)

    output.insert(tk.END, f"URL: {url}\n")
    output.insert(tk.END, f"Domain: {domain}\n")
    output.insert(tk.END, f"IP Address: {ip}\n")
    output.insert(tk.END, f"Domain Age: {age} days\n\n")

    output.insert(tk.END, f"RESULT: {result}\n\n")

    if warnings:
        output.insert(tk.END, "Warnings:\n")
        for w in warnings:
            output.insert(tk.END, f"- {w}\n")
    else:
        output.insert(tk.END, "No suspicious indicators")


def scan_url():

    url = url_entry.get().strip()

    if not url:
        return

    analyze_url(url)


def scan_screenshot():

    file = filedialog.askopenfilename()

    if not file:
        return

    img = Image.open(file)

    text = pytesseract.image_to_string(img)

    # fix OCR broken URLs
    text = text.replace("\n", "")
    text = text.replace(" ", "")

    urls = re.findall(r'https?://[^\s]+', text)

    if urls:
        analyze_url(urls[0])
    else:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No link detected in image")


def scan_qr():

    file = filedialog.askopenfilename()

    if not file:
        return

    img = cv2.imread(file)

    decoded = decode(img)

    if decoded:
        data = decoded[0].data.decode("utf-8")
        analyze_url(data)

    else:
        output.delete("1.0", tk.END)
        output.insert(tk.END, "No QR link detected")


# GUI
window = tk.Tk()
window.title("ShadowScan Cybersecurity Dashboard")
window.geometry("800x600")
window.configure(bg="#0d1117")

title = tk.Label(
    window,
    text="SHADOWSCAN DASHBOARD",
    font=("Consolas", 24, "bold"),
    fg="#00ffcc",
    bg="#0d1117"
)

title.pack(pady=10)

frame = tk.Frame(window, bg="#0d1117")
frame.pack(pady=10)

url_entry = tk.Entry(
    frame,
    width=70,
    font=("Consolas", 11),
    bg="#161b22",
    fg="#00ffcc",
    insertbackground="white"
)

url_entry.grid(row=0, column=0, padx=10)

scan_btn = tk.Button(
    frame,
    text="Scan URL",
    bg="#238636",
    fg="white",
    command=scan_url
)

scan_btn.grid(row=0, column=1)

btn_frame = tk.Frame(window, bg="#0d1117")
btn_frame.pack(pady=10)

img_btn = tk.Button(
    btn_frame,
    text="Scan Screenshot",
    bg="#1f6feb",
    fg="white",
    command=scan_screenshot
)

img_btn.grid(row=0, column=0, padx=10)

qr_btn = tk.Button(
    btn_frame,
    text="Scan QR Code",
    bg="#8b5cf6",
    fg="white",
    command=scan_qr
)

qr_btn.grid(row=0, column=1, padx=10)

output = tk.Text(
    window,
    height=25,
    width=90,
    bg="#161b22",
    fg="#00ffcc",
    font=("Consolas", 10)
)

output.pack(pady=20)

window.mainloop()
