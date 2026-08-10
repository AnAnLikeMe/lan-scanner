import os
import re
import socket
import threading
import sqlite3
import subprocess
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
scanning_status = {"running": False, "progress": "Idle"}

# ---------- 数据库初始化 ----------
def init_db():
    conn = sqlite3.connect('/data/remarks.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS remarks
                 (ip TEXT, port INTEGER, remark TEXT, PRIMARY KEY (ip, port))''')
    conn.commit()
    conn.close()
init_db()

def get_remark(ip, port):
    conn = sqlite3.connect('/data/remarks.db')
    c = conn.cursor()
    c.execute("SELECT remark FROM remarks WHERE ip=? AND port=?", (ip, port))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""

def set_remark(ip, port, remark):
    conn = sqlite3.connect('/data/remarks.db')
    c = conn.cursor()
    c.execute("REPLACE INTO remarks (ip, port, remark) VALUES (?, ?, ?)", (ip, port, remark))
    conn.commit()
    conn.close()

# ---------- 局域网扫描核心 (使用nmap) ----------
def get_local_subnet():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # 假设常见子网掩码为 /24
        return re.sub(r'\.\d+$', '.0/24', local_ip)
    except:
        return "192.168.1.0/24"

def run_nmap_scan(subnet):
    global scanning_status
    scanning_status["running"] = True
    scanning_status["progress"] = "扫描在线主机..."
    try:
        # 1. 发现在线主机 (ping扫描)
        ping_cmd = ["nmap", "-sn", subnet]
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=60)
        ips = re.findall(r'Nmap scan report for (?:[\w.-]+ )?\(?([0-9.]+)\)?', result.stdout)
        ips = list(set(ips))
        
        all_services = []
        total = len(ips)
        for idx, ip in enumerate(ips):
            scanning_status["progress"] = f"扫描 {ip} ({idx+1}/{total}) 的开放端口..."
            # 扫描常见端口 (可自行增减)
            port_cmd = ["nmap", "-sT", "-T4", "-p", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9090,9200,27017", ip]
            try:
                port_result = subprocess.run(port_cmd, capture_output=True, text=True, timeout=30)
                # 解析开放端口
                lines = port_result.stdout.split('\n')
                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        port = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        if port.isdigit():
                            all_services.append({
                                "ip": ip,
                                "port": int(port),
                                "service": service,
                                "remark": get_remark(ip, int(port))
                            })
            except:
                continue
        
        # 写入数据库（保留已存在的备注）
        # 先清除旧数据? 我们采用增量更新，但为了显示干净，我们只保留扫描到的新数据，但保留旧备注。
        # 这里简单点：直接返回扫描结果，前端展示。备注单独查。
        scanning_status["result"] = all_services
        scanning_status["running"] = False
        scanning_status["progress"] = "扫描完成"
        return all_services
    except Exception as e:
        scanning_status["running"] = False
        scanning_status["progress"] = f"扫描出错: {e}"
        return []

# ---------- Flask 接口 ----------
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def scan():
    if scanning_status["running"]:
        return jsonify({"status": "busy"})
    subnet = request.json.get('subnet', get_local_subnet())
    threading.Thread(target=run_nmap_scan, args=(subnet,)).start()
    return jsonify({"status": "started"})

@app.route('/api/status')
def status():
    return jsonify(scanning_status)

@app.route('/api/remark', methods=['POST'])
def remark():
    data = request.json
    set_remark(data['ip'], data['port'], data['remark'])
    return jsonify({"status": "ok"})

# ---------- 前端 UI (现代化仪表盘) ----------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>局域网服务扫描器</title>
    <style>
        * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
        body { background: #0b1120; color: #e5e7eb; padding: 2rem; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .title { font-size: 1.8rem; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .btn { background: #1e293b; border: none; color: #f1f5f9; padding: 0.7rem 1.8rem; border-radius: 30px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: 1px solid #334155; }
        .btn:hover { background: #2d3a52; transform: scale(1.02); }
        .btn-primary { background: #3b82f6; border-color: #3b82f6; }
        .btn-primary:hover { background: #2563eb; }
        .status-badge { background: #1e293b; padding: 0.4rem 1rem; border-radius: 30px; font-size: 0.8rem; color: #94a3b8; }
        .status-badge.active { color: #34d399; border: 1px solid #34d399; }
        .scan-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; }
        .ip-card { background: #1a2332; border-radius: 16px; padding: 1.2rem 1.5rem; border: 1px solid #2a3a4a; }
        .ip-header { display: flex; justify-content: space-between; font-weight: 600; color: #94a3b8; border-bottom: 1px solid #2a3a4a; padding-bottom: 0.5rem; margin-bottom: 0.8rem; }
        .ip-addr { color: #60a5fa; font-size: 1.1rem; }
        .service-row { display: flex; align-items: center; gap: 1.5rem; padding: 0.4rem 0; border-bottom: 1px solid #1e2a3a; flex-wrap: wrap; }
        .service-row:last-child { border-bottom: none; }
        .port-link { background: #0f172a; padding: 0.2rem 0.8rem; border-radius: 20px; font-family: monospace; font-size: 0.9rem; color: #facc15; text-decoration: none; border: 1px solid #334155; transition: 0.2s; }
        .port-link:hover { background: #facc15; color: #0f172a; border-color: #facc15; }
        .service-name { color: #cbd5e1; min-width: 80px; font-size: 0.9rem; }
        .remark-input { flex: 1; min-width: 150px; background: #0f172a; border: 1px solid #2a3a4a; color: #f1f5f9; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.85rem; }
        .remark-input:focus { outline: none; border-color: #3b82f6; }
        .remark-save { background: none; border: none; color: #34d399; cursor: pointer; font-size: 1rem; padding: 0 0.5rem; opacity: 0.6; transition: 0.2s; }
        .remark-save:hover { opacity: 1; }
        .empty-state { text-align: center; padding: 4rem; color: #64748b; }
        .loading-spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid #1e293b; border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle; margin-right: 10px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .progress-text { color: #94a3b8; font-size: 0.9rem; }
        .flex { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="title">🔍 局域网服务透视</div>
        <div class="flex">
            <span class="status-badge" id="statusBadge">● 就绪</span>
            <button class="btn btn-primary" id="scanBtn">🔄 开始扫描</button>
        </div>
    </div>
    <div id="progressBar" class="progress-text" style="margin-bottom: 1rem;"></div>
    <div id="resultContainer" class="scan-grid">
        <div class="empty-state">点击「开始扫描」探测局域网内的所有在线服务</div>
    </div>
</div>

<script>
    const scanBtn = document.getElementById('scanBtn');
    const statusBadge = document.getElementById('statusBadge');
    const progressBar = document.getElementById('progressBar');
    const container = document.getElementById('resultContainer');
    let pollInterval = null;

    function updateStatus(status) {
        if (status.running) {
            statusBadge.innerHTML = '⏳ 扫描中';
            statusBadge.classList.add('active');
            scanBtn.disabled = true;
            scanBtn.style.opacity = '0.5';
            progressBar.innerText = status.progress || '扫描中...';
        } else {
            statusBadge.innerHTML = '● 就绪';
            statusBadge.classList.remove('active');
            scanBtn.disabled = false;
            scanBtn.style.opacity = '1';
            if (status.progress && status.progress.includes('完成')) {
                progressBar.innerText = '✅ ' + status.progress;
            } else if (!status.progress || status.progress === 'Idle') {
                progressBar.innerText = '';
            }
        }
    }

    function renderResults(data) {
        if (!data || data.length === 0) {
            container.innerHTML = '<div class="empty-state">😐 未发现开放的服务端口，请检查网络或尝试扫描其他网段。</div>';
            return;
        }
        // 按IP分组
        const groups = {};
        data.forEach(item => {
            if (!groups[item.ip]) groups[item.ip] = [];
            groups[item.ip].push(item);
        });

        let html = '';
        for (const [ip, services] of Object.entries(groups)) {
            html += `<div class="ip-card"><div class="ip-header"><span class="ip-addr">📡 ${ip}</span><span>${services.length} 个端口</span></div>`;
            services.forEach(s => {
                const protocol = (s.port === 443 || s.port === 8443 || s.service === 'https') ? 'https' : 'http';
                html += `<div class="service-row">
                    <a href="${protocol}://${s.ip}:${s.port}" target="_blank" class="port-link">${s.port}</a>
                    <span class="service-name">${s.service || 'unknown'}</span>
                    <input type="text" class="remark-input" placeholder="添加备注..." value="${s.remark || ''}" data-ip="${s.ip}" data-port="${s.port}">
                    <button class="remark-save" data-ip="${s.ip}" data-port="${s.port}">💾</button>
                </div>`;
            });
            html += '</div>';
        }
        container.innerHTML = html;

        // 绑定备注保存事件
        document.querySelectorAll('.remark-save').forEach(btn => {
            btn.onclick = function() {
                const ip = this.dataset.ip;
                const port = this.dataset.port;
                const input = this.parentElement.querySelector('.remark-input');
                const remark = input.value;
                fetch('/api/remark', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, port, remark })
                }).then(() => {
                    input.style.borderColor = '#34d399';
                    setTimeout(() => input.style.borderColor = '', 1000);
                });
            };
        });
        // 按回车保存
        document.querySelectorAll('.remark-input').forEach(inp => {
            inp.onkeydown = (e) => { if (e.key === 'Enter') inp.parentElement.querySelector('.remark-save').click(); };
        });
    }

    function fetchStatus() {
        fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                updateStatus(data);
                if (data.result) {
                    renderResults(data.result);
                    // 清除结果以便下次增量，或者保留——我们保留并持续刷新，但扫描完成后服务器会返回新结果
                }
                if (!data.running && data.progress.includes('完成')) {
                    // 最后一次拉取结果
                    if (pollInterval) clearInterval(pollInterval);
                    pollInterval = null;
                }
            });
    }

    function startScan() {
        fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
            .then(res => res.json())
            .then(() => {
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(fetchStatus, 1500);
                fetchStatus();
            });
    }

    scanBtn.onclick = startScan;

    // 进入页面自动扫描一次（可注释掉）
    window.onload = function() {
        setTimeout(startScan, 500);
    };
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)