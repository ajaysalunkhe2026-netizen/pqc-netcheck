import * as vscode from 'vscode';
import * as cp from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    let disposable = vscode.commands.registerCommand('pqc-netcheck.scanNetwork', () => {
        const panel = vscode.window.createWebviewPanel('pqcPulse', 'PQC Network Pulse (Wire-Level)', vscode.ViewColumn.One, { enableScripts: true });

        const runWireScan = () => {
            // Added IPv6 fields to capture modern browser traffic correctly
            const tsharkCmd = 'tshark -i 5 -Y "tls.handshake.type == 1" -T fields -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tls.handshake.extensions_supported_group -a duration:5';
            
            cp.exec(tsharkCmd, (err: any, stdout: string) => {
                if (err) {
                    panel.webview.html = `<h2>Error: Is Wireshark/tshark installed and running?</h2><p>${err.message}</p>`;
                    return;
                }

                const lines = stdout.split('\n').filter((line: string) => line.trim() !== '');
                const rows = lines.map((line: string) => {
                    const [ip4src, ip6src, ip4dst, ip6dst, groups] = line.split('\t');
                    
                    // Automatically pick IPv4 or IPv6 whichever is active
                    const finalSrc = ip4src || ip6src || 'Unknown';
                    const finalDst = ip4dst || ip6dst || 'Unknown';
                    
                    const isPQC = groups && (groups.includes('0x11ab') || groups.includes('25497') || groups.includes('6399'));
                    const statusMsg = isPQC ? '✅ PQC Active (ML-KEM)' : '⚠️ Classical Only';
                    const trStyle = isPQC ? 'background-color: #003300;' : '';

                    return `<tr style="${trStyle}">
                        <td>TLS ClientHello</td><td>${finalSrc}</td><td>${finalDst}</td>
                        <td>${groups ? groups.substring(0, 30) + '...' : 'None'}</td>
                        <td>${statusMsg}</td>
                    </tr>`;
                }).join('');

                panel.webview.html = getHtmlTemplate(rows);
            });
        };

        runWireScan();
        
        // @ts-ignore
        const intervalId = setInterval(runWireScan, 10000); 
        // @ts-ignore
        panel.onDidDispose(() => clearInterval(intervalId), null, context.subscriptions);
    });
    context.subscriptions.push(disposable);
}

function getHtmlTemplate(rows: string) {
    return `<html>
        <style>
            body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 10px; border: 1px solid #30363d; text-align: left; }
            th { background: #161b22; }
            .header { border-bottom: 2px solid #238636; padding-bottom: 10px; }
        </style>
        <body>
            <div class="header">
                <h2>Wire-Level PQC Telemetry (Live tshark capture)</h2>
                <p>Intercepting TLS 1.3 Handshakes & Extension 10 (Supported Groups)</p>
            </div>
            <table>
                <tr><th>Packet Type</th><th>Source IP</th><th>Dest IP</th><th>Negotiated OIDs</th><th>Wire Status</th></tr>
                ${rows || '<tr><td colspan="5">Listening for TLS handshakes... (Generate some HTTPS traffic in your browser)</td></tr>'}
            </table>
        </body>
    </html>`;
}