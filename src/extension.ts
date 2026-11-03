import * as vscode from 'vscode';
import * as cp from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    const disposable = vscode.commands.registerCommand('pqc-netcheck.scanNetwork', () => {
        const panel = vscode.window.createWebviewPanel(
            'pqcPulse',
            'PQC Network Pulse (Lab)',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        const runWireScan = () => {
            // Lab note: change -i <N> to your capture interface (tshark -D to list)
            const tsharkCmd =
                'tshark -i 5 -Y "tls.handshake.type == 1" -T fields -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tls.handshake.extensions_supported_group -a duration:5';

            cp.exec(tsharkCmd, (err: any, stdout: string) => {
                if (err) {
                    panel.webview.html = `<h2>Error: Is Wireshark/tshark installed and in PATH?</h2><p>${err.message}</p><p>List interfaces: tshark -D</p>`;
                    return;
                }

                const lines = stdout.split('\n').filter((line: string) => line.trim() !== '');
                const rows = lines
                    .map((line: string) => {
                        const [ip4src, ip6src, ip4dst, ip6dst, groups] = line.split('\t');
                        const finalSrc = ip4src || ip6src || 'Unknown';
                        const finalDst = ip4dst || ip6dst || 'Unknown';

                        // ClientHello supported_groups = what the client OFFERS, not the selected group.
                        // Standard hybrid: X25519MLKEM768 = 0x11EC (4588)
                        // Draft (legacy): X25519Kyber768Draft00 = 0x6399 (25497)
                        const g = groups || '';
                        const offersFinalHybrid =
                            g.includes('0x11ec') ||
                            g.includes('0x11EC') ||
                            g.includes('4588');
                        const offersDraftHybrid =
                            g.includes('0x6399') ||
                            g.includes('25497') ||
                            g.includes('6399');

                        let statusMsg = 'Classical only (in offered list)';
                        let trStyle = '';
                        if (offersFinalHybrid) {
                            statusMsg = 'Offers X25519MLKEM768 (0x11EC)';
                            trStyle = 'background-color: #003300;';
                        } else if (offersDraftHybrid) {
                            statusMsg = 'Offers draft hybrid only (0x6399)';
                            trStyle = 'background-color: #3d2b00;';
                        }

                        return `<tr style="${trStyle}">
                        <td>TLS ClientHello</td>
                        <td>${finalSrc}</td>
                        <td>${finalDst}</td>
                        <td>${g ? g.substring(0, 40) + (g.length > 40 ? '...' : '') : 'None'}</td>
                        <td>${statusMsg}</td>
                    </tr>`;
                    })
                    .join('');

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
            .note { color: #8b949e; font-size: 12px; margin-top: 8px; }
        </style>
        <body>
            <div class="header">
                <h2>Wire-level PQC lab (ClientHello offered groups)</h2>
                <p>TLS 1.3 Extension 10 — supported_groups from ClientHello</p>
                <p class="note">This is what the client offers. Selected group is in ServerHello — not shown here. Lab prototype.</p>
            </div>
            <table>
                <tr>
                    <th>Packet</th>
                    <th>Source</th>
                    <th>Dest</th>
                    <th>Offered groups</th>
                    <th>Status</th>
                </tr>
                ${
                    rows ||
                    '<tr><td colspan="5">Listening... generate HTTPS traffic in the browser</td></tr>'
                }
            </table>
        </body>
    </html>`;
}
