import json
import logging
import subprocess
from datetime import datetime
from typing import Any, Dict, Optional, Type, Union

from tabulate import tabulate

from fuzzyai.llm.providers.base import BaseLLMProvider, llm_provider_fm
from fuzzyai.llm.providers.enums import LLMProvider
from fuzzyai.models.fuzzer_result import FuzzerResult

CURRENT_TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
logger = logging.getLogger(__name__)

def llm_provider_model_sanity(provider: str, model: str) -> None:
    """
    Check if the model is supported by the provider.

    Args:
        provider (str): The flavor of the provider.
        model (str): The model to check.

    Raises:
        ValueError: If the model is not supported by the provider.
    """
    provider_class: Type[BaseLLMProvider] = llm_provider_fm[provider]
    supported_models: Union[str, list[str]] = provider_class.get_supported_models()
    if supported_models and isinstance(supported_models, list) and model not in supported_models:
        raise ValueError(f"Model {model} not supported by provider {provider}, supported models: {supported_models}")
    
def llm_provider_factory(provider: LLMProvider, model: str, **extra: Any) -> BaseLLMProvider:
    """
    Factory method to create an instance of the language model provider.

    Args:
        provider_name (LLMProvider): The name of the language model provider.
        model (str): The model to use.
        **extra (Any): Additional arguments for the language model provider.

    Returns:
        BaseLLMProvider: An instance of the language model provider.
    """
    llm_provider_model_sanity(provider, model)
    return llm_provider_fm[provider](provider=provider, model=model, **extra)

def extract_json(s: str) -> Optional[dict[str, Any]]:
    """
    Given a string potentially containing JSON data, extracts and returns
    the values for `improvement` and `adversarial prompt` as a dictionary.

    Args:
        s (str): The string containing the potential JSON structure.

    Returns:
        dict: A dictionary containing the extracted values.
    """
    # Find the JSON substring
    start_pos = s.find("{")
    end_pos = s.find("}", start_pos) + 1  # Include the closing brace
    if end_pos == -1:
        logger.error("Error extracting potential JSON structure")
        logger.error(f"Input:\n {s}")
        return None

    json_str = s[start_pos:end_pos].replace("\n", "").replace("\r", "")

    try:
        parsed: dict[str, Any] = json.loads(json_str)
        if not all(key in parsed for key in ["improvement", "prompt"]):
            logger.error("Error in extracted structure. Missing keys.")
            logger.error(f"Extracted:\n {json_str}")
            return None
        return parsed
    except json.JSONDecodeError:
        logger.error("Error parsing extracted structure")
        logger.error(f"Extracted:\n {json_str}")
        return None

def print_report(report: FuzzerResult) -> None:
    headers = ["prompt", "model", "attack method", "adversarial prompt", "response", "jailbreak?"]
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"
    table_data = []
    green = f"✅"
    red = f"❌"

    for entry in report.attacking_techniques or []:
        for model_entry in entry.models:
            for failed_prompts in model_entry.failed_prompts:
                table_data.append([failed_prompts.original_prompt, model_entry.name, entry.attack_mode, failed_prompts.harmful_prompt or "-", failed_prompts.harmful_response, red])
            for successful_prompts in model_entry.harmful_prompts:
                table_data.append([successful_prompts.original_prompt, model_entry.name, entry.attack_mode, successful_prompts.harmful_prompt, successful_prompts.harmful_response, green])
            
    try:
        print(tabulate(table_data, headers, tablefmt="simple_grid", maxcolwidths=[40, 20, 20, 40, 50, 10], colalign=("center", "center", "center", "center", "center", "center")))
    except Exception as e:
        logger.error("Can't generating report")

# Define the template with double curly braces for JavaScript/CSS and single for Python
REPORT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FuzzyAI — Red Team Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Syne:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {{
            --bg:    #010409;
            --bg2:   #070c17;
            --bg3:   #0a1020;
            --green: #00ff88;
            --blue:  #00d4ff;
            --red:   #ff2255;
            --gold:  #ffd700;
            --t:     #5a6880;
            --tl:    #c0cdd9;
            --glass: rgba(7,12,23,0.85);
            --gb:    rgba(0,255,136,0.12);
            --gbb:   rgba(0,212,255,0.18);
        }}

        *, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
        html {{ scroll-behavior:smooth; }}

        body {{
            font-family: 'Syne', sans-serif;
            background: var(--bg);
            color: var(--tl);
            padding: 0;
            min-height: 100vh;
        }}

        /* Scanlines */
        body::before {{
            content: '';
            position: fixed; inset: 0; z-index: 9999; pointer-events: none;
            background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px);
        }}

        /* ── HEADER ── */
        .report-header {{
            background: var(--bg2);
            border-bottom: 1px solid var(--gb);
            padding: 2.5rem 3rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 2rem;
            flex-wrap: wrap;
        }}
        .header-brand {{
            font-family: 'Orbitron', sans-serif;
            font-weight: 900;
            font-size: 1.8rem;
            letter-spacing: 5px;
            color: #fff;
        }}
        .header-brand span {{ color: var(--green); }}
        .header-meta {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--t);
            letter-spacing: 2px;
            line-height: 2;
            text-align: right;
        }}
        .header-meta strong {{ color: var(--blue); }}

        /* ── LAYOUT ── */
        .report-body {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2.5rem 2rem;
        }}

        /* ── SECTION LABEL ── */
        .s-label {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            color: var(--blue);
            letter-spacing: 4px;
            text-transform: uppercase;
            display: block;
            margin-bottom: 0.6rem;
        }}
        .s-title {{
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 1.05rem;
            color: #fff;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .s-title i {{ color: var(--green); font-size: 0.9rem; }}

        /* ── CARD ── */
        .card {{
            background: var(--glass);
            border: 1px solid var(--gb);
            border-radius: 4px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(12px);
            position: relative;
        }}
        .card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0;
            width: 3px; height: 100%;
            background: linear-gradient(to bottom, var(--blue), var(--green));
            border-radius: 4px 0 0 4px;
        }}

        /* Corner brackets */
        .card::after {{
            content: '';
            position: absolute;
            top: -1px; right: -1px;
            width: 16px; height: 16px;
            border-top: 2px solid var(--green);
            border-right: 2px solid var(--green);
        }}

        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }}
        @media(max-width: 750px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

        /* ── CHART ── */
        .chart-wrap {{
            position: relative;
            height: 320px;
            width: 100%;
        }}
        .chart-wrap.tall {{ height: 420px; }}

        /* ── MITIGATIONS ── */
        .mit-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }}
        .mit-list li {{
            font-size: 0.88rem;
            line-height: 1.8;
            color: var(--tl);
            padding: 0.9rem 1.1rem;
            background: rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 4px;
            border-left: 3px solid var(--red);
        }}
        .mit-list li.safe {{ border-left-color: var(--green); }}
        .severity-high {{
            color: var(--red);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            font-weight: 700;
        }}

        /* ── TABLE ── */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.84rem;
        }}
        .data-table thead tr {{
            background: rgba(0,212,255,0.06);
            border-bottom: 1px solid rgba(0,212,255,0.2);
        }}
        .data-table th {{
            font-family: 'Orbitron', monospace;
            font-size: 0.65rem;
            letter-spacing: 2px;
            color: var(--blue);
            padding: 12px 14px;
            text-align: left;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .data-table td {{
            padding: 11px 14px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            color: var(--tl);
            vertical-align: top;
        }}
        .data-table tr:hover td {{ background: rgba(0,255,136,0.03); }}
        .data-table code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--gold);
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 3px;
            display: block;
            margin-top: 4px;
            line-height: 1.6;
        }}
        .badge-vuln {{
            font-family: 'Orbitron', sans-serif;
            font-size: 0.58rem;
            letter-spacing: 1px;
            padding: 4px 8px;
            background: rgba(255,34,85,0.15);
            border: 1px solid rgba(255,34,85,0.4);
            color: var(--red);
            border-radius: 3px;
            white-space: nowrap;
        }}

        /* ── FOOTER ── */
        .report-footer {{
            text-align: center;
            padding: 2rem;
            border-top: 1px solid rgba(255,255,255,0.04);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            color: var(--t);
            letter-spacing: 2px;
        }}
        .report-footer strong {{ color: var(--green); }}
    </style>
</head>
<body>

    <!-- HEADER -->
    <div class="report-header">
        <div>
            <div class="header-brand"><span>◈</span> FUZZYAI</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:var(--t);letter-spacing:3px;margin-top:4px">RED TEAM SECURITY REPORT</div>
        </div>
        <div class="header-meta">
            <strong>UNIVERSITY OF BAHRAIN</strong><br>
            Cybersecurity Research — Class of 2026<br>
            Generated: <span id="gen-time"></span>
        </div>
    </div>

    <div class="report-body">

        <!-- MITIGATIONS -->
        <div class="card">
            <span class="s-label">// 01 — Recommendations</span>
            <div class="s-title"><i class="fas fa-shield-alt"></i>Recommended Mitigations</div>
            <ul id="mitigationsList" class="mit-list"></ul>
        </div>

        <!-- RADAR -->
        <div class="card">
            <span class="s-label">// 02 — Threat Surface</span>
            <div class="s-title"><i class="fas fa-spider"></i>Attack Surface Radar</div>
            <div class="chart-wrap tall">
                <canvas id="radarChart"></canvas>
            </div>
        </div>

        <!-- BAR CHARTS -->
        <div class="two-col">
            <div class="card">
                <span class="s-label">// 03 — Model Exposure</span>
                <div class="s-title"><i class="fas fa-robot"></i>Model Vulnerability Rate</div>
                <div class="chart-wrap"><canvas id="modelSuccessChart"></canvas></div>
            </div>
            <div class="card">
                <span class="s-label">// 04 — Attack Vectors</span>
                <div class="s-title"><i class="fas fa-crosshairs"></i>Attack Vector Success</div>
                <div class="chart-wrap"><canvas id="attackSuccessChart"></canvas></div>
            </div>
        </div>

        <!-- TABLE -->
        <div class="card">
            <span class="s-label">// 05 — Exfiltration Log</span>
            <div class="s-title"><i class="fas fa-biohazard"></i>Extracted Data — Successful Jailbreaks</div>
            <table class="data-table" id="harmfulPromptsTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Original Intent</th>
                        <th>Adversarial Payload</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

    </div>

    <!-- FOOTER -->
    <div class="report-footer">
        <strong>FUZZYAI</strong> &nbsp;·&nbsp; University of Bahrain &nbsp;·&nbsp; Open-Source Data Exfiltration Framework
    </div>

    <script>
        // Timestamp
        document.getElementById('gen-time').textContent = new Date().toUTCString();

        const reportData = {report_data};

        // ── 1. MITIGATIONS ──
        const mitigationsList = document.getElementById('mitigationsList');
        const mitigations = new Set();
        const mitigationsDict = reportData.mitigationsDict;

        reportData.attackSuccessRate.forEach(attack => {{
            if (attack.value > 0) {{
                if (mitigationsDict[attack.name]) {{
                    mitigations.add(mitigationsDict[attack.name]);
                }} else {{
                    mitigations.add('<span class="severity-high">[ATTENTION] ' + attack.name + ':</span> Vulnerability detected. <b>Mitigation:</b> Apply general LLM security best practices and review logs.');
                }}
            }}
        }});

        if (mitigations.size === 0) {{
            const li = document.createElement('li');
            li.classList.add('safe');
            li.innerHTML = '<span style="color:var(--green);font-family:JetBrains Mono,monospace;font-size:.8rem">[SAFE] ZERO VULNERABILITIES DETECTED</span><br>No major vulnerabilities detected during this fuzzing run. Current system prompts are highly resilient.';
            mitigationsList.appendChild(li);
        }} else {{
            mitigations.forEach(text => {{
                const li = document.createElement('li');
                li.innerHTML = text;
                mitigationsList.appendChild(li);
            }});
        }}

        // ── CHART DEFAULTS ──
        Chart.defaults.color = '#5a6880';
        Chart.defaults.font.family = "'JetBrains Mono', monospace";
        Chart.defaults.font.size = 11;

        const gridColor = 'rgba(255,255,255,0.06)';

        // ── 2. RADAR ──
        const radarColors   = ['rgba(255,34,85,0.25)','rgba(0,212,255,0.25)','rgba(255,215,0,0.25)','rgba(0,255,136,0.25)'];
        const radarBorders  = ['rgba(255,34,85,0.9)','rgba(0,212,255,0.9)','rgba(255,215,0,0.9)','rgba(0,255,136,0.9)'];

        const radarDatasets = reportData.heatmap.models.map((model, index) => ({{
            label: model,
            data: reportData.heatmap.attacks.map((_, i) => reportData.heatmap.data[i][index] * 100),
            backgroundColor: radarColors[index % radarColors.length],
            borderColor:     radarBorders[index % radarBorders.length],
            pointBackgroundColor: radarBorders[index % radarBorders.length],
            pointRadius: 4,
            fill: true
        }}));

        new Chart(document.getElementById('radarChart'), {{
            type: 'radar',
            data: {{ labels: reportData.heatmap.attacks, datasets: radarDatasets }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                scales: {{ r: {{
                    angleLines: {{ color: gridColor }},
                    grid:       {{ color: gridColor }},
                    pointLabels: {{ color: '#c0cdd9', font: {{ size: 12, family: "'Orbitron', sans-serif" }} }},
                    ticks: {{ backdropColor: 'transparent', color: '#5a6880', min: 0, max: 100 }}
                }} }},
                plugins: {{ legend: {{ labels: {{ color: '#c0cdd9', padding: 20 }} }} }}
            }}
        }});

        // ── 3. BAR CHARTS ──
        const barOpts = {{
            responsive: true, maintainAspectRatio: false,
            scales: {{
                y: {{ beginAtZero: true, max: 100, grid: {{ color: gridColor }}, ticks: {{ color: '#5a6880' }} }},
                x: {{ grid: {{ color: 'transparent' }}, ticks: {{ color: '#5a6880' }} }}
            }},
            plugins: {{ legend: {{ display: false }} }}
        }};

        new Chart(document.getElementById('modelSuccessChart'), {{
            type: 'bar',
            data: {{
                labels: reportData.modelSuccessRate.map(i => i.name),
                datasets: [{{ data: reportData.modelSuccessRate.map(i => i.value), backgroundColor: 'rgba(255,34,85,0.7)', borderColor: 'rgba(255,34,85,1)', borderWidth: 1, borderRadius: 3 }}]
            }},
            options: barOpts
        }});

        new Chart(document.getElementById('attackSuccessChart'), {{
            type: 'bar',
            data: {{
                labels: reportData.attackSuccessRate.map(i => i.name),
                datasets: [{{ data: reportData.attackSuccessRate.map(i => i.value), backgroundColor: 'rgba(0,212,255,0.6)', borderColor: 'rgba(0,212,255,1)', borderWidth: 1, borderRadius: 3 }}]
            }},
            options: barOpts
        }});

        // ── 4. TABLE ──
        const tbody = document.querySelector('#harmfulPromptsTable tbody');
        reportData.harmfulPrompts.forEach(prompt => {{
            const row = document.createElement('tr');
            row.innerHTML =
                `<td><span class="badge-vuln">BREACH</span></td>` +
                `<td>${{prompt.original}}</td>` +
                `<td><code>${{prompt.harmful.substring(0, 150)}}...</code></td>`;
            tbody.appendChild(row);
        }});

        if (reportData.harmfulPrompts.length === 0) {{
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="3" style="text-align:center;color:var(--t);padding:2rem;font-family:'JetBrains Mono',monospace;font-size:.8rem">[ NO SUCCESSFUL JAILBREAKS IN THIS SESSION ]</td>`;
            tbody.appendChild(row);
        }}
    </script>
</body>
</html>
'''

def generate_report(report: FuzzerResult) -> None:
    try:
        # Process data for the report
        model_success_rate = []
        attack_success_rate = []
        harmful_prompts = []
        failed_prompts = []
        
        # Calculate model success rates
        model_total_prompts: Dict[str, int] = {}
        model_success: Dict[str, int] = {}
        
        # Calculate heatmap data
        heatmap_data = []
        models = []
        attacks = []
        
        for entry in report.attacking_techniques or []:
            attacks.append(entry.attack_mode)
            row_data = []
            
            for model_entry in entry.models:
                if model_entry.name not in models:
                    models.append(model_entry.name)
                
                total = len(model_entry.harmful_prompts) + len(model_entry.failed_prompts)
                success = len(model_entry.harmful_prompts)
                
                # Add to model totals
                model_total_prompts[model_entry.name] = model_total_prompts.get(model_entry.name, 0) + total
                model_success[model_entry.name] = model_success.get(model_entry.name, 0) + success
                
                # Add to heatmap
                success_rate = success / total if total > 0 else 0
                row_data.append(success_rate)
                
                # Collect prompts
                for prompt in model_entry.harmful_prompts:
                    harmful_prompts.append({
                        "original": prompt.original_prompt,
                        "harmful": prompt.harmful_prompt
                    })
                for prompt in model_entry.failed_prompts:
                    failed_prompts.append({
                        "original": prompt.original_prompt,
                        "harmful": prompt.harmful_prompt
                    })
            
            heatmap_data.append(row_data)

        # Convert to format needed for Chart.js
        for model_name, total in model_total_prompts.items():
            success_rate = (model_success[model_name] / total * 100) if total > 0 else 0
            model_success_rate.append({
                "name": model_name,
                "value": round(success_rate, 2)
            })

        # Calculate attack mode success rates
        attack_totals: Dict[str, int] = {}
        attack_successes: Dict[str, int] = {}
        
        for entry in report.attacking_techniques or []:
            mode = entry.attack_mode
            attack_totals[mode] = 0
            attack_successes[mode] = 0
            
            for model_entry in entry.models:
                attack_totals[mode] += len(model_entry.harmful_prompts) + len(model_entry.failed_prompts)
                attack_successes[mode] += len(model_entry.harmful_prompts)

        for mode, total in attack_totals.items():
            success_rate = (attack_successes[mode] / total * 100) if total > 0 else 0
            attack_success_rate.append({
                "name": mode,
                "value": round(success_rate, 2)
            })

        # Define dynamic mitigations mapped to attack modes
        dynamic_mitigations = {
            "prompt_extraction": "<span class='severity-high'>[HIGH] Prompt Extraction:</span> The model is leaking internal constraints. <b>Mitigation:</b> Implement strict input validation and utilize a robust system prompt with explicit refusal instructions for meta-queries.",
            "format_forcing": "<span class='severity-high'>[HIGH] Format Forcing:</span> The model is leaking data via format manipulation. <b>Mitigation:</b> Enforce strict output schema validation before rendering responses to the user. Strip unexpected JSON/YAML tags.",
            "gpt_fuzzer": "<span class='severity-high'>[HIGH] Generative Roleplay:</span> The model is bypassing rules through complex persona adoption. <b>Mitigation:</b> Deploy an LLM-based Input Classifier to block adversarial framing.",
            "dan": "<span class='severity-high'>[HIGH] DAN Jailbreak:</span> The model is breaking character constraints. <b>Mitigation:</b> Reinforce core directives and use a secondary evaluator to monitor for persona drift.",
            "base64": "<span class='severity-high'>[MED] Obfuscation Bypass:</span> The model is executing encoded payloads. <b>Mitigation:</b> Implement a pre-processing middleware to decode and scan Base64 strings against blocklists."
        }

        # Prepare the report data
        report_data = {
            "modelSuccessRate": model_success_rate,
            "attackSuccessRate": attack_success_rate,
            "harmfulPrompts": harmful_prompts,
            "failedPrompts": failed_prompts,
            "heatmap": {
                "data": heatmap_data,
                "models": models,
                "attacks": attacks
            },
            "mitigationsDict": dynamic_mitigations 
        }

        # Generate the HTML report using string formatting
        html_data = REPORT_TEMPLATE.format(report_data=json.dumps(report_data))
        
        # Save the report
        output_path = f'results/{CURRENT_TIMESTAMP}/report.html'
        with open(output_path, 'w') as f:
            f.write(html_data)
            
        logger.info(f"Report generated at {output_path}")
        
    except Exception as ex:
        logger.error(f"Error generating report: {str(ex)}")
        raise

def run_ollama_list_command() -> None:
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"Error running 'ollama list': {result.stderr}")
        return
    except FileNotFoundError:
        print("Error: 'ollama' command not found. Please make sure to download ollama from ollama.com")
        return
    except Exception as e:
        print(f"An error occurred while running 'ollama list': {e}")
        return
    
def get_ollama_models() -> list[str]:
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running 'ollama list': {result.stderr}")
            return []
        
        lines = result.stdout.splitlines()
        models = [line.split()[0] for line in lines[1:] if line.strip()]
        return models
    except FileNotFoundError:
        print("Error: 'ollama' command not found. Please make sure to download ollama from ollama.com")
        return []
    except Exception as e:
        print(f"An error occurred while running 'ollama list': {e}")
        return []