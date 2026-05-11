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
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>FuzzyAI Red Team Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 20px; background-color: #121212; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .card {{ background-color: #1e1e1e; border: 1px solid #333; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); padding: 20px; margin-bottom: 20px; }}
        .chart-container {{ position: relative; height: 400px; width: 100%; }}
        h1, h2 {{ color: #ffffff; border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 0.9em; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #333; }}
        th {{ background-color: #2d2d2d; font-weight: 600; }}
        tr:hover {{ background-color: #2a2a2a; }}
        .mitigation-list li {{ margin-bottom: 10px; line-height: 1.5; }}
        .severity-high {{ color: #ff4444; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        
        <div class="card">
            <h2><i class="fas fa-shield-alt"></i> Recommended Mitigations</h2>
            <ul id="mitigationsList" class="mitigation-list"></ul>
        </div>

        <div class="card">
            <h2><i class="fas fa-spider"></i> Threat Surface (Radar)</h2>
            <div class="chart-container" style="height: 500px;">
                <canvas id="radarChart"></canvas>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <h2>Model Vulnerability Rate</h2>
                    <div class="chart-container"><canvas id="modelSuccessChart"></canvas></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <h2>Attack Vector Success</h2>
                    <div class="chart-container"><canvas id="attackSuccessChart"></canvas></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2><i class="fas fa-biohazard"></i> Extracted Data (Successful Jailbreaks)</h2>
            <table id="harmfulPromptsTable">
                <thead><tr><th>Target Model</th><th>Original Intent</th><th>Adversarial Payload</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <script>
        const reportData = {report_data};

        // 1. Generate Mitigations based on successful attacks
        const mitigationsList = document.getElementById('mitigationsList');
        const mitigations = new Set();
        
        const mitigationsDict = reportData.mitigationsDict;

        reportData.attackSuccessRate.forEach(attack => {{
            if (attack.value > 0) {{
                // Check if we have a specific mitigation for this attack
                if (mitigationsDict[attack.name]) {{
                    mitigations.add(mitigationsDict[attack.name]);
                }} else {{
                    // Fallback mitigation using standard string addition to avoid Python format errors
                    mitigations.add('<span class="severity-high">[ATTENTION] ' + attack.name + ':</span> Vulnerability detected. <b>Mitigation:</b> Apply general LLM security best practices and review logs.');
                }}
            }}
        }});

        if (mitigations.size === 0) {{
            mitigations.add('<span style="color: #00C851;">[SAFE] Zero-Day Defenses Active:</span> No major vulnerabilities detected during this fuzzing run. Current system prompts are highly resilient.');
        }}

        mitigations.forEach(text => {{
            const li = document.createElement('li');
            li.innerHTML = text;
            mitigationsList.appendChild(li);
        }});

        // 2. Radar Chart (Threat Surface)
        const radarColors = ['rgba(255, 99, 132, 0.5)', 'rgba(54, 162, 235, 0.5)', 'rgba(255, 206, 86, 0.5)', 'rgba(75, 192, 192, 0.5)'];
        const radarBorders = ['rgba(255, 99, 132, 1)', 'rgba(54, 162, 235, 1)', 'rgba(255, 206, 86, 1)', 'rgba(75, 192, 192, 1)'];
        
        const radarDatasets = reportData.heatmap.models.map((model, index) => ({{
            label: model,
            data: reportData.heatmap.attacks.map((attack, i) => reportData.heatmap.data[i][index] * 100),
            backgroundColor: radarColors[index % radarColors.length],
            borderColor: radarBorders[index % radarBorders.length],
            pointBackgroundColor: radarBorders[index % radarBorders.length],
            fill: true
        }}));

        new Chart(document.getElementById('radarChart'), {{
            type: 'radar',
            data: {{ labels: reportData.heatmap.attacks, datasets: radarDatasets }},
            options: {{ responsive: true, maintainAspectRatio: false, scales: {{ r: {{ angleLines: {{ color: '#444' }}, grid: {{ color: '#444' }}, pointLabels: {{ color: '#fff', font: {{ size: 14 }} }}, ticks: {{ backdropColor: 'transparent', color: '#888', min: 0, max: 100 }} }} }}, plugins: {{ legend: {{ labels: {{ color: '#fff' }} }} }} }}
        }});

        // 3. Bar Charts
        const commonOptions = {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ beginAtZero: true, max: 100, grid: {{ color: '#333' }}, ticks: {{ color: '#888' }} }}, x: {{ grid: {{ color: '#333' }}, ticks: {{ color: '#888' }} }} }}, plugins: {{ legend: {{ display: false }} }} }};

        new Chart(document.getElementById('modelSuccessChart'), {{
            type: 'bar',
            data: {{ labels: reportData.modelSuccessRate.map(i => i.name), datasets: [{{ data: reportData.modelSuccessRate.map(i => i.value), backgroundColor: 'rgba(255, 99, 132, 0.8)' }}] }},
            options: commonOptions
        }});

        new Chart(document.getElementById('attackSuccessChart'), {{
            type: 'bar',
            data: {{ labels: reportData.attackSuccessRate.map(i => i.name), datasets: [{{ data: reportData.attackSuccessRate.map(i => i.value), backgroundColor: 'rgba(54, 162, 235, 0.8)' }}] }},
            options: commonOptions
        }});

        // 4. Data Table
        const harmfulPromptsBody = document.querySelector('#harmfulPromptsTable tbody');
        reportData.harmfulPrompts.forEach(prompt => {{
            const row = document.createElement('tr');
            row.innerHTML = `<td><span class="badge bg-danger">VULNERABLE</span></td><td>${{prompt.original}}</td><td><code>${{prompt.harmful.substring(0, 150)}}...</code></td>`;
            harmfulPromptsBody.appendChild(row);
        }});
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