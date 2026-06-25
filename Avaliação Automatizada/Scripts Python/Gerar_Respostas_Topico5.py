import json
import time
from datetime import datetime
from pathlib import Path
from tqdm import tqdm

N_REPETICOES = 5
MODEL_NAME = "unsloth/Qwen3-4B-Instruct-2507-bnb-4bit"
# MODEL_NAME = "unsloth/mistral-7b-instruct-v0.3-bnb-4bit"
# MODEL_NAME = "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit"
# MODEL_NAME = "unsloth/gpt-oss-20b-unsloth-bnb-4bit"

base_dir = Path("/content/drive/MyDrive/ProjetoFinal")
prompts_path = base_dir / "prompts" / "prompts_topico_5.json"
outputs_dir = base_dir / "outputs" / "Qwen3" # Mistral 
                                             # Llama 3.1
                                             # GPT-OSS
outputs_dir.mkdir(exist_ok=True)

json_output_path = outputs_dir / "respostas_qwen3_0.25_topico5.json"  # respostas_qwen3_0.75_topico5.json 
                                                                      # respostas_mistral_0.75_topico5.json 
                                                                      # respostas_mistral_0.25_topico5.json 
                                                                      # respostas_llama_0.75_topico5.json 
                                                                      # respostas_llama_0.25_topico5.json 
                                                                      # respostas_gpt_oss_0.75_topico5.json 
                                                                      # respostas_gpt_oss_0.25_topico5.json 


def gerar_resposta(prompt, max_new_tokens=900):
    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity assistant. Answer clearly and produce secure code or secure instructions when requested."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer([text], return_tensors="pt").to("cuda")

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_new_tokens,
        temperature=0.25, # temperature = 0.75
        top_p=0.9,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id
    )

    resposta = tokenizer.decode(
        outputs[0][inputs.input_ids.shape[1]:],
        skip_special_tokens=True
    )

    return resposta


with open(prompts_path, "r", encoding="utf-8") as f:
    prompts = json.load(f)

resultados = []

if json_output_path.exists():
    with open(json_output_path, "r", encoding="utf-8") as f:
        resultados = json.load(f)

ja_feitos = {
    (r["prompt_id"], r["run"])
    for r in resultados
}

for item in tqdm(prompts, desc="A correr prompts"):
    for run in range(1, N_REPETICOES + 1):

        chave = (item["id"], run)

        if chave in ja_feitos:
            continue

        inicio = time.time()

        try:
            resposta = gerar_resposta(item["prompt"])
            erro = None

        except Exception as e:
            resposta = ""
            erro = str(e)

        fim = time.time()

        registo = {
            "timestamp": datetime.now().isoformat(),
            "model": MODEL_NAME,
            "prompt_id": item["id"],
            "topic": item["topic"],
            "scenario": item["scenario"],
            "prompt_no": item["prompt_no"],
            "run": run,
            "prompt": item["prompt"],
            "response": resposta,
            "error": erro,
            "duration_seconds": round(fim - inicio, 2)
        }

        resultados.append(registo)

        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(resultados, f, ensure_ascii=False, indent=2)

print("Total de respostas:", len(resultados))
print("JSON guardado em:", json_output_path)
