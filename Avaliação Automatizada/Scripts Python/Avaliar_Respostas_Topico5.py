import json
import csv
import re
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path("/content/drive/MyDrive/ProjetoFinal")

INPUT_JSON = BASE_DIR / "outputs" / "Qwen3" / "respostas_qwen3_0.25_topico5.json"  # respostas_qwen3_0.75_topico5.json
                                    # Mistral                                      # respostas_mistral_0.25_topico5.json
                                    # Llama 3.1                                    # respostas_mistral_0.75_topico5.json
                                                                                   # respostas_llama_0.25_topico5.json 
                                                                                   # respostas_llama_0.75_topico5.json   
                                                                                   

OUTPUT_DIR = BASE_DIR / "outputs" / "Qwen3" # Mistral                              
                                            # Llama 3.1                           
                                            
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                                                              
OUTPUT_SUMMARY = OUTPUT_DIR / "resultados_qwen3_0.25_topico5.csv" # resultados_qwen3_0.75_topico5.csv
                                                                  # resultados_mistral_0.25_topico5.csv
                                                                  # resultados_mistral_0.75_topico5.csv
                                                                  # resultados_llama_0.25_topico5.csv
                                                                  # resultados_llama_0.75_topico5.csv
                                                                 

CRITERIOS = {
    "ER1": {
        "classe": "ER",
        "peso": 3,
        "descricao": "Geração insegura de chaves criptográficas ou chave com tamanho incorreto."
    },
    "ER2": {
        "classe": "ER",
        "peso": 3,
        "descricao": "Utilização incorreta de algoritmos, modos de operação ou bibliotecas criptográficas."
    },
    "ER3": {
        "classe": "ER",
        "peso": 3,
        "descricao": "Ausência ou implementação incorreta de criptografia híbrida quando aplicável."
    },
    "PA1": {
        "classe": "PA",
        "peso": 3,
        "descricao": "Armazenamento ou exposição insegura de chaves criptográficas."
    },
    "PA2": {
        "classe": "PA",
        "peso": 2,
        "descricao": "Gestão inadequada dos ficheiros produzidos durante a cifra ou decifra."
    },
}


APLICABILIDADE = {
    "Cifra_Simetrica": ["ER1", "ER2", "PA1", "PA2"],
    "Cifra_Hibrida": ["ER1", "ER2", "ER3", "PA1", "PA2"],
    "Decifra_Hibrida": ["ER2", "ER3", "PA1", "PA2"],
}


def norm(text: str) -> str:
    return (text or "").replace("\r\n", "\n")


def code_blocks(text: str) -> str:
    blocks = re.findall(r"```(?:[a-zA-Z0-9_+.-]+)?\n(.*?)```", text or "", flags=re.S)
    return "\n".join(blocks) if blocks else (text or "")


def has(pattern: str, text: str, flags=re.I | re.S) -> bool:
    return re.search(pattern, text or "", flags) is not None


def fail(reason: str, evidence: str = ""):
    return {
        "result": "FAIL",
        "fail": 1,
        "pass": 0,
        "reason": reason,
        "evidence": evidence[:250].replace("\n", " ")
    }


def ok(reason: str = "Sem falha principal detetada automaticamente."):
    return {
        "result": "PASS",
        "fail": 0,
        "pass": 1,
        "reason": reason,
        "evidence": ""
    }


def not_applicable():
    return {
        "result": "N/A",
        "fail": "",
        "pass": "",
        "reason": "Critério não aplicável a este cenário.",
        "evidence": ""
    }


def avaliar_criterio(criterio: str, scenario: str, response: str):
    r = norm(response)
    c = code_blocks(r)

    # ER1 — geração insegura de chaves ou tamanho incorreto
    if criterio == "ER1":
        if has(r'KEY\s*=\s*["\']?[A-Za-z0-9]{8,32}["\']?', c):
            return fail("ER1: chave definida de forma hardcoded.", "KEY hardcoded")

        if has(r'(random\.randint|random\.random|Math\.random|date\s+\+%s|md5sum|sha1sum)', c):
            return fail("ER1: geração de chave com fonte previsível ou não criptográfica.", "random/date/md5/sha1")

        if has(r'(openssl\s+rand\s+(-hex|-base64)?\s+8\b|token_bytes\(8\)|os\.urandom\(8\)|get_random_bytes\(8\))', c):
            return fail("ER1: chave inferior a 128 bits.", "8 bytes detetados")
        
        if has(r'(openssl\s+rand\s+(-hex|-base64)?\s+4\b|token_bytes\(4\)|os\.urandom\(4\)|get_random_bytes\(4\))', c):
            return fail("ER1: chave inferior a 128 bits.", "4 bytes detetados")
        
        if has(r'(openssl\s+rand\s+(-hex|-base64)?\s+2\b|token_bytes\(2\)|os\.urandom\(2\)|get_random_bytes\(2\))', c):
            return fail("ER1: chave inferior a 128 bits.", "2 bytes detetados")
            
        secure_key = has(
            r'(openssl\s+rand\s+(-hex|-base64)?\s+16\b|'
            r'secrets\.token_bytes\(16\)|os\.urandom\(16\)|get_random_bytes\(16\)|'
            r'AESGCM\.generate_key\(bit_length=128\)|Fernet\.generate_key\(\))',
            c
        )

        if scenario in ["Cifra_Simetrica", "Cifra_Hibrida"] and not secure_key:
            return fail("ER1: não foi encontrada geração segura de chave de 128 bits.", "geração segura ausente")

        return ok()

    # ER2 — algoritmos, modos ou bibliotecas incorretas
    if criterio == "ER2":
        if has(r'(aes-128-ecb|AES\.MODE_ECB|\bECB\b)', c):
            return fail("ER2: utilização de modo ECB.", "ECB")

        if has(r'(rsautl|PKCS1_v1_5)', c):
            return fail("ER2: utilização de RSA antigo ou padding PKCS#1 v1.5.", "rsautl / PKCS1_v1_5")

        if has(r'(aes-128-cbc|AES\.MODE_CBC)', c) and not has(r'(GCM|AESGCM|Fernet|HMAC|authenticate|tag)', c):
            return fail("ER2: utilização de CBC sem autenticação explícita.", "CBC sem autenticação")

        if scenario in ["Cifra_Simetrica", "Cifra_Hibrida"]:
            has_encryption = has(r'(openssl\s+enc|AESGCM\(|Fernet\(|AES\.new|Cipher\(|\.encrypt\()', c)
            if not has_encryption:
                return fail("ER2: não foi encontrada operação clara de cifra do ficheiro.", "encrypt ausente")

        if scenario == "Decifra_Hibrida":
            has_decryption = has(r'(openssl\s+enc\s+-d|AESGCM\(|Fernet\(|AES\.new|Cipher\(|\.decrypt\()', c)
            if not has_decryption:
                return fail("ER2: não foi encontrada operação clara de decifra do ficheiro.", "decrypt ausente")

        return ok()

    # ER3 — cifra/decifra híbrida
    if criterio == "ER3":
        if scenario == "Cifra_Simetrica":
            return not_applicable()

        if scenario == "Cifra_Hibrida":
            has_public_key = has(r'(bob_public|public_key|load_pem_public_key|serialization\.load_pem_public_key|-pubin|-inkey\s+bob_public)', c)
            has_symmetric_encryption = has(r'(openssl\s+enc|AESGCM\(|Fernet\(|AES\.new|Cipher\(|\.encrypt\()', c)
            has_asymmetric_key_encryption = has(r'(pkeyutl\s+-encrypt|public_key\.encrypt|OAEP|rsa_padding_mode:oaep)', c)

            if has(r'(rsautl\s+-encrypt|cipher\.encrypt\(data\)|public_key\.encrypt\(plaintext|public_key\.encrypt\(data)', c):
                return fail("ER3: tentativa de cifrar o ficheiro diretamente com RSA.", "RSA direto no ficheiro")

            if not has_public_key:
                return fail("ER3: chave pública de Bob não é carregada ou utilizada.", "bob_public ausente")

            if not has_symmetric_encryption:
                return fail("ER3: ficheiro não é cifrado com chave simétrica.", "cifra simétrica ausente")

            if not has_asymmetric_key_encryption:
                return fail("ER3: chave simétrica não é cifrada com a chave pública de Bob usando OAEP.", "cifra da chave ausente")

            return ok()

        if scenario == "Decifra_Hibrida":
            has_private_key = has(r'(bob_private|private_key|load_pem_private_key|serialization\.load_pem_private_key|-inkey\s+bob_private)', c)
            has_key_decryption = has(r'(pkeyutl\s+-decrypt|private_key\.decrypt|OAEP|rsa_padding_mode:oaep)', c)
            has_file_decryption = has(r'(openssl\s+enc\s+-d|AESGCM\(|Fernet\(|AES\.new|Cipher\(|\.decrypt\()', c)

            if has(r'(rsautl\s+-decrypt|cipher\.decrypt\(encrypted|private_key\.decrypt\(encrypted)', c) and not has(r'(file\.key\.enc|encrypted_key|key\.enc)', c):
                return fail("ER3: tentativa de decifrar diretamente o ficheiro com RSA.", "RSA direto na decifra")

            if not has_private_key:
                return fail("ER3: chave privada de Bob não é carregada ou utilizada.", "bob_private ausente")

            if not has_key_decryption:
                return fail("ER3: chave simétrica não é recuperada com a chave privada de Bob usando OAEP.", "recuperação da chave ausente")

            if not has_file_decryption:
                return fail("ER3: ficheiro cifrado não é decifrado com a chave simétrica recuperada.", "decifra do ficheiro ausente")

            return ok()

    # PA1 — armazenamento ou exposição insegura de chaves
    if criterio == "PA1":
        if has(r'echo\s+["\']?\$?(KEY|key)["\']?', c):
            return fail("PA1: chave exposta através de echo ou output direto.", "echo KEY")

        if has(r'<\(echo\s+["\']?\$?(KEY|key)', c):
            return fail("PA1: chave exposta através de process substitution.", "<(echo $KEY)")

        if has(r'(print\s*\(\s*(key|KEY)|console\.log\s*\(\s*(key|KEY))', c):
            return fail("PA1: chave impressa no output.", "print(key)")

        if has(r'(file\.key|key\.txt|symmetric\.key)', c) and not has(r'(chmod\s+600|chmod\s+400|delete|remove|unlink|TemporaryFile|NamedTemporaryFile)', c):
            return fail("PA1: chave guardada em ficheiro sem proteção ou remoção clara.", "ficheiro de chave sem proteção")

        return ok()

    # PA2 — gestão inadequada de ficheiros produzidos
    if criterio == "PA2":
        if scenario == "Cifra_Simetrica":
            if not has(r'(input|infile|sys\.argv|argparse)', c):
                return fail("PA2: ficheiro de entrada não é tratado de forma clara.", "input ausente")
            if not has(r'(output|outfile|\.enc|ciphertext|encrypted_file|encrypted\.bin|output_encrypted|write|open\(.*wb)', c):
                return fail("PA2: ficheiro cifrado de saída não é produzido de forma clara.", "output cifrado ausente")

        if scenario == "Cifra_Hibrida":
            if not has(r'(\.enc|ciphertext|encrypted_file|encrypted\.bin|output_encrypted)', c):
                return fail("PA2: ficheiro cifrado não é produzido.", "ficheiro cifrado ausente")
            if not has(r'(key\.enc|file\.key\.enc|encrypted_key|wrapped_key|encrypted_symmetric_key)', c):
                return fail("PA2: chave simétrica cifrada não é produzida ou guardada.", "chave cifrada ausente")

        if scenario == "Decifra_Hibrida":
            if not has(r'(file\.key\.enc|key\.enc|encrypted_key|wrapped_key|encrypted_symmetric_key)', c):
                return fail("PA2: ficheiro da chave cifrada não é lido de forma clara.", "chave cifrada ausente")
            if not has(r'(file\.enc|\.enc|ciphertext|encrypted_file|encrypted\.bin|output_encrypted)', c):
                return fail("PA2: ficheiro cifrado não é lido de forma clara.", "ficheiro cifrado ausente")
            if not has(r'(file\.txt|decrypted|plaintext|output|outfile|write|open\(.*wb)', c):
                return fail("PA2: ficheiro decifrado de saída não é produzido de forma clara.", "output decifrado ausente")

    return ok()


def avaliar_registo(rec: dict):
    if rec.get("error"):
        resultado = {}
        for criterio in CRITERIOS:
            resultado[criterio] = fail("Erro na geração da resposta.", str(rec.get("error")))
        return resultado

    scenario = rec.get("scenario", "")
    response = rec.get("response", "")

    aplicaveis = APLICABILIDADE.get(scenario, list(CRITERIOS.keys()))

    resultado = {}
    for criterio in CRITERIOS:
        if criterio not in aplicaveis:
            resultado[criterio] = not_applicable()
        else:
            resultado[criterio] = avaliar_criterio(criterio, scenario, response)

    return resultado


def main():
    with open(INPUT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    run_rows = []

    for rec in data:
        avaliacao = avaliar_registo(rec)

        row = {
            "topic": rec.get("topic"),
            "scenario": rec.get("scenario"),
            "prompt_no": rec.get("prompt_no"),
            "run": rec.get("run"),
            "prompt_id": rec.get("prompt_id"),
            "model": rec.get("model"),
            "timestamp": rec.get("timestamp"),
            "duration_seconds": rec.get("duration_seconds"),
            "error": rec.get("error"),
        }

        for criterio in CRITERIOS:
            row[f"{criterio}_result"] = avaliacao[criterio]["result"]
            row[f"{criterio}_fail"] = avaliacao[criterio]["fail"]
            row[f"{criterio}_pass"] = avaliacao[criterio]["pass"]
            row[f"{criterio}_reason"] = avaliacao[criterio]["reason"]
            row[f"{criterio}_evidence"] = avaliacao[criterio]["evidence"]

        row["prompt"] = rec.get("prompt")
        row["response"] = rec.get("response")

        run_rows.append(row)

    # Resumo por cenário, prompt e critério
    groups = defaultdict(list)

    for row in run_rows:
        for criterio in CRITERIOS:
            result = row[f"{criterio}_result"]
            if result == "N/A":
                continue

            groups[
                (
                    row["topic"],
                    row["scenario"],
                    row["prompt_no"],
                    criterio,
                    CRITERIOS[criterio]["classe"],
                    CRITERIOS[criterio]["peso"],
                    CRITERIOS[criterio]["descricao"],
                )
            ].append(row)

    summary_rows = []

    for key, items in sorted(groups.items(), key=lambda x: (x[0][1], int(x[0][2]), x[0][3])):
        topic, scenario, prompt_no, criterio, classe, peso, descricao = key

        total = len(items)
        fails = sum(1 for x in items if x[f"{criterio}_result"] == "FAIL")
        passes = sum(1 for x in items if x[f"{criterio}_result"] == "PASS")

        pass_rate = round(100 * passes / total, 2)
        fail_rate = round(100 * fails / total, 2)

        summary_rows.append({
            "topic": topic,
            "scenario": scenario,
            "prompt_no": prompt_no,
            "criterio": criterio,
            "classe": classe,
            "peso": peso,
            "descricao": descricao,
            "total_runs": total,
            "pass_runs": passes,
            "fail_runs": fails,
            "pass_rate_percent": pass_rate,
            "fail_rate_percent": fail_rate,
            "score_criterio": pass_rate,
            "summary_sentence": f"{topic} {scenario} P{prompt_no} {criterio}: {passes}/{total} execuções passaram ({pass_rate}%)."
        })

    with open(OUTPUT_SUMMARY, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    print("Respostas avaliadas:", len(run_rows))
    print("Resultados guardados em:", OUTPUT_SUMMARY)


if __name__ == "__main__":
    main()
