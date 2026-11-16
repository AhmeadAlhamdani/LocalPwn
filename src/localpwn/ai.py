"""Optional BYOK AI analysis. AI outputs are advisory, never executable commands."""
import json
import os
import urllib.request
import urllib.error
from urllib.parse import urlsplit

SYSTEM = ("You are a defensive security assessment analyst. Analyze only the supplied observations. "
          "Return concise JSON with keys summary (string), hypotheses (array of objects with "
          "service, rationale, confidence), recommendations (array of strings). "
          "Do not provide shell commands, payloads, persistence or exploitation steps. "
          "Do not claim a weakness was confirmed based only on a software banner.")

def _post(url, payload, headers=None):
    request=urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json", **(headers or {})})
    with urllib.request.urlopen(request, timeout=90) as resp:
        return json.loads(resp.read(2_000_000))

def analyze(observations, provider="none", model=None, api_key=None):
    if provider == "none":
        return {"summary":"AI disabled: manual review required", "hypotheses":[],"recommendations":[]}
    content=json.dumps(observations,sort_keys=True)[:18000]
    if provider == "ollama":
        url=os.environ.get("LOCALPWN_OLLAMA_URL","http://127.0.0.1:11434/api/chat")
        parsed_url = urlsplit(url)
        if parsed_url.scheme != 'http' or parsed_url.hostname not in {'127.0.0.1', 'localhost', '::1'}:
            raise ValueError('Ollama must be accessible from the loopback interface')
        response=_post(url,{"model":model or "gpt-oss:20b", "stream":False,"format":"json","options":{"num_predict":768}, "messages":[{"role":"system","content":SYSTEM},{"role":"user","content":content}]})
        answer=response["message"]["content"]
    elif provider == "openai":
        key=api_key or os.environ.get("OPENAI_API_KEY")
        if not key: raise ValueError("OPENAI_API_KEY not set")
        response=_post("https://api.openai.com/v1/chat/completions",{"model":model or "gpt-4.1-mini","messages":[{"role":"system","content":SYSTEM},{"role":"user","content":content}],"response_format":{"type":"json_object"},"max_tokens":768}, {"Authorization":"Bearer "+key})
        answer=response["choices"][0]["message"]["content"]
    elif provider == "anthropic":
        key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key: raise ValueError("ANTHROPIC_API_KEY not set")
        response=_post("https://api.anthropic.com/v1/messages",{"model":model or "claude-sonnet-4-5","max_tokens":768,"system":SYSTEM,"messages":[{"role":"user","content":content}]}, {"x-api-key":key,"anthropic-version":"2023-06-01"})
        answer="".join(part.get("text","") for part in response.get("content",[]) if part.get("type")=="text")
    else:
        raise ValueError("Unsupported AI provider")
    parsed=json.loads(answer)
    if not isinstance(parsed,dict): raise ValueError("AI response must be a JSON object")
    return {"summary":str(parsed.get("summary",""))[:3000], "hypotheses":parsed.get("hypotheses",[])[:20] if isinstance(parsed.get("hypotheses",[]),list) else [],"recommendations":parsed.get("recommendations",[])[:20] if isinstance(parsed.get("recommendations",[]),list) else []}
