// PromptArmor — prompt-injection detector
// Pure ESM, zero dependencies. Runs identically in Node.js and Cloudflare Workers.
//
// analyze(text) -> { score, verdict: 'allow' | 'flag' | 'block', hits: [{ rule, detail }] }
//
// Design notes:
// - Detection runs on a *normalized* copy of the input: Unicode NFKC, zero-width
//   characters stripped, Cyrillic/Greek homoglyphs folded to Latin, common
//   leetspeak folded back, whitespace collapsed, and "s p a c e d   o u t"
//   letter runs joined. Attackers use all of these to slip past naive filters.
// - Rules are weighted. High-severity rules score 70 (block on their own),
//   medium rules score 30-40 (flag on their own, block in combination).
// - Thresholds: score >= 70 -> block, >= 30 -> flag, otherwise allow.

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF\u00AD\u180E]/g;

// Cyrillic / Greek look-alikes -> Latin
const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'м': 'm', 'т': 't',
  'к': 'k', 'н': 'h', 'в': 'b', 'п': 'n', 'г': 'r', 'д': 'd',
  'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ι': 'i', 'κ': 'k', 'ν': 'v', 'μ': 'u', 'ω': 'w', 'β': 'b', 'γ': 'y',
};

// Common leetspeak -> letters (applied to the detection copy only)
const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's' };

function normalize(raw) {
  let t = String(raw ?? '');
  t = t.normalize('NFKC');
  t = t.replace(ZERO_WIDTH, '');
  t = [...t].map((ch) => HOMOGLYPHS[ch] ?? HOMOGLYPHS[ch.toLowerCase()] ?? ch).join('');
  t = t.toLowerCase();
  t = [...t].map((ch) => LEET[ch] ?? ch).join('');
  // Leet folding collides with a few real tech terms (base64 -> base6a, rot13 -> rotie); restore them.
  t = t.replace(/\bbase6a\b/g, 'base64').replace(/\brotie\b/g, 'rot13');
  t = t.replace(/\s+/g, ' ');
  // Join "s p a c e d" letter runs (3+ single-letter tokens in a row)
  t = t.replace(/(?:\b[a-z]\b[ ]+){2,}\b[a-z]\b/g, (m) => m.replace(/ /g, ''));
  return t.trim();
}

// --- Rule set ---------------------------------------------------------------
// Each rule: id, weight, human-readable label, regex list (tested on normalized text)

const RULES = [
  {
    id: 'instruction_override',
    weight: 70,
    label: 'Instruction override attempt',
    patterns: [
      /\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}\b(previous|prior|above|earlier|preceding|original|system)\b[^.]{0,30}\b(instruction|prompt|rule|directive|command)/,
      /\b(ignore|disregard)\b[^.]{0,20}\b(all|the|your|any)\b[^.]{0,30}\b(instruction|prompt|rule|directive)/,
      /\bforget everything\b[^.]{0,30}\b(told|said|instructed|before)/,
      /\byour new (instruction|directive|rule|task)s?\b[^.]{0,20}\b(are|is|follow)/,
      /(忽略|无视|不要理会|忘掉|忘记)[^.。]{0,12}(之前|以上|前面|先前|所有|全部)[^.。]{0,10}(指令|提示|规则|要求|设定)/,
      /(不要|别)(遵守|理会|管)[^.。]{0,10}(之前|系统|原来)[^.。]{0,8}(指令|提示|规则)/,
    ],
  },
  {
    id: 'system_prompt_theft',
    weight: 70,
    label: 'System prompt / hidden instruction extraction',
    patterns: [
      /\b(reveal|print|show|output|repeat|tell me|give me|leak|disclose|dump)\b[^.]{0,35}\b(system prompt|system instructions|initial instructions|hidden instructions|your instructions)\b/,
      /\bwhat\b[^.]{0,25}\byour (system prompt|initial instructions|system instructions|hidden instructions)\b/,
      /\b(system prompt|initial instructions)\b[^.]{0,15}\bverbatim\b/,
      /(告诉我|说出|输出|打印|泄露|透露|展示|给出)[^.。]{0,14}(系统提示词|系统提示|系统指令|初始指令|隐藏指令)/,
      /你的(系统提示词|系统指令|初始指令|隐藏指令)(是什么|内容|原文)/,
      /(系统提示词|系统提示|初始指令)[^.。]{0,10}(原文|完整)(输出|告诉|发)/,
    ],
  },
  {
    id: 'delimiter_smuggling',
    weight: 70,
    label: 'Forged role / delimiter smuggling',
    patterns: [
      /<\|im_(start|end)\|>/,
      /<\|(system|assistant|user|endoftext)\|>/,
      /\[inst\]|\[\/inst\]|<<\/?sys>>/,
      /#{2,}\s*(system|assistant|developer)\s*:/,
      /(^|\n)\s*\[system\]/,
      /\bsystem override\b/,
      /伪造(的)?(系统|指令)标记/,
    ],
  },
  {
    id: 'data_exfiltration',
    weight: 70,
    label: 'Context / secret exfiltration to external destination',
    patterns: [
      /\b(send|post|upload|forward|transmit|exfiltrate|email|leak)\b[^.]{0,70}\b(system prompt|conversation|chat history|context|api key|hidden instructions|everything above|all of the above)\b[^.]{0,60}\b(to|https?|webhook|server|endpoint|url)\b/,
      /\b(curl|wget)\b[^.]{0,90}\b(api key|system prompt|conversation|chat history|context|instructions)\b/,
      /\bfetch\s*\([^)]{0,80}(api key|system prompt|conversation|context)/,
      /(把|将)[^.。]{0,18}(对话|上下文|聊天记录|系统提示|密钥|api.?key)[^.。]{0,20}(发送|发给|发到|上传|传到|提交到|转发到)/,
      /(发送|上传|转发)[^.。]{0,14}(上下文|对话|系统提示|聊天记录)[^.。]{0,14}(到|给)/,
    ],
  },
  {
    id: 'decode_and_execute',
    weight: 70,
    label: 'Decode-then-execute encoded payload',
    patterns: [
      /\b(decode|decipher|decrypt|deobfuscate)\b[^.]{0,45}\b(execute|run|follow|obey|comply|carry out)\b/,
      /\b(rot13|base64|hex)\b[^.]{0,40}\b(obey|execute|follow|run)\b[^.]{0,20}\b(result|instruction|it|what|text)/,
      /解码[^。]{0,14}(执行|照做|遵循|服从|照着做)/,
      /解码(后|完)[^.。]{0,10}(按|照|执行|做)/,
    ],
  },
  {
    id: 'role_hijack',
    weight: 40,
    label: 'Persona hijack (unrestricted / DAN / jailbreak mode)',
    patterns: [
      /\bdan\b[^.]{0,30}\b(do anything now|no restriction|unrestricted)/,
      /\bdo anything now\b/,
      /\byou are now\b[^.]{0,45}\b(unrestricted|unfiltered|dan\b|no limits|no restrictions|evil|jailbreak)/,
      /\b(act as|pretend to be|roleplay as|simulate)\b[^.]{0,35}\b(unrestricted|unfiltered|dan\b|jailbreak|no rules)/,
      /\bjailbreak(ed|ing)?\b[^.]{0,30}\b(mode|prompt|ai|assistant|you)\b/,
      /\bdeveloper mode\b[^.]{0,45}\b(without|no |unrestricted|bypass|ignore)/,
      /无限制(模式|的|ai|助手)/,
      /不受(任何)?(限制|约束|规则)/,
      /你现在是[^。]{0,24}(无限制|不受|黑客|dan|邪恶)/,
      /越狱(模式|版|ai|助手)/,
      /扮演[^。]{0,14}(无限制|不受限制|黑客|邪恶)/,
    ],
  },
  {
    id: 'safety_disable',
    weight: 35,
    label: 'Safety mechanism disable request',
    patterns: [
      /\b(disable|deactivate|turn off|remove|drop)\b[^.]{0,30}\b(safety|filter|guardrail|restriction|moderation)/,
      /\bsafety (filters|measures|features)\b[^.]{0,15}\b(disabled|off|removed)\b/,
      /\bwithout (any )?(safety )?(limits|restrictions|filters|rules)\b/,
      /\bno (restrictions|limitations|filtering)\b[^.]{0,25}\b(answer|respond|reply|mode|ai|assistant)\b/,
      /关闭[^。]{0,8}(安全|过滤|限制|审查)/,
      /(安全|内容)(过滤|审查)[^.。]{0,8}(关闭|禁用|取消)/,
    ],
  },
  {
    id: 'extraction_probe',
    weight: 35,
    label: 'Verbatim context extraction probe',
    patterns: [
      /\brepeat the words above\b/,
      /\b(output|print|repeat|show)\b[^.]{0,30}\b(everything|all)\b[^.]{0,15}\b(above|before this|preceding)\b/,
      /\b(repeat|output|print)\b[^.]{0,25}\bverbatim\b[^.]{0,25}\b(above|prompt|instruction|message)/,
      /重复[^。]{0,10}(上面|以上|前面)[^.。]{0,10}(原文|内容|话)/,
    ],
  },
  {
    id: 'encoded_payload',
    weight: 30,
    label: 'Encoded payload present (long base64/hex blob or cipher instruction)',
    patterns: [
      /[a-z0-9+/]{40,}={0,2}/,
      /\brot13\b/,
      /\b(decode|decipher)\b[^.]{0,25}\b(base64|hex|string|text|following)\b/,
      /(base64|十六进制|hex)[^.。]{0,10}(解码|编码的(指令|内容))/,
    ],
  },
];

const BLOCK_THRESHOLD = 70;
const FLAG_THRESHOLD = 30;

export function analyze(text) {
  const norm = normalize(text);
  const hits = [];
  let score = 0;
  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      const m = norm.match(pattern);
      if (m) {
        hits.push({ rule: rule.id, detail: `${rule.label}: matched "${m[0].slice(0, 80)}"` });
        score += rule.weight;
        break; // one hit per rule
      }
    }
  }
  score = Math.min(score, 100);
  const verdict = score >= BLOCK_THRESHOLD ? 'block' : score >= FLAG_THRESHOLD ? 'flag' : 'allow';
  return { score, verdict, hits };
}

export default analyze;
