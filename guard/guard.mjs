// See contract.md. Return a Claude PreToolUse decision object.
//
// One question decides every call: after resolving paths, does this tool call
// write to a protected file? The guard is built in four layers:
//   1. shape and fail-safe   (always a valid decision object, deny on doubt)
//   2. canonicalize paths    (relative, dotted, doubled, symlinked)
//   3. classify paths        (is this canonical path protected?)
//   4. extract write targets (per tool; for Bash, a small shell parser)
import fs from 'node:fs';
import path from 'node:path';

// ---------- Step 1: output shape and fail-safe ----------

const MAX_REASON = 2000;

function out(permissionDecision, reason) {
  const text = String(reason || 'no reason given').slice(0, MAX_REASON);
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: text,
    },
  };
}

const allow = reason => out('allow', reason);
const deny = reason => out('deny', reason);

const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);

const FILE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit']);

// Returns a deny decision if the event is malformed, otherwise null.
function validate(event) {
  if (!isPlainObject(event)) return deny('Malformed event: expected an object.');
  const {tool_name, tool_input, cwd} = event;
  if (typeof tool_name !== 'string' || tool_name === '') {
    return deny('Malformed event: tool_name must be a non-empty string.');
  }
  if (!isPlainObject(tool_input)) {
    return deny(`Malformed ${tool_name} event: tool_input must be an object.`);
  }
  if (typeof cwd !== 'string' || !path.isAbsolute(cwd)) {
    return deny(`Malformed ${tool_name} event: cwd must be an absolute path so relative paths can be resolved.`);
  }
  if (FILE_TOOLS.has(tool_name) && (typeof tool_input.file_path !== 'string' || tool_input.file_path === '')) {
    return deny(`Malformed ${tool_name} event: file_path must be a non-empty string.`);
  }
  if (tool_name === 'Bash' && (typeof tool_input.command !== 'string' || tool_input.command.trim() === '')) {
    return deny('Malformed Bash event: command must be a non-empty string.');
  }
  return null;
}

// ---------- Step 2: canonicalize paths (read-only filesystem access) ----------

const MAX_LINK_HOPS = 40;

// Resolve every symlink in `abs`, even when the final file (or a link's
// target) does not exist yet. Only reads the filesystem; never creates anything.
function resolveLinks(abs, hops = 0) {
  if (hops > MAX_LINK_HOPS) throw new Error(`too many symlink hops resolving ${abs}`);

  // Fast path: the whole path exists.
  try { return fs.realpathSync(abs); } catch { /* fall through */ }

  // The path itself may be a *dangling* symlink: writing through it would
  // create its target, so follow it even though realpath failed.
  let st = null;
  try { st = fs.lstatSync(abs); } catch { /* does not exist */ }
  if (st && st.isSymbolicLink()) {
    const target = fs.readlinkSync(abs);
    const base = resolveLinks(path.dirname(abs), hops);
    return resolveLinks(path.resolve(base, target), hops + 1);
  }

  // Otherwise it simply does not exist yet: resolve the parent, keep the name.
  const parent = path.dirname(abs);
  if (parent === abs) return abs; // reached the filesystem root
  return path.join(resolveLinks(parent, hops), path.basename(abs));
}

// Every form of `p` worth checking: the lexical absolute path (`..`, `.` and
// `//` removed) and the symlink-resolved path. Checking both keeps the guard
// correct on machines where /workspace does not exist or is itself a link.
export function canonicalPaths(p, cwd) {
  const lexical = path.resolve(cwd, p);
  const real = resolveLinks(lexical);
  return lexical === real ? [lexical] : [lexical, real];
}

// ---------- Step 3: classify ----------

const PROTECTED_FILES = ['/workspace/intent.md'];
const PROTECTED_DIRS = ['/workspace/tests/instructor'];
const PROTECTED_ALL = [...PROTECTED_FILES, ...PROTECTED_DIRS];

const isInside = (abs, dir) => abs === dir || abs.startsWith(dir + '/');

// Why `abs` is protected, or null. Three cases:
//   - it IS a protected file
//   - it is inside a protected directory
//   - it CONTAINS a protected target (e.g. `rm -rf /workspace/tests`), only
//     checked when `contains` is true: for destructive operations, not for
//     e.g. `git add .`, which names /workspace but changes nothing in it.
// Matching is on whole path components, so `src/intent.md` and
// `tests/instructor-old` are not protected.
export function protectionReason(abs, contains = true) {
  for (const f of PROTECTED_FILES) {
    if (abs === f) return `${f} is the approved intent`;
  }
  for (const d of PROTECTED_DIRS) {
    if (isInside(abs, d)) return `${abs} is inside the instructor tests (${d}/)`;
  }
  if (contains) {
    for (const t of PROTECTED_ALL) {
      if (isInside(t, abs)) return `${abs} contains the protected path ${t}`;
    }
  }
  return null;
}

// First protected hit among all canonical forms of `p`, or null.
export function protectedHit(p, cwd, contains = true) {
  for (const abs of canonicalPaths(p, cwd)) {
    const why = protectionReason(abs, contains);
    if (why) {
      const via = abs === path.resolve(cwd, p) ? '' : ` (${p} resolves to ${abs})`;
      return `${why}${via}`;
    }
  }
  return null;
}

// Tools that only read, search or talk to the user: nothing to protect.
const READ_ONLY_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'LS', 'WebFetch', 'WebSearch', 'TodoWrite', 'TodoRead',
]);

function decideFileTool(tool, filePath, cwd) {
  const hit = protectedHit(filePath, cwd);
  if (hit) return deny(`${tool} blocked: ${hit}. Protected files can only change with instructor approval.`);
  return allow(`${tool} on ${path.resolve(cwd, filePath)} does not touch a protected file.`);
}

// ---------- Step 4: Bash ----------
//
// Not a full shell: a lexer that understands quoting, expansions, operators,
// redirections and heredocs well enough to find every place a command can
// write. Anything it cannot resolve (variables, unknown cwd, parse errors)
// is denied when it sits in a write position.

const MAX_COMMAND = 100_000;
const MAX_DEPTH = 6;
const MAX_SCRIPT_BYTES = 1_000_000;
const MAX_CWDS = 16;
const HOLE = '\u0000'; // placeholder for an expansion inside a word

class ParseError extends Error {}

// --- lexer: command string -> tokens ---
// word:  {type:'word', text, quoted, dyn, glob, brace, subs:[inner commands]}
// op:    {type:'op', op}            ; && || | |& & ( ) ;; and newline as ;
// redir: {type:'redir', op, fd, body?}
function lex(src) {
  const tokens = [];
  const pendingHeredocs = [];
  let i = 0;
  let word = null;
  let heredocRedir = null; // a << waiting for its delimiter word

  const startWord = () => {
    if (!word) word = {type: 'word', text: '', quoted: false, dyn: false, glob: false, brace: false, subs: []};
  };
  const endWord = () => {
    if (!word) return;
    tokens.push(word);
    if (heredocRedir) {
      pendingHeredocs.push({redir: heredocRedir, delim: word.text});
      heredocRedir.quotedDelim = word.quoted;
      heredocRedir = null;
    }
    word = null;
  };

  // Index just past the matching `close`, skipping quotes. `from` is just past `open`.
  function capture(open, close, from) {
    let depth = 1;
    let j = from;
    while (j < src.length) {
      const c = src[j];
      if (c === '\\') { j += 2; continue; }
      if (c === "'") {
        const k = src.indexOf("'", j + 1);
        if (k < 0) throw new ParseError('unterminated single quote');
        j = k + 1;
        continue;
      }
      if (c === '"') {
        j++;
        while (j < src.length && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
        if (j >= src.length) throw new ParseError('unterminated double quote');
        j++;
        continue;
      }
      if (c === open) depth++;
      else if (c === close && --depth === 0) return [src.slice(from, j), j + 1];
      j++;
    }
    throw new ParseError(`unbalanced ${open}${close}`);
  }

  // At `$` or a backtick. Consumes an expansion and returns true, or false for a lone `$`.
  function readExpansion() {
    const c = src[i];
    if (c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== '`') j += src[j] === '\\' ? 2 : 1;
      if (j >= src.length) throw new ParseError('unterminated backtick');
      word.subs.push(src.slice(i + 1, j));
      word.text += HOLE; word.dyn = true; i = j + 1;
      return true;
    }
    const n = src[i + 1];
    if (n === '(') {
      const [inner, end] = capture('(', ')', i + 2);
      word.subs.push(inner);
      word.text += HOLE; word.dyn = true; i = end;
      return true;
    }
    if (n === '{') {
      const [inner, end] = capture('{', '}', i + 2);
      // ${x:-$(cmd)} can hide a command substitution: check it too.
      if (/\$\(|`/.test(inner)) word.subs.push(`: "${inner.replace(/^[^$`]*/, '')}"`);
      word.text += HOLE; word.dyn = true; i = end;
      return true;
    }
    if (n !== undefined && /[A-Za-z0-9_@*#?$!-]/.test(n)) {
      let j = i + 2;
      if (/[A-Za-z_]/.test(n)) while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      word.text += HOLE; word.dyn = true; i = j;
      return true;
    }
    return false;
  }

  function readDoubleQuoted() { // i is just past the opening "
    while (i < src.length) {
      const c = src[i];
      if (c === '"') { i++; return; }
      if (c === '\\' && i + 1 < src.length) {
        const n = src[i + 1];
        if ('$`"\\\n'.includes(n)) { if (n !== '\n') word.text += n; i += 2; continue; }
        word.text += c; i++;
        continue;
      }
      if ((c === '$' || c === '`') && readExpansion()) continue;
      word.text += c; i++;
    }
    throw new ParseError('unterminated double quote');
  }

  function readHeredocBodies() { // i is at the start of the line after the << line
    while (pendingHeredocs.length) {
      const h = pendingHeredocs.shift();
      const strip = h.redir.op === '<<-';
      let body = '';
      while (i < src.length) {
        let nl = src.indexOf('\n', i);
        if (nl < 0) nl = src.length;
        const line = src.slice(i, nl);
        i = Math.min(nl + 1, src.length);
        if ((strip ? line.replace(/^\t+/, '') : line) === h.delim) break;
        body += line + '\n';
      }
      h.redir.body = body;
    }
  }

  const REDIRS = ['&>>', '<<<', '<<-', '&>', '>>', '>|', '>&', '<<', '<&', '<>', '>', '<'];
  const OPS = ['&&', '||', ';;', '|&', ';', '|', '&', '(', ')'];

  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r') { endWord(); i++; continue; }
    if (c === '\n') { endWord(); tokens.push({type: 'op', op: ';'}); i++; readHeredocBodies(); continue; }
    if (c === '#' && !word) { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue; }
      startWord();
      if (i + 1 < src.length) word.text += src[i + 1];
      word.quoted = true; i += 2;
      continue;
    }
    if (c === "'") {
      startWord();
      const k = src.indexOf("'", i + 1);
      if (k < 0) throw new ParseError('unterminated single quote');
      word.text += src.slice(i + 1, k); word.quoted = true; i = k + 1;
      continue;
    }
    if (c === '$' && src[i + 1] === "'") { // ANSI-C $'...': escapes could spell anything
      startWord();
      let j = i + 2;
      let s = '';
      while (j < src.length && src[j] !== "'") { if (src[j] === '\\') { s += src[j] + (src[j + 1] ?? ''); j += 2; } else s += src[j++]; }
      if (j >= src.length) throw new ParseError("unterminated $'...'");
      word.text += s; word.quoted = true; if (s.includes('\\')) word.dyn = true; i = j + 1;
      continue;
    }
    if (c === '"') { startWord(); word.quoted = true; i++; readDoubleQuoted(); continue; }
    if (c === '$' || c === '`') {
      startWord();
      if (readExpansion()) continue;
      word.text += c; i++;
      continue;
    }
    if ((c === '<' || c === '>') && src[i + 1] === '(' && !word) { // process substitution
      startWord();
      const [inner, end] = capture('(', ')', i + 2);
      word.subs.push(inner); word.text += HOLE; word.dyn = true; i = end;
      continue;
    }
    const rop = REDIRS.find(op => src.startsWith(op, i));
    if (rop) {
      let fd = null;
      if (word && /^\d+$/.test(word.text) && !word.quoted && !word.dyn) { fd = word.text; word = null; } else endWord();
      const tok = {type: 'redir', op: rop, fd};
      tokens.push(tok);
      i += rop.length;
      if (rop === '<<' || rop === '<<-') heredocRedir = tok;
      continue;
    }
    const op = OPS.find(o => src.startsWith(o, i));
    if (op) { endWord(); tokens.push({type: 'op', op}); i += op.length; continue; }
    startWord();
    if ('*?['.includes(c)) word.glob = true;
    if (c === '{') word.brace = true;
    if (c === '~' && word.text === '') word.dyn = true; // ~ / ~user: home directory unknown
    word.text += c; i++;
  }
  endWord();
  readHeredocBodies();
  return tokens;
}

// --- parser: tokens -> [{kind:'pipeline', cmds, sep} | {kind:'open'} | {kind:'close'}] ---
function parse(tokens) {
  const items = [];
  const newCmd = () => ({words: [], redirs: []});
  let cmd = newCmd();
  let pipe = [];
  const flushCmd = () => { if (cmd.words.length || cmd.redirs.length) pipe.push(cmd); cmd = newCmd(); };
  const flushPipe = sep => { flushCmd(); if (pipe.length) items.push({kind: 'pipeline', cmds: pipe, sep}); pipe = []; };
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.type === 'word') { cmd.words.push(t); continue; }
    if (t.type === 'redir') {
      const target = tokens[k + 1];
      if (!target || target.type !== 'word') throw new ParseError(`redirection ${t.op} has no target`);
      k++;
      cmd.redirs.push({...t, target});
      continue;
    }
    if (t.op === '|' || t.op === '|&') { flushCmd(); continue; }
    if (t.op === '(') { flushPipe(';'); items.push({kind: 'open'}); continue; }
    if (t.op === ')') { flushPipe(';'); items.push({kind: 'close'}); continue; }
    flushPipe(t.op);
  }
  flushPipe(';');
  return items;
}

// --- word helpers ---

const show = w => w.text.replaceAll(HOLE, '$…');

// Bash brace expansion for unquoted {a,b} and {1..3}; innermost first.
function expandBraces(s, budget = {n: 64}) {
  const m = /\{([^{}]*)\}/.exec(s);
  if (!m) return [s];
  let alts = null;
  if (m[1].includes(',')) alts = m[1].split(',');
  else {
    const r = /^(-?\d+)\.\.(-?\d+)$/.exec(m[1]);
    if (r) {
      const [a, b] = [Number(r[1]), Number(r[2])];
      alts = [];
      for (let x = a; a <= b ? x <= b : x >= b; x += a <= b ? 1 : -1) { alts.push(String(x)); if (alts.length > budget.n) break; }
    }
  }
  if (!alts) return [s];
  const outs = [];
  for (const a of alts) {
    for (const e of expandBraces(s.slice(0, m.index) + a + s.slice(m.index + m[0].length), budget)) {
      outs.push(e);
      if (--budget.n < 0) throw new ParseError('brace expansion too large to check');
    }
  }
  return outs;
}

function globCompRegex(comp) {
  let re = '';
  for (let k = 0; k < comp.length; k++) {
    const c = comp[k];
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[') {
      const end = comp.indexOf(']', k + 2);
      if (end < 0) { re += '\\['; continue; }
      let cls = comp.slice(k + 1, end);
      if (cls.startsWith('!')) cls = '^' + cls.slice(1);
      re += '[' + cls.replace(/\\/g, '\\\\') + ']';
      k = end;
    } else re += c.replace(/[.+^${}()|\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

const comps = p => p.split('/').filter(Boolean);
const matchComps = (pat, names) => pat.length === names.length && pat.every((g, k) => globCompRegex(g).test(names[k]));

// Could the glob `pattern` expand to something protected?
function globHit(pattern, cwd, contains) {
  const parts = comps(path.resolve(cwd, pattern));
  const g = parts.findIndex(c => /[*?[]/.test(c));
  if (g < 0) return protectedHit(pattern, cwd, contains);
  const literal = '/' + parts.slice(0, g).join('/');
  let real = literal;
  try { real = resolveLinks(literal); } catch { /* keep literal */ }
  for (const base of new Set([literal, real])) {
    for (const d of PROTECTED_DIRS) if (isInside(base, d)) return `${pattern} expands inside ${d}/`;
    const pat = [...comps(base), ...parts.slice(g)];
    const candidates = new Set(PROTECTED_ALL);
    if (contains) for (const t of PROTECTED_ALL) for (let p = path.dirname(t); p !== '/'; p = path.dirname(p)) candidates.add(p);
    for (const c of candidates) if (matchComps(pat, comps(c))) return `${pattern} can expand to ${c}`;
    for (const d of PROTECTED_DIRS) {
      const dc = comps(d);
      if (pat.length > dc.length && matchComps(pat.slice(0, dc.length), dc)) return `${pattern} can expand to files inside ${d}/`;
    }
  }
  return null;
}

// Is word `w` (a path argument) protected, under every possible cwd?
// write: the word is a write target, so anything unresolvable is denied.
function checkWord(w, state, {write = false, contains = false} = {}) {
  if (w.text === '') return null;
  if (w.dyn) return write ? `"${show(w)}" uses shell expansion, so the guard cannot tell what it writes` : null;
  let texts = [w.text];
  if (w.brace) texts = expandBraces(w.text);
  for (const text of texts) {
    if (!path.isAbsolute(text) && state.unknownCwd) {
      if (write) return `"${text}" is relative but the working directory is unknown after cd`;
      continue;
    }
    for (const cwd of state.cwds) {
      const why = w.glob ? globHit(text, cwd, contains) : protectedHit(text, cwd, contains);
      if (why) return why;
    }
  }
  return null;
}

const plainWord = text => ({type: 'word', text, quoted: true, dyn: false, glob: false, brace: false, subs: []});

// Path-like fragments inside an argument or a script: `--out=x`, `'x'`, `w x`.
function fragments(text) {
  const parts = new Set([text]);
  const eq = text.indexOf('=');
  if (eq >= 0) parts.add(text.slice(eq + 1));
  for (const p of text.split(/[\s'"`(),;:=+[\]{}<>|&]+/)) if (p) parts.add(p);
  return [...parts].filter(p => p && !p.includes(HOLE));
}

// Any fragment of `text` that resolves to a protected path (no `contains`:
// a script that says '.' is not therefore rewriting the workspace).
function scanText(text, state) {
  for (const f of fragments(text)) {
    const why = checkWord(plainWord(f), state);
    if (why) return why;
  }
  return null;
}

// --- command classification ---

const WRAPPERS = new Set([
  'sudo', 'doas', 'env', 'command', 'builtin', 'exec', 'nohup', 'nice', 'time', 'timeout', 'stdbuf', 'ionice',
  'then', 'do', 'else', 'elif', 'if', 'while', 'until', '!', '{', '}', 'fi', 'done', 'esac',
]);
const WRAPPER_ARG_OPTS = {sudo: ['-u', '-g', '-C'], doas: ['-u'], env: ['-u', '-C', '-S'], nice: ['-n'], ionice: ['-c', '-n'], timeout: ['-s', '-k']};

function splitCommand(words) {
  let k = 0;
  while (k < words.length) {
    const t = words[k].text;
    if (!words[k].quoted && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { k++; continue; } // VAR=value
    if (!WRAPPERS.has(t)) break;
    k++;
    const argOpts = WRAPPER_ARG_OPTS[t] || [];
    while (k < words.length && words[k].text.startsWith('-') && words[k].text !== '-') {
      k += argOpts.includes(words[k].text) ? 2 : 1;
    }
    if (t === 'env') while (k < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k].text)) k++;
    if (t === 'timeout' && k < words.length) k++; // the duration
  }
  const nameWord = words[k];
  return {nameWord, name: nameWord ? path.basename(nameWord.text) : '', args: words.slice(k + 1)};
}

const READ_ONLY_CMDS = new Set([
  'cat', 'tac', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'ls', 'dir', 'wc',
  'diff', 'cmp', 'comm', 'stat', 'file', 'sha1sum', 'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum', 'md5sum',
  'md5', 'shasum', 'cksum', 'b2sum', 'echo', 'printf', 'pwd', 'true', 'false', 'test', '[', '[[', 'realpath',
  'readlink', 'basename', 'dirname', 'which', 'whereis', 'type', 'whoami', 'id', 'date', 'uname', 'hostname',
  'jq', 'cut', 'tr', 'nl', 'od', 'xxd', 'hexdump', 'strings', 'tree', 'du', 'df', 'column', 'fold', 'fmt',
  'expand', 'unexpand', 'paste', 'join', 'look', 'sort', 'uniq', 'seq', 'sleep', 'exit', 'return', ':', 'for',
  'case', 'select', 'export', 'unset', 'local', 'declare', 'readonly', 'set', 'shift', 'alias', 'unalias',
  'history', 'man', 'help', 'env', 'printenv', 'ps', 'locale', 'wait', 'jobs', '',
]);
// Read-only commands that can still write through an option.
function readOnlyWrites(name, args) {
  const t = args.map(a => a.text);
  if (name === 'sort') return t.some(x => /^(-o|--output)/.test(x));
  if (name === 'tree') return t.some(x => /^-o/.test(x));
  if (name === 'uniq') return t.filter(x => !x.startsWith('-')).length > 1; // uniq IN OUT
  return false;
}

const DESTRUCTIVE = new Set(['rm', 'rmdir', 'unlink', 'shred', 'chmod', 'chown', 'chgrp', 'chattr', 'chflags', 'setfacl']);
const WRITERS = new Set(['touch', 'truncate', 'tee', 'ln', 'link', 'mkdir', 'mkfifo', 'mknod', 'sponge', 'patch', 'split', 'csplit']);
const COPIERS = new Set(['cp', 'mv', 'install', 'rsync', 'scp', 'ditto']);
const SHELLS = /^(sh|bash|zsh|dash|ksh|mksh|fish|busybox)$/;
const INTERPRETERS = /^(python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|perl[0-9.]*|ruby|php[0-9.]*|lua[0-9.]*|Rscript|osascript|awk|gawk|mawk|nawk|tclsh|jshell)$/;
const CODE_FLAGS = new Set(['-c', '-e', '-E', '-r', '-p', '--eval', '--print', '--command']);
const INTERP_ARG_OPTS = new Set(['-m', '-W', '-X', '--require', '--import', '--loader', '-I', '-M', '-f', '-v', '-F']);

const GIT_READ = new Set(['status', 'log', 'diff', 'show', 'blame', 'grep', 'ls-files', 'ls-tree', 'rev-parse', 'describe',
  'shortlog', 'cat-file', 'branch', 'remote', 'config', 'fetch', 'tag', 'reflog', 'help', 'version', 'show-ref',
  'for-each-ref', 'count-objects', 'add', 'commit', 'push', 'init']);
const GIT_WORKTREE = new Set(['checkout', 'switch', 'restore', 'reset', 'clean', 'stash', 'rm', 'mv', 'apply', 'am',
  'merge', 'pull', 'rebase', 'cherry-pick', 'revert']);

const nonOptions = args => args.filter(a => !(a.text.startsWith('-') && a.text !== '-'));

function readScript(w, state) {
  if (w.dyn) return {unknown: true};
  for (const cwd of state.cwds) {
    try {
      const p = path.resolve(cwd, w.text);
      const st = fs.statSync(p);
      if (st.isFile() && st.size <= MAX_SCRIPT_BYTES) return {text: fs.readFileSync(p, 'utf8')};
      if (st.isFile()) return {unknown: true};
    } catch { /* try the next cwd */ }
  }
  return null; // no such script
}

// Returns a deny reason for one simple command, or null.
function checkCommand(cmd, pipeline, state, depth) {
  const {nameWord, name, args} = splitCommand(cmd.words);
  const allArgs = (opts) => {
    for (const a of args) {
      if (!opts.write && a.text.startsWith('-') && !a.text.includes('=')) continue;
      const why = opts.write ? checkWord(a.text.startsWith('-') ? plainWord(a.text.replace(/^[^=]*=/, '')) : a, state, opts) : (a.dyn ? null : scanArg(a));
      if (why) return why;
    }
    return null;
  };
  const scanArg = a => {
    if (a.glob || a.brace) return checkWord(a, state);
    for (const f of fragments(a.text)) { const why = checkWord(plainWord(f), state); if (why) return why; }
    return null;
  };
  const stdinText = () => [
    ...cmd.redirs.filter(r => r.op === '<<<').map(r => r.target.text),
    ...cmd.redirs.filter(r => r.op === '<<' || r.op === '<<-').map(r => r.body || ''),
  ];

  if (!nameWord) return null;
  if (nameWord.dyn) { // `$EDITOR intent.md`: unknown program
    const why = allArgs({});
    return why && `unknown command "${show(nameWord)}" names a protected path: ${why}`;
  }

  if (name === 'cd' || name === 'pushd' || name === 'popd') return null; // handled by the caller

  if (name === 'find') {
    const acts = args.some(a => /^-(delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/.test(a.text));
    if (!acts) return null;
    const why = allArgs({write: false});
    if (why) return `find with an action names a protected path: ${why}`;
    for (const a of nonOptions(args)) {
      const w = checkWord(a, state, {contains: true});
      if (w) return `find with an action reaches a protected path: ${w}`;
    }
    return null;
  }

  if (name === 'git') return checkGit(args, state);

  if (READ_ONLY_CMDS.has(name) && !readOnlyWrites(name, args)) return null;

  if (DESTRUCTIVE.has(name)) {
    for (const a of nonOptions(args)) {
      const why = checkWord(a, state, {write: true, contains: true});
      if (why) return `${name} ${show(a)}: ${why}`;
    }
    return null;
  }

  if (WRITERS.has(name)) {
    for (const a of nonOptions(args)) {
      const why = checkWord(a, state, {write: true});
      if (why) return `${name} writes ${show(a)}: ${why}`;
    }
    return null;
  }

  if (name === 'dd') {
    for (const a of args) {
      if (!a.text.startsWith('of=')) continue;
      const why = checkWord({...a, text: a.text.slice(3)}, state, {write: true});
      if (why) return `dd ${show(a)}: ${why}`;
    }
    return null;
  }

  if (name === 'sed' && args.some(a => /^(-[a-zA-Z]*i|--in-place)/.test(a.text))) {
    for (const a of nonOptions(args)) {
      const why = checkWord(a, state, {write: true});
      if (why) return `sed -i ${show(a)}: ${why}`;
    }
    return null;
  }

  if (COPIERS.has(name)) return checkCopy(name, args, state);

  if (name === 'xargs') {
    // Arguments come from stdin: check every word in the pipeline.
    let k = 0;
    while (k < args.length && args[k].text.startsWith('-')) k += /^-[IdEnLPs]$/.test(args[k].text) ? 2 : 1;
    const inner = args[k] ? path.basename(args[k].text) : 'echo';
    const destructive = DESTRUCTIVE.has(inner) || COPIERS.has(inner) || WRITERS.has(inner) || !READ_ONLY_CMDS.has(inner);
    if (READ_ONLY_CMDS.has(inner)) return null;
    for (const c of pipeline.cmds) {
      for (const w of c.words) {
        const why = destructive ? (checkWord(w, state, {contains: DESTRUCTIVE.has(inner) || COPIERS.has(inner)}) || (w.dyn ? null : scanArg(w))) : null;
        if (why) return `xargs ${inner} could receive a protected path: ${why}`;
      }
    }
    return null;
  }

  if (SHELLS.test(name) || name === 'eval' || name === 'source' || name === '.') return checkShellLike(name, args, cmd, pipeline, state, depth, stdinText);

  if (INTERPRETERS.test(name)) return checkInterpreter(name, args, cmd, pipeline, state, depth, stdinText);

  // Unknown command: it may write any file it names.
  const why = allArgs({});
  return why && `${name} is not known to be read-only and names a protected path: ${why}`;
}

function checkCopy(name, args, state) {
  const files = [];
  let target = null;
  let recursive = false;
  for (let k = 0; k < args.length; k++) {
    const t = args[k].text;
    if (t === '--') { files.push(...args.slice(k + 1)); break; }
    if (t === '-t' || t === '--target-directory') { target = args[++k]; continue; }
    if (t.startsWith('--target-directory=')) { target = {...args[k], text: t.slice(19)}; continue; }
    if (t.startsWith('-') && t !== '-') {
      if (/^-[a-zA-Z]*[rRa]/.test(t) || t === '--recursive' || t === '--archive' || t === '--delete') recursive = true;
      continue;
    }
    files.push(args[k]);
  }
  if (!target) target = files.pop();
  if (!target) return null;
  // mv also removes its sources (and everything inside them).
  if (name === 'mv') {
    for (const s of files) {
      const why = checkWord(s, state, {write: true, contains: true});
      if (why) return `mv moves ${show(s)} away: ${why}`;
    }
  }
  const destWhy = checkWord(target, state, {write: true, contains: recursive || name === 'mv'});
  if (destWhy) return `${name} writes to ${show(target)}: ${destWhy}`;
  // When the destination is a directory, each source lands at dest/basename(source).
  for (const s of files) {
    if (s.dyn || target.dyn) continue;
    const landed = {...target, text: target.text.replace(/\/+$/, '') + '/' + path.basename(s.text)};
    const why = checkWord(landed, state, {write: true});
    if (why) return `${name} would place ${show(s)} at ${landed.text}: ${why}`;
  }
  return null;
}

function checkGit(args, state) {
  let k = 0;
  let gitState = state;
  while (k < args.length && args[k].text.startsWith('-')) {
    const t = args[k].text;
    if (t === '-C' && args[k + 1]) {
      const d = args[k + 1];
      if (d.dyn) return 'git -C with a shell expansion: the guard cannot tell which repository it changes';
      gitState = {...state, cwds: state.cwds.map(c => path.resolve(c, d.text))};
      k += 2;
      continue;
    }
    k += ['-c', '--git-dir', '--work-tree', '--namespace'].includes(t) ? 2 : 1;
  }
  const sub = args[k] ? args[k].text : '';
  const rest = args.slice(k + 1);
  const restText = rest.map(a => a.text);
  if (GIT_READ.has(sub) && !restText.some(t => t.startsWith('--output'))) {
    // Reading, staging or committing never rewrites the working tree.
    return null;
  }
  const worktree = GIT_WORKTREE.has(sub) &&
    !(sub === 'reset' && !restText.some(t => /^--(hard|merge|keep)$/.test(t))) &&
    !(sub === 'stash' && /^(list|show)$/.test(restText[0] || '')) &&
    !((sub === 'checkout' || sub === 'switch') && restText.some(t => /^-[bBcC]$/.test(t)));
  if (!worktree) {
    for (const a of rest) {
      if (a.dyn || a.text.startsWith('-')) continue;
      const why = checkWord(a, gitState);
      if (why) return `git ${sub} names a protected path: ${why}`;
    }
    return null;
  }
  const dd = restText.indexOf('--');
  const paths = dd >= 0 ? rest.slice(dd + 1) : nonOptions(rest);
  const pathsOnly = dd >= 0 || ['restore', 'rm', 'mv', 'clean'].includes(sub);
  if (pathsOnly && paths.length) {
    for (const a of paths) {
      const why = checkWord(a, gitState, {write: true, contains: true});
      if (why) return `git ${sub} ${show(a)}: ${why}`;
    }
    return null;
  }
  // Rewrites the working tree as a whole (switch branch, merge, reset --hard, ...).
  for (const cwd of gitState.cwds) {
    const why = protectedHit('.', cwd, true);
    if (why) return `git ${sub} can rewrite every tracked file under ${cwd}, and ${why}`;
  }
  if (gitState.unknownCwd) return `git ${sub} runs in an unknown directory after cd`;
  return null;
}

function checkShellLike(name, args, cmd, pipeline, state, depth, stdinText) {
  const recurse = (code, what) => {
    const why = bashDenyReason(code, state, depth + 1);
    return why && `${what}: ${why}`;
  };
  if (name === 'eval') {
    if (args.some(a => a.dyn)) return 'eval of a shell expansion: the guard cannot tell what it runs';
    return recurse(args.map(a => a.text).join(' '), 'eval');
  }
  const ci = args.findIndex(a => a.text === '-c' || /^-[a-z]*c$/.test(a.text));
  if (ci >= 0 && name !== 'source' && name !== '.') {
    const code = args[ci + 1];
    if (!code) return `${name} -c without a command`;
    if (code.dyn) return `${name} -c "${show(code)}": the command uses shell expansion, so the guard cannot tell what it runs`;
    return recurse(code.text, `${name} -c`);
  }
  const script = nonOptions(args)[0];
  if (script && script.text !== '-') {
    const s = readScript(script, state);
    if (s && s.unknown) return `${name} ${show(script)}: the script cannot be read, so the guard cannot tell what it writes`;
    if (s) {
      const why = recurse(s.text, `script ${show(script)}`);
      if (why) return why;
    }
  } else {
    // Commands arrive on stdin: a heredoc, here-string, or the rest of the pipeline.
    for (const body of stdinText()) { const why = recurse(body, `${name} reading a heredoc`); if (why) return why; }
    for (const c of pipeline.cmds) {
      if (c === cmd) continue;
      for (const w of c.words) { if (w.dyn) continue; const why = scanText(w.text, state); if (why) return `${name} reads commands from a pipe that mentions a protected path: ${why}`; }
    }
  }
  return null;
}

function checkInterpreter(name, args, cmd, pipeline, state, depth, stdinText) {
  let sawCode = false;
  let script = null;
  for (let k = 0; k < args.length; k++) {
    const t = args[k].text;
    if (CODE_FLAGS.has(t) || (/^awk|^gawk|^mawk|^nawk/.test(name) && !script && !sawCode && !t.startsWith('-'))) {
      const code = CODE_FLAGS.has(t) ? args[++k] : args[k];
      if (!code) return `${name} ${t} without code`;
      sawCode = true;
      if (code.dyn) {
        const why = scanText(code.text, state);
        if (why) return `${name} code mentions a protected path: ${why}`;
        continue;
      }
      const why = scanText(code.text, state);
      if (why) return `${name} code mentions a protected path: ${why}`;
      continue;
    }
    if (INTERP_ARG_OPTS.has(t)) {
      if (t === '-f' && args[k + 1]) script = args[k + 1]; // awk -f progfile
      k++;
      continue;
    }
    if (t.startsWith('-')) continue;
    if (!sawCode && !script) { script = args[k]; continue; }
    // Remaining arguments: data files the program may write.
    const why = args[k].dyn ? null : checkWord(args[k], state) || scanText(args[k].text, state);
    if (why) return `${name} is given a protected path: ${why}`;
  }
  if (script && script.text !== '-') {
    const s = readScript(script, state);
    if (s && s.unknown) return `${name} ${show(script)}: the script cannot be read, so the guard cannot tell what it writes`;
    if (s) {
      const why = scanText(s.text, state);
      if (why) return `script ${show(script)} mentions a protected path: ${why}`;
    }
  }
  if (!sawCode && (!script || script.text === '-')) {
    // Program text arrives on stdin.
    for (const body of stdinText()) { const why = scanText(body, state); if (why) return `${name} program from stdin mentions a protected path: ${why}`; }
    for (const c of pipeline.cmds) {
      if (c === cmd) continue;
      for (const w of c.words) { if (w.dyn) continue; const why = scanText(w.text, state); if (why) return `${name} reads a program from a pipe that mentions a protected path: ${why}`; }
    }
  }
  for (const body of stdinText()) { const why = scanText(body, state); if (why) return `${name} input mentions a protected path: ${why}`; }
  return null;
}

const OUTPUT_REDIRS = new Set(['>', '>>', '>|', '&>', '&>>', '<>', '>&']);

function checkPipeline(pl, state, depth) {
  for (const cmd of pl.cmds) {
    // Command and process substitutions run first, wherever they appear.
    for (const w of [...cmd.words, ...cmd.redirs.map(r => r.target)]) {
      for (const s of w.subs) {
        const why = bashDenyReason(s, state, depth + 1);
        if (why) return `inside $(…): ${why}`;
      }
    }
    for (const r of cmd.redirs) {
      if (r.op === '<<' || r.op === '<<-') {
        if (!r.quotedDelim && r.body) { // unquoted heredocs expand $(…) in their body
          let subs = [];
          try { subs = lex('"' + r.body.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"')[0]?.subs || []; } catch { /* conservative below */ }
          for (const s of subs) { const why = bashDenyReason(s, state, depth + 1); if (why) return `inside a heredoc $(…): ${why}`; }
        }
        continue;
      }
      if (!OUTPUT_REDIRS.has(r.op)) continue;
      if (r.op === '>&' && /^(\d+|-)$/.test(r.target.text)) continue; // 2>&1: duplicates a descriptor
      const why = checkWord(r.target, state, {write: true});
      if (why) return `redirect ${r.fd || ''}${r.op} ${show(r.target)}: ${why}`;
    }
    const why = checkCommand(cmd, pl, state, depth);
    if (why) return why;
  }
  return null;
}

function applyCd(pl, state) {
  if (pl.cmds.length !== 1) return;
  const {name, args} = splitCommand(pl.cmds[0].words);
  if (name === 'popd') { state.unknownCwd = true; return; }
  if (name !== 'cd' && name !== 'pushd') return;
  const dir = nonOptions(args)[0];
  if (!dir || dir.dyn || dir.text === '-') { state.unknownCwd = true; return; }
  const next = state.cwds.map(c => path.resolve(c, dir.text));
  // After `cd x &&` the shell is in x if it exists. Otherwise (`;`, `||`, or a
  // directory that may not exist) it could still be in the old directory.
  const sure = pl.sep === '&&' && next.every(d => { try { return fs.statSync(d).isDirectory(); } catch { return false; } });
  state.cwds = [...new Set(sure ? next : [...state.cwds, ...next])];
  if (state.cwds.length > MAX_CWDS) state.unknownCwd = true;
}

// A deny reason for a whole shell command, or null if it is safe.
function bashDenyReason(src, outer, depth) {
  if (depth > MAX_DEPTH) return 'commands are nested too deeply to check';
  if (src.length > MAX_COMMAND) return 'the command is too long to check';
  let items;
  try {
    items = parse(lex(src));
  } catch (e) {
    if (e instanceof ParseError) return `the command could not be parsed safely (${e.message})`;
    throw e;
  }
  let state = {cwds: [...outer.cwds], unknownCwd: outer.unknownCwd};
  const stack = [];
  for (const it of items) {
    if (it.kind === 'open') { stack.push({cwds: [...state.cwds], unknownCwd: state.unknownCwd}); continue; }
    if (it.kind === 'close') { if (stack.length) state = stack.pop(); continue; }
    const why = checkPipeline(it, state, depth);
    if (why) return why;
    applyCd(it, state);
  }
  return null;
}

function decideBash(command, cwd) {
  const why = bashDenyReason(command, {cwds: [cwd], unknownCwd: false}, 0);
  if (why) return deny(`Bash blocked: ${why}. Protected files can only change with instructor approval.`);
  return allow('Bash command checked: no write reaches a protected file.');
}

// ---------- decision ----------

export function decide(event) {
  try {
    const invalid = validate(event);
    if (invalid) return invalid;
    const {tool_name: tool, tool_input: input, cwd} = event;

    if (FILE_TOOLS.has(tool)) return decideFileTool(tool, input.file_path, cwd);

    if (tool === 'NotebookEdit') {
      if (typeof input.notebook_path !== 'string' || input.notebook_path === '') {
        return deny('Malformed NotebookEdit event: notebook_path must be a non-empty string.');
      }
      return decideFileTool(tool, input.notebook_path, cwd);
    }

    if (READ_ONLY_TOOLS.has(tool)) return allow(`${tool} is read-only.`);

    if (tool === 'Bash') return decideBash(input.command, cwd);

    // Unknown tools might write anywhere: fail closed, but say why.
    return deny(`Unrecognised tool "${tool}": the guard cannot tell what it writes, so it is denied.`);
  } catch (err) {
    // A crashing guard must fail closed, never open.
    return deny(`Guard error, denying to be safe: ${err && err.message ? err.message : String(err)}`);
  }
}
