// Student regression tests for guard/guard.mjs.
// Every test asserts at least one deny, so an allow-all guard fails all of them.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {decide} from '../../../guard/guard.mjs';

const W = '/workspace';
const HAS_FIXTURE_LINK = (() => {
  try { return fs.lstatSync('/workspace/src/shortcut').isSymbolicLink(); } catch { return false; }
})();

// Checks the graded shape on every call, then returns the decision.
function run(event) {
  const result = decide(event);
  assert.ok(!(result instanceof Promise), 'decide must be synchronous');
  assert.deepEqual(Object.keys(result), ['hookSpecificOutput']);
  const out = result.hookSpecificOutput;
  assert.deepEqual(Object.keys(out).sort(), ['hookEventName', 'permissionDecision', 'permissionDecisionReason']);
  assert.equal(out.hookEventName, 'PreToolUse');
  assert.ok(['allow', 'deny'].includes(out.permissionDecision));
  assert.equal(typeof out.permissionDecisionReason, 'string');
  assert.ok(out.permissionDecisionReason.length > 0 && out.permissionDecisionReason.length <= 2000);
  return out;
}

const file = (tool, file_path, cwd = W) => run({tool_name: tool, tool_input: {file_path, content: 'x', old_string: 'a', new_string: 'b'}, cwd});
const bash = (command, cwd = W) => run({tool_name: 'Bash', tool_input: {command}, cwd});

function denies(out, label) {
  assert.equal(out.permissionDecision, 'deny', `expected deny: ${label} (${out.permissionDecisionReason})`);
}
function allows(out, label) {
  assert.equal(out.permissionDecision, 'allow', `expected allow: ${label} (${out.permissionDecisionReason})`);
}

test('malformed events are denied with a reason, not thrown', () => {
  for (const event of [
    null,
    undefined,
    {},
    [],
    'Write intent.md',
    {tool_name: 'Edit', tool_input: {}, cwd: W},
    {tool_name: 'Write', tool_input: {file_path: 42}, cwd: W},
    {tool_name: 'Bash', tool_input: {}, cwd: W},
    {tool_name: 'Bash', tool_input: {command: ['rm', 'intent.md']}, cwd: W},
    {tool_name: 'Write', tool_input: null, cwd: W},
    {tool_name: 'Write', tool_input: {file_path: 'intent.md'}, cwd: 'relative/dir'},
  ]) {
    denies(run(event), JSON.stringify(event) ?? String(event));
  }
});

test('direct writes to protected files are denied for every file tool', () => {
  for (const tool of ['Edit', 'Write', 'MultiEdit']) {
    denies(file(tool, '/workspace/intent.md'), `${tool} intent.md`);
    denies(file(tool, '/workspace/tests/instructor/check.mjs'), `${tool} instructor test`);
    denies(file(tool, '/workspace/tests/instructor/new-file.mjs'), `${tool} new file in instructor tests`);
  }
  denies(run({tool_name: 'NotebookEdit', tool_input: {notebook_path: 'intent.md'}, cwd: W}), 'NotebookEdit');
});

test('ordinary source edits and look-alike names are allowed, protected files are not', () => {
  allows(file('Edit', '/workspace/src/app.mjs'), 'edit src/app.mjs');
  allows(file('Write', '/workspace/src/new/module.mjs'), 'new nested source file');
  allows(file('Write', '/workspace/src/intent.md'), 'look-alike src/intent.md');
  allows(file('Write', '/workspace/tests/instructor-old/check.mjs'), 'look-alike directory');
  allows(file('Write', '/workspace/tests/student/guard/extra.test.mjs'), 'student tests');
  allows(file('Write', '/workspace/intent.md.bak'), 'look-alike suffix');
  denies(file('Write', '/workspace/intent.md'), 'the real intent next to its look-alikes');
});

test('relative, dotted and doubled paths resolve to the protected target', () => {
  denies(file('Write', 'intent.md'), 'relative to cwd');
  denies(file('Write', './intent.md'), 'dot prefix');
  denies(file('Edit', '/workspace/src/../intent.md'), 'traversal');
  denies(file('Edit', '../intent.md', '/workspace/src'), 'relative traversal from src');
  denies(file('Edit', '../../intent.md', '/workspace/src/lib'), 'deeper traversal');
  denies(file('Write', '/workspace//intent.md'), 'doubled slash');
  denies(file('Write', '/workspace/./tests//instructor/../instructor/check.mjs'), 'mixed dots and slashes');
  denies(file('Write', 'instructor/check.mjs', '/workspace/tests'), 'relative into instructor tests');
  allows(file('Edit', '/workspace/src/../src/app.mjs'), 'traversal that stays in src');
});

test('a symlink to a protected file is treated as that file', {skip: !HAS_FIXTURE_LINK && 'needs /workspace/src/shortcut'}, () => {
  denies(file('Write', '/workspace/src/shortcut'), 'Write through symlink');
  denies(file('Edit', 'shortcut', '/workspace/src'), 'relative Edit through symlink');
  denies(bash('printf x > src/shortcut'), 'redirect through symlink');
  denies(bash('cp src/app.mjs src/shortcut'), 'cp onto symlink');
  denies(bash('echo x | tee -a src/shortcut'), 'tee through symlink');
  allows(bash('cat src/shortcut'), 'reading through the symlink');
});

test('rename into or out of a protected file is denied', () => {
  denies(bash('mv src/app.mjs intent.md'), 'mv into intent');
  denies(bash('mv intent.md src/intent-old.md'), 'mv out of intent');
  denies(bash('mv /workspace/tests/instructor/check.mjs /tmp/'), 'mv instructor test away');
  denies(bash('mv src/evil.mjs tests/instructor/check.mjs'), 'mv over instructor test');
  denies(bash('mv tests tests-old'), 'mv a directory containing instructor tests');
  denies(bash('mv src/intent.md /workspace/'), 'mv into the directory, landing on intent.md');
  allows(bash('mv src/a.mjs src/b.mjs'), 'ordinary rename in src');
});

test('shell redirection to a protected file is denied', () => {
  denies(bash('printf changed > intent.md'), '>');
  denies(bash('echo more >> intent.md'), '>>');
  denies(bash('echo x>intent.md'), 'no spaces');
  denies(bash('node build.mjs 2> /workspace/intent.md'), '2>');
  denies(bash('node build.mjs &> intent.md'), '&>');
  denies(bash('echo x >| ./src/../intent.md'), '>| with traversal');
  denies(bash('echo x > tests/instructor/check.mjs'), 'redirect into instructor tests');
  denies(bash('cat > intent.md <<EOF\nnew\nEOF'), 'heredoc into intent');
  allows(bash('cat intent.md > src/copy.md'), 'redirect from protected into src');
  allows(bash('echo x > src/intent.md'), 'redirect into look-alike');
  allows(bash('npm test 2>&1'), 'descriptor duplication');
});

test('cp, tee and python writes to a protected file are denied', () => {
  denies(bash('cp src/app.mjs intent.md'), 'cp onto intent');
  denies(bash('cp -f src/x.mjs /workspace/tests/instructor/check.mjs'), 'cp onto instructor test');
  denies(bash('cp src/intent.md /workspace/'), 'cp into directory lands on intent.md');
  denies(bash('echo x | tee intent.md'), 'tee');
  denies(bash('echo x | tee -a intent.md'), 'tee -a');
  denies(bash('echo x | tee src/log.txt tests/instructor/check.mjs'), 'tee with several files');
  denies(bash(`python3 -c "open('intent.md','w').write('x')"`), 'python3 -c');
  denies(bash(`python3 -c 'import pathlib; pathlib.Path("/workspace/intent.md").write_text("x")'`), 'python3 pathlib');
  denies(bash('python3 - <<EOF\nopen("intent.md", "a").write("x")\nEOF'), 'python3 heredoc');
  allows(bash('cp intent.md src/backup.md'), 'copying FROM a protected file');
  allows(bash('echo x | tee src/log.txt'), 'tee into src');
  allows(bash('python3 -c "print(1)"'), 'harmless python');
});

test('other mutating commands on protected files are denied', () => {
  for (const command of [
    'rm intent.md',
    'rm -rf tests',
    'rm -f tests/instructor/*.mjs',
    'rm -rf *',
    'truncate -s 0 intent.md',
    'touch tests/instructor/new.mjs',
    'sed -i s/a/b/ intent.md',
    'ln -sf src/app.mjs intent.md',
    'dd if=/dev/zero of=intent.md',
    'chmod 000 intent.md',
    'find . -name intent.md -delete',
    'echo intent.md | xargs rm',
    'git checkout -- intent.md',
    'git reset --hard',
  ]) denies(bash(command), command);
  allows(bash('rm -rf src/tmp'), 'rm inside src');
  allows(bash('sed -i s/a/b/ src/app.mjs'), 'sed -i on source');
});

test('quoting, cd, nesting and expansions do not hide a protected write', () => {
  for (const command of [
    `echo x > 'intent.md'`,
    'echo x > "int""ent.md"',
    'echo x > {intent,notes}.md',
    'cd tests && rm instructor/check.mjs',
    'cd tests/instructor; echo x > check.mjs',
    '(cd src); echo x > intent.md',
    'cd src || echo x > intent.md',
    'sh -c "printf x > intent.md"',
    `bash -c 'echo x | tee intent.md'`,
    'eval "echo x > intent.md"',
    'echo $(echo x > intent.md)',
    'sudo tee intent.md',
    'env A=1 cp src/a intent.md',
    'echo x > "$TARGET"',
    'echo "unterminated > intent.md',
  ]) denies(bash(command), command);
  allows(bash('cd src && echo x > app.mjs'), 'cd into src then write');
  allows(bash('echo "x > intent.md"'), 'redirect text inside quotes is just text');
  allows(bash('ls # > intent.md'), 'redirect inside a comment');
});

test('read-only commands are allowed, writes in the same session are not', () => {
  for (const command of [
    'cat intent.md',
    'head -5 /workspace/intent.md',
    'grep -n approved intent.md tests/instructor/check.mjs',
    'wc -l intent.md',
    'diff intent.md src/intent.md',
    'ls -la tests/instructor',
    'cat intent.md | grep a | sort | uniq',
    'git status',
    'git diff intent.md',
    'node --test "tests/student/guard/**/*.test.mjs"',
  ]) allows(bash(command), command);
  allows(run({tool_name: 'Read', tool_input: {file_path: '/workspace/intent.md'}, cwd: W}), 'Read tool');
  denies(bash('cat intent.md > intent.md'), 'a read that redirects back onto intent');
});

test('deciding never changes the fixture files', {skip: !fs.existsSync('/workspace/intent.md') && 'needs /workspace'}, () => {
  const snapshot = () => ['/workspace/intent.md', '/workspace/tests/instructor/check.mjs', '/workspace/src/app.mjs']
    .map(p => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null));
  const before = snapshot();
  denies(file('Write', '/workspace/intent.md'), 'write intent');
  denies(bash('printf x > intent.md; rm -rf tests'), 'shell write');
  allows(file('Edit', '/workspace/src/app.mjs'), 'source edit');
  assert.deepEqual(snapshot(), before);
});
