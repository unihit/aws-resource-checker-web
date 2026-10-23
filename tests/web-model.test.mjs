import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import {createHash} from 'node:crypto';

const page=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const scripts=[...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const context=vm.createContext({module:{exports:{}}});
for(const script of scripts)new vm.Script(script);
vm.runInContext(scripts.find(s=>s.includes('const SUBJECT =')),context);
const M=context.module.exports;
const data=JSON.parse(page.match(/window\.CHECKER_DATA = (\{[^\n]+\});/)[1]);
const clone=v=>JSON.parse(JSON.stringify(v));

test('WAR command flag is opt-in with strict boolean input',()=>{
  assert.ok(!M.cloudShellCommand('','core',data.collector).includes(' --war'));
  assert.ok(!M.cloudShellCommand('','core',data.collector,false).includes(' --war'));
  assert.ok(M.cloudShellCommand('','core',data.collector,true).includes("--scope 'core' --war"));
  assert.throws(()=>M.cloudShellCommand('','core',data.collector,'false'));
});

test('legacy JSON keeps existing tables and explicitly lacks WAR',()=>{
  const r=clone(data.sample);delete r.war;
  assert.equal(M.parseReport(r),r);
  assert.equal(M.warView(r).available,false);
  assert.match(M.warView(r).message,/포함되어 있지/);
  assert.equal(M.reportRows(r,'war').length,0);
  assert.equal(M.reportRows(r,'resources').length,r.resources.length);
});
test('new snapshot has six pillars, manual work and recomputed counts',()=>{
  const r=clone(data.sample);r.war.counts={PASS:999999};
  const view=M.warView(r);
  assert.equal(view.available,true);
  assert.equal(Object.keys(view.pillars).length,6);
  assert.equal(view.counts.MANUAL,6);
  assert.notEqual(view.counts.PASS,999999);
  assert.equal(Object.values(view.counts).reduce((a,b)=>a+b,0),r.war.findings.length);
});
test('pillar, status and text filters compose without changing source',()=>{
  const r=clone(data.sample),before=JSON.stringify(r);
  const rows=M.reportRows(r,'war','EBS','COST','FAIL');
  assert.ok(rows.length>0);
  assert.ok(rows.every(f=>f.pillar==='COST'&&f.status==='FAIL'&&f.service==='EBS'));
  assert.equal(JSON.stringify(r),before);
});
test('malformed WAR never blocks legacy inventory or looks like a pass',()=>{
  for(const change of [war=>war.schema_version=2,war=>war.findings=[{}],war=>war.findings=null,war=>war.findings[0].status='HEALTHY',war=>war.findings[0].pillar='__proto__',war=>war.findings[0].status='EXCEPTION']) {
    const r=clone(data.sample);change(r.war);
    assert.equal(M.parseReport(r),r);
    const view=M.warView(r);
    assert.equal(view.available,false);assert.equal(view.findings.length,0);
    assert.match(view.message,/WAR/);
    assert.equal(M.reportRows(r,'resources').length,r.resources.length);
  }
});
test('manifest verifies exactly the shipped collector files',()=>{
  for(const name of ['checker.py','cloudshell.py','war.py']) {
    const bytes=readFileSync(new URL('../collector/'+name,import.meta.url));
    assert.equal(createHash('sha256').update(bytes).digest('hex'),data.collector[name]);
  }
  const extra={...data.collector,'../../bad.py':'a'.repeat(64)};
  const command=M.cloudShellCommand('ap-northeast-2','core',extra);
  assert.ok(command.includes('war.py'));
  assert.ok(!command.includes('../../bad.py'));
  assert.throws(()=>M.cloudShellCommand('ap-northeast-2','core',{'checker.py':'a'.repeat(64),'cloudshell.py':'b'.repeat(64)}));
});
test('existing input validation and console authentication flow stay intact',()=>{
  assert.throws(()=>M.cloudShellCommand('ap-northeast-2; touch bad','core',data.collector));
  assert.throws(()=>M.cloudShellCommand('all us-east-1','core',data.collector));
  const command=M.cloudShellCommand('all','full',data.collector);
  assert.ok(command.includes('--regions \'all\' --scope \'full\''));
  assert.ok(!command.includes('AWS_ACCESS_KEY_ID='));
});
test('empty or auto region leaves detection to CloudShell at execution time',()=>{
  for(const input of ['', '  ', 'auto']){
    const command=M.cloudShellCommand(input,'core',data.collector);
    assert.ok(!command.includes('--regions'));
    assert.ok(command.includes('--scope \'core\''));
    assert.ok(!command.includes('ap-northeast-2'));
  }
  assert.throws(()=>M.cloudShellCommand('auto us-east-1','core',data.collector));
  assert.match(page,/cloudshell\/home"/);
  assert.ok(!page.includes('cloudshell/home?region=ap-northeast-2'));
  assert.ok(!page.includes('서울 리전과 기본 범위로 시작'));
});
test('page retains CSP and local-file behavior; WAR uses safe text nodes',()=>{
  assert.match(page,/connect-src 'none'/);
  assert.match(page,/data-table="war"/);
  assert.match(page,/id="warPillar"/);assert.match(page,/id="warStatus"/);
  assert.ok(!page.includes('localStorage')&&!page.includes('sessionStorage'));
  assert.ok(!page.includes('.innerHTML'));
  assert.ok(page.includes('title.textContent=label'));
});
