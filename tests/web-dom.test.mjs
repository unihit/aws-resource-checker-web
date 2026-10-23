// DOM behavior tests, not a claim of real-browser layout verification.
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const require=createRequire(process.env.WAR_DOM_PACKAGE || new URL('../package.json',import.meta.url));
const {parseHTML}=require('linkedom');
const page=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const data=JSON.parse(page.match(/window\.CHECKER_DATA = (\{[^\n]+\});/)[1]);

function app() {
  const {window,document}=parseHTML(page);
  // linkedom has no layout, navigation or native clipboard. Supply only these APIs.
  window.scrollTo=()=>{};
  window.location={hash:'#setup'};
  window.history={replaceState:(_a,_b,hash)=>window.location.hash=hash};
  window.navigator.clipboard={writeText:async text=>window.copied=text};
  const select=window.HTMLSelectElement.prototype;
  if(!Object.getOwnPropertyDescriptor(select,'value')?.set)Object.defineProperty(select,'value',{
    get(){return (this.querySelector('option[selected]')||this.querySelector('option'))?.value||'';},
    set(value){for(const option of this.querySelectorAll('option'))option.toggleAttribute('selected',option.value===value);},configurable:true,
  });
  const context=vm.createContext({window,document,navigator:window.navigator,location:window.location,
    history:window.history,setTimeout:()=>0,clearTimeout:()=>{},URL,Blob,console});
  for(const match of page.matchAll(/<script>([\s\S]*?)<\/script>/g))vm.runInContext(match[1],context);
  const $=id=>document.getElementById(id);
  async function upload(value) {
    const input=$('reportFile');
    Object.defineProperty(input,'files',{value:[{name:'test-report.json',size:100,text:async()=>JSON.stringify(value)}],configurable:true});
    input.dispatchEvent(new window.Event('change'));
    await new Promise(resolve=>setImmediate(resolve));
  }
  return {window,document,$,upload};
}

test('sample loads, WAR tab renders six pillars and combined filters work',()=>{
  const {document,$,window}=app();
  $('loadDemoStart').click();
  assert.equal($('reportContent').hidden,false);
  document.querySelector('[data-table="war"]').click();
  assert.equal($('warPanel').hidden,false);
  assert.equal($('warPillars').children.length,6);
  assert.equal($('warCounts').children.length,6);
  $('warPillar').value='COST';$('warStatus').value='FAIL';
  $('warStatus').dispatchEvent(new window.Event('change'));
  const rows=[...$('reportTable').querySelectorAll('tbody tr')];
  assert.ok(rows.length>0);
  assert.ok(rows.every(row=>row.textContent.includes('Cost Optimization')&&row.textContent.includes('FAIL')));
  $('search').value='no-such-resource';$('search').dispatchEvent(new window.Event('input'));
  assert.match($('reportTable').textContent,/검색 결과가 없습니다/);
  document.querySelector('[data-table="resources"]').click();
  assert.equal($('warPanel').hidden,true);
});
test('legacy file keeps inventory usable and WAR explicitly unavailable',async()=>{
  const {document,$,upload}=app();
  const value=JSON.parse(JSON.stringify(data.sample));delete value.war;
  await upload(value);
  assert.equal($('reportError').hidden,true);
  document.querySelector('[data-table="war"]').click();
  assert.match($('warNotice').textContent,/포함되어 있지/);
  assert.equal($('warPillar').disabled,true);
  assert.equal($('warCounts').children.length,0);
  document.querySelector('[data-table="resources"]').click();
  assert.equal($('reportTable').querySelectorAll('tbody tr').length,value.resources.length);
});
test('bad WAR and malicious resource text cannot execute or hide legacy tables',async()=>{
  const {document,$,upload}=app();
  const value=JSON.parse(JSON.stringify(data.sample));
  value.war.findings[0].title='<img src=x onerror=alert(1)>';
  value.resources[0].name='<script>alert(1)</script>';
  await upload(value);
  document.querySelector('[data-table="war"]').click();
  assert.ok($('reportTable').textContent.includes('<img src=x onerror=alert(1)>'));
  assert.equal($('reportTable').querySelectorAll('img,script').length,0);
  value.war={schema_version:99};await upload(value);
  document.querySelector('[data-table="war"]').click();
  assert.match($('warNotice').textContent,/확인할 수 없습니다/);
  assert.equal($('warCounts').children.length,0);
  document.querySelector('[data-table="resources"]').click();
  assert.equal($('reportTable').querySelectorAll('script').length,0);
  assert.ok($('reportTable').textContent.includes('<script>alert(1)</script>'));
});
test('newly opened report resets filters and reloads correct counts',()=>{
  const {document,$,window}=app();$('loadDemoStart').click();
  document.querySelector('[data-table="war"]').click();
  $('warPillar').value='SEC';$('warStatus').value='PASS';
  $('warStatus').dispatchEvent(new window.Event('change'));
  $('clearReport').click();$('loadDemoEmpty').click();
  document.querySelector('[data-table="war"]').click();
  assert.equal($('warPillar').value,'');assert.equal($('warStatus').value,'');
  assert.equal($('reportTable').querySelectorAll('tbody tr').length,data.sample.war.findings.length);
});
test('default run command needs no region input; manual override and reset work',()=>{
  const {document,$,window}=app();
  assert.equal($('regions').value,'');
  assert.ok(!$('command').value.includes('--regions'));
  assert.equal($('copyRun').disabled,false);
  $('regions').value='us-west-2';$('regions').dispatchEvent(new window.Event('input'));
  assert.ok($('command').value.includes("--regions 'us-west-2'"));
  $('regions').value='';$('regions').dispatchEvent(new window.Event('input'));
  assert.ok(!$('command').value.includes('--regions'));
  assert.ok(!document.querySelector('a[href*="cloudshell/home"]').getAttribute('href').includes('?region='));
});

test('WAR is off by default; toggling updates command without changing an opened report',()=>{
  const {document,$,window}=app();
  assert.ok(!$('includeWar').hasAttribute('checked'));
  assert.ok(!$('command').value.includes(' --war'));
  $('includeWar').checked=true;
  $('includeWar').dispatchEvent(new window.Event('change'));
  assert.ok($('command').value.includes("--scope 'core' --war"));
  $('loadDemoStart').click();
  document.querySelector('[data-table="war"]').click();
  const before=$('reportTable').textContent;
  $('includeWar').checked=false;
  $('includeWar').dispatchEvent(new window.Event('change'));
  assert.ok(!$('command').value.includes(' --war'));
  assert.equal($('reportTable').textContent,before);
});

test('WAR excluded snapshot shows exclusion and retains inventory',async()=>{
  const {document,$,upload}=app();
  const value=JSON.parse(JSON.stringify(data.sample));
  value.war_enabled=false; // Even stale embedded results must not be shown.
  await upload(value);
  document.querySelector('[data-table="war"]').click();
  assert.match($('warNotice').textContent,/끄고 실행/);
  assert.equal($('warCounts').children.length,0);
  assert.equal($('warPillar').disabled,true);
  document.querySelector('[data-table="resources"]').click();
  assert.equal($('reportTable').querySelectorAll('tbody tr').length,value.resources.length);
});
