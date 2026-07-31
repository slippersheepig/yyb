package httpapi

const fallbackIndexHTML = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YYB Go 控制台</title>
<body style="margin:0;background:oklch(0.974 0.004 250);color:oklch(0.19 0.025 252);font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif">
<main style="max-width:960px;margin:48px auto;padding:0 24px">
<section style="background:oklch(1 0 0);border:1px solid oklch(0.885 0.012 250);border-radius:8px;padding:24px">
<h1 style="margin:0 0 8px;font-size:24px">YYB Go 控制台</h1>
<p style="margin:0 0 20px;color:oklch(0.43 0.025 252)">资源模板未找到，服务仍可通过以下入口使用。</p>
<p style="display:flex;gap:10px;flex-wrap:wrap;margin:0">
<a style="padding:10px 12px;border-radius:8px;background:oklch(0.54 0.205 3);color:oklch(1 0 0);text-decoration:none" href="/scan">扫码添加</a>
<a style="padding:10px 12px;border-radius:8px;border:1px solid oklch(0.885 0.012 250);color:inherit;text-decoration:none" href="/docs/index.html">Swagger 文档</a>
<a style="padding:10px 12px;border-radius:8px;border:1px solid oklch(0.885 0.012 250);color:inherit;text-decoration:none" href="/openapi.json">OpenAPI JSON</a>
</p>
</section>
</main>
</body></html>`

const fallbackScanHTML = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>扫码添加账号</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:oklch(0.974 0.004 250);color:oklch(0.19 0.025 252);font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif">
<main style="width:min(420px,calc(100vw - 32px));background:oklch(1 0 0);border:1px solid oklch(0.885 0.012 250);border-radius:8px;padding:24px;text-align:center">
<h1 style="margin:0 0 8px;font-size:22px">扫码添加账号</h1>
<p id="s" style="margin:0 0 18px;color:oklch(0.43 0.025 252)">正在生成二维码</p>
<div id="qr" style="width:240px;height:240px;margin:0 auto 18px;display:grid;place-items:center;border:1px solid oklch(0.885 0.012 250);border-radius:8px;background:oklch(0.986 0.004 250)">请稍候</div>
<p style="display:flex;gap:10px;justify-content:center;margin:0">
<button onclick="newQR()" style="border:0;border-radius:8px;padding:10px 12px;background:oklch(0.54 0.205 3);color:oklch(1 0 0)">重新生成</button>
<a href="/" style="border:1px solid oklch(0.885 0.012 250);border-radius:8px;padding:9px 12px;color:inherit;text-decoration:none">返回首页</a>
</p>
</main>
<script>
let sid,timer;
async function api(url,options){
 const resp=await fetch(url,options);
 const text=await resp.text();
 let data=null;
 try{data=text?JSON.parse(text):null}catch(e){data=text}
 const isEnvelope=data&&typeof data==='object'&&!Array.isArray(data)&&Object.prototype.hasOwnProperty.call(data,'code')&&Object.prototype.hasOwnProperty.call(data,'msg')&&Object.prototype.hasOwnProperty.call(data,'data');
 if(!resp.ok||(isEnvelope&&data.code!==0)){throw new Error(isEnvelope?data.msg:'HTTP '+resp.status)}
 return isEnvelope?data.data:data;
}
async function newQR(){
 clearInterval(timer);
 document.getElementById('qr').textContent='请稍候';
 document.getElementById('s').textContent='正在生成二维码';
 const r=await api('/qr',{method:'POST'});
 sid=r.session_id;
 document.getElementById('qr').innerHTML='<img alt="二维码" style="width:240px;height:240px" src="'+r.image_url+'">';
 document.getElementById('s').textContent='等待扫码';
 timer=setInterval(poll,1500);
}
async function poll(){
 const r=await api('/qr/'+sid+'/poll');
 document.getElementById('s').textContent=r.status;
 if(r.status==='authorized'){
  clearInterval(timer);
  const a=await api('/qr/'+sid+'/confirm',{method:'POST'});
  document.getElementById('s').textContent='添加成功: '+(a.nickname||a.openid);
 }
 if(['expired','cancelled','unknown'].includes(r.status)){clearInterval(timer)}
}
newQR();
</script></body></html>`

var openAPISpec = newOpenAPISpec()

var fallbackLoginHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f5f7fa;height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui}.box{background:#fff;width:360px;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:32px}h2{font-size:20px;margin-bottom:20px;text-align:center}.field{margin-bottom:16px}label{display:block;font-size:13px;color:#606266;margin-bottom:6px}input{width:100%;padding:10px 12px;border:1px solid #dcdfe6;border-radius:6px;font-size:14px;outline:none}input:focus{border-color:#409eff}.btn{width:100%;padding:11px;border:none;border-radius:6px;background:#409eff;color:#fff;font-size:15px;cursor:pointer}.btn:hover{background:#66b1ff}.err{color:#f56c6c;font-size:13px;margin-top:8px;min-height:20px}</style>
</head><body><div class="box"><h2>YYB 管理登录</h2><form id="f"><div class="field"><label>用户名</label><input id="u" autocomplete="off"></div><div class="field"><label>密码</label><input id="p" type="password" autocomplete="off"></div><div class="err" id="e"></div><button class="btn" type="submit">登录</button></form></div>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const u=document.getElementById('u').value,p=document.getElementById('p').value,el=document.getElementById('e');el.textContent='';try{const resp=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)});const d=await resp.json();if(d.code===0){location.href=d.data.redirect||'/admin'}else{el.textContent=d.msg||'登录失败'}}catch(err){el.textContent='网络错误'}});</script>
</body></html>`

var fallbackMyHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>我的账号</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f5f7fa;font-family:system-ui;min-height:100vh;display:flex;align-items:center;justify-content:center}.box{background:#fff;width:420px;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:28px}h2{font-size:18px;margin-bottom:18px}.info{background:#f0f9eb;border:1px solid #c2e7b0;border-radius:8px;padding:14px;margin-bottom:14px}.row{display:flex;justify-content:space-between;padding:4px 0;font-size:14px}.row span:first-child{color:#909399}.row span:last-child{font-weight:600}.status-ok{color:#67c23a}.status-bad{color:#f56c6c}.logout{display:inline-block;margin-top:12px;color:#909399;text-decoration:none;font-size:13px}.logout:hover{color:#409eff}</style>
</head><body><div class="box"><h2>我的账号状态</h2><div id="content">加载中...</div><a class="logout" href="/logout">退出</a></div>
<script>fetch('/api/my/status').then(r=>r.json()).then(d=>{if(d.code!==0){location.href='/scan';return}const c=document.getElementById('content');if(d.data.is_admin){location.href='/admin';return}const a=d.data.account,n=a.nickname||'(未命名)',s=a.status||'未知';c.innerHTML='<div class="info"><div class="row"><span>昵称</span><span>'+n+'</span></div><div class="row"><span>UIN</span><span>'+(a.uin||'-')+'</span></div><div class="row"><span>状态</span><span class="'+(s==='alive'?'status-ok':'status-bad')+'">'+(s==='alive'?'✅ 可用':'⚠️ '+s)+'</span></div><div class="row"><span>OpenID</span><span style="font-size:12px;word-break:break-all">'+a.openid+'</span></div></div>';}).catch(()=>{location.href='/scan'});</script>
</body></html>`
