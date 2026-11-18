#!/usr/bin/env python3
"""Private Unix-socket fixture acceptance; prints no secrets or row contents."""
import argparse, base64, hashlib, html, http.client, json, os, pathlib, pty, re, select, signal, socket, subprocess, tempfile, time, urllib.parse, fcntl, termios
def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 path.write_text(json.dumps(value,indent=2)+"\n");path.chmod(0o600)
def read(path):
 with open(path) as stream:return json.load(stream)
def prepare_auth(binary,path):
 master,slave=pty.openpty()
 def session():os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
 proc=subprocess.Popen([binary,"prepare-auth","--output",str(path),"--username","owner"],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session);os.close(slave)
 output=b"";sent=0;deadline=time.monotonic()+10
 try:
  while proc.poll() is None and time.monotonic()<deadline:
   ready,_,_=select.select([master],[],[],0.1)
   if ready:
    try:output+=os.read(master,4096)
    except OSError:break
   if sent==0 and b"characters): " in output and not termios.tcgetattr(master)[3]&termios.ECHO:os.write(master,b"fixture-owner-password\n");sent=1
   if sent==1 and b"Confirm login password: " in output and not termios.tcgetattr(master)[3]&termios.ECHO:os.write(master,b"fixture-owner-password\n");sent=2
  proc.wait(timeout=2)
  assert proc.returncode==0 and sent==2,"credential preparation failed"
  assert b"fixture-owner-password" not in output,"terminal echo was enabled"
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
  os.close(master)
def request(base,path,method="GET",body=None,headers=None):
 conn=http.client.HTTPConnection(base,timeout=10);h=dict(headers or {})
 conn.request(method,path,body=body,headers=h);r=conn.getresponse();data=r.read();status=r.status;rh={k.lower():v for k,v in r.getheaders()};conn.close()
 return status,rh,data
def form(base,path,values,cookie=None):
 return request(base,path,"POST",urllib.parse.urlencode(values),{"Content-Type":"application/x-www-form-urlencoded",**({"Cookie":cookie} if cookie else {})})
def hidden(body,name):
 return html.unescape(re.search(r'name="'+name+r'" value="([^"]*)"',body.decode()).group(1))
def acquire(base,auth,scopes,prefix="/agent",selected_scopes=None):
 verifier=base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
 challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
 resource="https://mcp.example.invalid"+prefix+"/mcp"
 params={"response_type":"code","client_id":auth["client_id"],"redirect_uri":"http://127.0.0.1:9876/callback","resource":resource,"scope":scopes,"state":"opaque <&>","code_challenge_method":"S256","code_challenge":challenge}
 status,h,body=request(base,prefix+"/oauth/authorize?"+urllib.parse.urlencode(params));assert status==200,"authorize failed"
 cookie=h["set-cookie"].split(";")[0];rid=hidden(body,"request_id")
 status,h,body=form(base,prefix+"/oauth/login",{"request_id":rid,"csrf":hidden(body,"csrf"),"username":"owner","password":"fixture-owner-password"},cookie);assert status==200,"login failed"
 choices={}
 for tag in re.findall(r'<input[^>]*type="checkbox"[^>]*>',body.decode()):
  name=re.search(r'name="scope_([^"]+)"',tag)
  assert name,"scope checkbox has no name"
  choices[html.unescape(name[1])]=bool(re.search(r'\schecked(?:[\s=>]|$)',tag))
 consent={"request_id":rid,"csrf":hidden(body,"csrf"),"decision":"approve"}
 if choices:
  assert {scope for scope,checked in choices.items() if checked}==set(scopes.split()),"consent defaults differ from URL scopes"
  selected=(selected_scopes if selected_scopes is not None else scopes).split()
  assert set(selected)<=choices.keys(),"selected scope absent from consent"
  consent.update({"scope_"+scope:"on" for scope in selected})
 else:
  assert selected_scopes is None,"server does not offer selectable scopes"
 status,h,body=form(base,prefix+"/oauth/consent",consent,cookie);assert status==303,"consent failed"
 callback=urllib.parse.parse_qs(urllib.parse.urlsplit(h["location"]).query);assert callback["state"]==["opaque <&>"] and callback["iss"]==["https://mcp.example.invalid/agent"]
 status,h,body=form(base,prefix+"/oauth/token",{"grant_type":"authorization_code","client_id":auth["client_id"],"client_secret":auth["client_secret"],"resource":resource,"code":callback["code"][0],"redirect_uri":params["redirect_uri"],"code_verifier":verifier});assert status==200,"code exchange failed"
 token=json.loads(body)
 assert token["scope"]==" ".join(sorted(set((selected_scopes if selected_scopes is not None else scopes).split()))),"token scopes differ from approval"
 return token
def rpc(base,token,method,params=None):
 body={"jsonrpc":"2.0","id":1,"method":method}
 if params is not None:body["params"]=params
 status,h,data=request(base,"/agent/mcp","POST",json.dumps(body),{"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-11-25","Authorization":"Bearer "+token})
 assert status==200,"MCP request failed"
 value=json.loads(data);assert "error" not in value,"MCP protocol error";return value["result"]
def call(base,token,name,args=None):
 result=rpc(base,token,"tools/call",{"name":name,"arguments":args or {}})
 assert not result.get("isError"),"tool failed"
 structured=result["structuredContent"];assert json.loads(result["content"][0]["text"])==structured,"representations differ"
 return structured
def start(binary,config,base):
 proc=subprocess.Popen([binary,"serve","--config",str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 for _ in range(100):
  if proc.poll() is not None:raise AssertionError("server startup failed: "+proc.stderr.read().decode().strip())
  try:
   if request(base,"/agent/health")[0]==200:return proc
  except (OSError,http.client.HTTPException):pass
  time.sleep(0.05)
 proc.terminate();proc.wait(timeout=10);raise AssertionError("server did not become ready")
def stop(proc):
 proc.send_signal(signal.SIGTERM);out,err=proc.communicate(timeout=10);assert proc.returncode==0,"graceful shutdown failed"
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--binary",required=True);parser.add_argument("--previous-binary",help="Optional earlier implementation to issue tokens before the replacement starts");parser.add_argument("--tapo-app",required=True);parser.add_argument("--socket",default="/build/tmp/mariadb-mcp-fixture/test.sock");args=parser.parse_args()
 assert pathlib.Path(os.path.realpath(args.socket)).is_relative_to("/build/tmp"),"only /build/tmp fixture sockets are accepted"
 project=pathlib.Path(__file__).resolve().parents[1]
 with tempfile.TemporaryDirectory(prefix="mcp-acceptance-") as tmp:
  root=pathlib.Path(tmp);root.chmod(0o700)
  for folder in ("apps.d","connections","credentials"): (root/folder).mkdir(mode=0o700)
  app=read(args.tapo_app);app["database_user"]="mcp_tapo_fixture";write(root/"apps.d/tapo.json",app)
  write(root/"connections/tapo.json",{"socket":args.socket,"database":"mcp_tapo_fixture","credentials_file":"../credentials/tapo.json"})
  write(root/"credentials/tapo.json",{"username":"mcp_tapo_fixture","password":"fixture-only-password"})
  inventory=read(project/"examples/apps.d/inventory.example.json")
  write(root/"connections/inventory.json",{"socket":args.socket,"database":"inventory","credentials_file":"../credentials/inventory.json"})
  write(root/"credentials/inventory.json",{"username":"mcp_inventory","password":"fixture-only-password"})
  authpath=root/"oauth.json";prepare_auth(args.binary,authpath);auth=read(authpath)
  with socket.socket() as reservation:reservation.bind(("127.0.0.1",0));port=reservation.getsockname()[1]
  base=f"127.0.0.1:{port}";config=root/"mcp.json"
  write(config,{"version":1,"listen":base,"public_base_url":"https://mcp.example.invalid/agent","apps_directory":"apps.d","oauth_credentials_file":"oauth.json","state_directory":"state///","redirect_uris":["http://127.0.0.1:9876/callback"]})
  subprocess.run([args.binary,"init-state","--config",str(config)],check=True,stdout=subprocess.DEVNULL)
  subprocess.run([args.binary,"check","--config",str(config)],check=True,stdout=subprocess.DEVNULL)
  proc=start(args.previous_binary or args.binary,config,base)
  try:
   tokens=acquire(base,auth,"tapo:read");access=tokens["access_token"]
   init=rpc(base,access,"initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"private-acceptance","version":"1"}});assert init["protocolVersion"]=="2025-11-25"
   assert len(rpc(base,access,"tools/list")["tools"])==4
   listing=call(base,access,"tapo__list_sensors");assert listing["row_count"]==6
   current=call(base,access,"tapo__get_current_conditions",{"sensor_id":"f"});assert current["rows"][0]["measurement_id"]=="21"
   absent=call(base,access,"tapo__get_current_conditions",{"sensor_id":"c"})["rows"][0];assert not absent["reading_present"] and absent["temperature_c"] is None
   future=call(base,access,"tapo__get_current_conditions",{"sensor_id":"d"})["rows"][0];assert future["clock_anomaly"] and future["collection_freshness"]=="clock_anomaly"
   stale=call(base,access,"tapo__get_current_conditions",{"sensor_id":"e"})["rows"][0];assert stale["collection_freshness"]=="stale"
   recent=call(base,access,"tapo__get_current_conditions",{"sensor_id":"a"})["rows"][0];assert recent["observed_at"] is None and not recent["observation_freshness_known"]
   assert call(base,access,"tapo__get_collection_health",{"sensor_id":"a"})["rows"][0]["health"]=="healthy"
   assert call(base,access,"tapo__get_collection_health",{"sensor_id":"c"})["rows"][0]["health"]=="unknown"
   history_args={"sensor_id":"a","start":"2026-10-12T00:00:00Z","end":"2026-10-12T01:00:00Z","limit":2}
   history=call(base,access,"tapo__get_sensor_history",history_args);assert history["truncated"] and history["row_count"]==2 and history["rows"][0]["resolution_seconds"]==900
   history_args["end"]="2026-10-12T00:30:00Z";halfopen=call(base,access,"tapo__get_sensor_history",history_args);assert not halfopen["truncated"] and halfopen["row_count"]==2
   history_args["sensor_id"]="b";missing=call(base,access,"tapo__get_sensor_history",history_args)["rows"][0];assert not missing["reading_present"] and missing["data_status"]=="no_readings_in_range"
   unknown=rpc(base,access,"tools/call",{"name":"tapo__get_current_conditions","arguments":{"sensor_id":"unknown"}});assert unknown["isError"] and unknown["structuredContent"]["error"]["code"]=="not_found"
  finally:stop(proc)
  snapshot=(root/"state/oauth-state.json").read_text();assert tokens["access_token"] not in snapshot and tokens["refresh_token"] not in snapshot
  settings=read(config)
  settings["oauth"]={"provider":"builtin","credentials_file":settings.pop("oauth_credentials_file"),"state_directory":settings.pop("state_directory"),"redirect_uris":settings.pop("redirect_uris")}
  write(config,settings)
  write(root/"apps.d/inventory.json",inventory)
  subprocess.run([args.binary,"check","--config",str(config)],check=True,stdout=subprocess.DEVNULL)
  proc=start(args.binary,config,base)
  try:
   assert len(rpc(base,access,"tools/list")["tools"])==4,"old grants expanded on restart"
   status,h,_=request(base,"/agent/mcp","POST",json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"}),{"Content-Type":"application/json"})
   assert status==401,"missing token was not refused"
   challenge=h.get("www-authenticate","")
   hinted=re.search(r'(?:^|, )scope="([^"]+)"',challenge)
   assert hinted and hinted[1]=="inventory:read tapo:read","new app missing from read scope challenge"
   read_token=acquire(base,auth,"tapo:read",selected_scopes=hinted[1])["access_token"]
   assert len(rpc(base,read_token,"tools/list")["tools"])==5,"challenge-guided grant cannot discover both read apps"
   assert call(base,read_token,"inventory__get_item",{"id":"7"})["row_count"]==1
   status,h,_=request(base,"/agent/mcp","POST",json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inventory__set_item_label","arguments":{}}}),{"Content-Type":"application/json","Authorization":"Bearer "+read_token})
   assert status==403 and 'scope="inventory:write"' in h.get("www-authenticate","") and 'error="insufficient_scope"' in h["www-authenticate"],"write denial lacks exact scope guidance"
   new=acquire(base,auth,"tapo:read",selected_scopes="tapo:read inventory:read inventory:write")["access_token"]
   assert len(rpc(base,new,"tools/list")["tools"])==6,"new app not discovered"
   item=call(base,new,"inventory__get_item",{"id":"7"})["rows"][0]
   result=call(base,new,"inventory__set_item_label",{"id":"7","label":"Private acceptance","expected_version":item["version"]});assert result["commit"]=="committed" and result["affected_rows"]==1
   status,_,_=request(base,"/agent/mcp","POST",json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inventory__get_item","arguments":{"id":"7"}}}),{"Content-Type":"application/json","Authorization":"Bearer "+access});assert status==403
   status,_,_=form(base,"/agent/oauth/token",{"grant_type":"refresh_token","client_id":auth["client_id"],"client_secret":auth["client_secret"],"resource":"https://mcp.example.invalid/agent/mcp","refresh_token":tokens["refresh_token"]});assert status==200,"refresh failed after restart"
  finally:stop(proc)
 print("Private acceptance passed: Tapo semantics, OAuth, MCP 2025-11-25, legacy-to-nested OAuth configuration, restart persistence, app discovery, challenge-guided read consent, separate read/write scopes and acknowledged writes.")
if __name__=="__main__":main()
