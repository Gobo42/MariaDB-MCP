import os, pathlib, shlex, stat, subprocess, tempfile, unittest
SCRIPT=pathlib.Path(__file__).with_name("install.sh").resolve()
class InstallTests(unittest.TestCase):
 def run_script(self,config,state,cwd):
  shell=f"""source {shlex.quote(str(SCRIPT))}
config_dir={shlex.quote(str(config))}
state_dir={shlex.quote(str(state))}
id() {{ if [[ $1 == -u && $# == 1 ]]; then echo 0; else echo 1001; fi; }}
getent() {{ echo mcpagent:x:1001:; }}
chown() {{ :; }}
prepare_directories
"""
  return subprocess.run(["bash","-c",shell],cwd=cwd,capture_output=True,text=True)
 def test_directories_and_reruns_preserve_contents_and_fix_modes(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)
   for i,suffix in enumerate(("", "/", "///")):
    config=root/f"config{i}";state=root/f"state{i}"
    self.assertEqual(self.run_script(str(config)+suffix,str(state)+suffix,root).returncode,0)
    credential=config/"credentials"/"app.json";token=state/"oauth-state.json"
    credential.write_text("credential-sentinel");token.write_text("token-sentinel")
    os.chmod(credential,0o644);os.chmod(token,0o644)
    self.assertEqual(self.run_script(str(config)+suffix,str(state)+suffix,root).returncode,0)
    self.assertEqual(credential.read_text(),"credential-sentinel");self.assertEqual(token.read_text(),"token-sentinel")
    for path in (config,state,config/"apps.d",config/"connections",config/"credentials"):
     self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
    for path in (credential,token):self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
 def test_relative_nonexistent_and_existing_paths(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)
   for suffix in ("","/","///"):
    result=self.run_script("config"+suffix,"state"+suffix,root);self.assertEqual(result.returncode,0,result.stderr)
 def test_symlink_entries_ancestors_and_roots_are_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);outside=root/"outside";outside.mkdir();(outside/"sentinel").write_text("keep")
   link=root/"link";link.symlink_to(outside,target_is_directory=True)
   for path in (str(link)+"/",str(link)+"/../config","/"):
    self.assertNotEqual(self.run_script(path,root/"state",root).returncode,0)
   config=root/"config";config.mkdir();(config/"bad").symlink_to(outside/"sentinel")
   self.assertNotEqual(self.run_script(config,root/"state",root).returncode,0);self.assertEqual((outside/"sentinel").read_text(),"keep")
 def test_help_and_extra_arguments_do_not_mutate(self):
  self.assertEqual(subprocess.run(["bash",str(SCRIPT),"--help"],capture_output=True).returncode,0)
  self.assertNotEqual(subprocess.run(["bash",str(SCRIPT),"unexpected"],capture_output=True).returncode,0)
if __name__=="__main__":unittest.main()
