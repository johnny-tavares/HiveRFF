"""Integration checks for worker-local preprocessing and the compiled Zig loader."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parent
source=Path(os.environ.get('AFL_SOURCE_DIR','/opt/sched-fuzz/AFL-2.57b'))
if not source.is_dir(): source=root.parent/'sched-fuzz/AFL-2.57b'
library=Path(os.environ['HIVE_LIBMUTATOR'])
with tempfile.TemporaryDirectory(prefix='hive-preprocess-test-') as tmp:
    work=Path(tmp);bin_dir=work/'bin';bin_dir.mkdir()
    converter=work/'convert.py'; jar=work/'rapid.jar';jar.write_text('fixture')
    converter.write_text('''import os,sys
from pathlib import Path
assert 'LD_PRELOAD' not in os.environ
assert sys.argv[1:]==['events.log','mapping.log','comb.log']
if os.environ.get('FAIL_STEP')=='convert': sys.exit(3)
Path('comb.log').write_text('1|r(7)|123\\n2|w(7)|456\\n')
''')
    predictor=bin_dir/'java'
    predictor.write_text('''#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
assert 'LD_PRELOAD' not in os.environ
assert sys.argv[sys.argv.index('-sp')+1]=='min; touch UNEXPECTED'
if os.environ.get('FAIL_STEP')=='predict': sys.exit(7)
Path('event_pairs.json').write_text(json.dumps({'rels':[],'scores':[]}))
'''); predictor.chmod(0o755)
    exe=work/'test_preprocess'
    subprocess.run(['gcc','-O2','-ffunction-sections','-fdata-sections','-Wno-pointer-sign',
                    '-Wno-discarded-qualifiers','-iquote',str(source),'-DBIN_PATH="/tmp"','-DDOC_PATH="/tmp"',
                    '-DHIVE_PREPROCESS_SCRIPT="'+str(converter)+'"',
                    '-DHIVE_PAIR_SCRIPT="'+str(root/'all_event_pairs.py')+'"',
                    '-DHIVE_PREDICTOR_JAR="'+str(jar)+'"',str(root/'test_preprocess.c'),str(library),
                    '-Wl,--gc-sections','-o',str(exe),'-lm','-ldl','-lrt'],check=True)
    shared_sentinel=work/'shared-sentinel';shared_sentinel.write_text('do not modify')
    env=dict(os.environ,PATH=str(bin_dir)+os.pathsep+os.environ['PATH'])
    def run(mode,args=(),extra=None,success=True):
        directory=work/('case-'+str(run.count));run.count+=1;directory.mkdir()
        if mode=='pipeline':
            for name in ['events.log','mapping.log','comb.log','event_pairs.json','all_pairs.json']:
                (directory/name).symlink_to(shared_sentinel)
        result=subprocess.run([str(exe),mode,str(directory)]+list(map(str,args)),cwd=str(directory),
                              env=dict(env,**(extra or {})),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              universal_newlines=True,timeout=20)
        assert (result.returncode==0)==success,result.stdout
        return directory,result.stdout
    run.count=0
    fixtures={
      'empty':{'rels':[],'scores':[]},
      'valid':{'rels':[{'r':123,'w':456}],'scores':[0.5]},
      'race':{'rels':[{'r':123,'w':456}],'scores':[0]},
      'mismatch':{'rels':[{'r':1,'w':2}],'scores':[]},
      'badscore':{'rels':[{'r':999,'w':888},{'r':123,'w':456}],'scores':[0.5,2]},
    }
    files={}
    for name,data in fixtures.items():
        files[name]=work/(name+'.json');files[name].write_text(json.dumps(data))
    broken=work/'broken.json';broken.write_text('{')
    directory,_=run('load',[files['empty']]);metrics=json.loads((directory/'hive_metrics.json').read_text())
    assert metrics['pair_loads']==1 and metrics['pair_empty_loads']==1 and metrics['pair_available']==0
    _,output=run('checked',[files['valid'],files['badscore'],files['empty']])
    loads=[line for line in output.splitlines() if line.startswith('LOAD ')]
    assert loads==['LOAD 0 1 1','LOAD -1 0 1','LOAD 0 0 1'],output
    for file in [work/'missing.json',broken,files['mismatch'],files['badscore']]:
        directory,output=run('load',[file],success=False)
        assert 'Failed to load RF pair file' in output
        assert json.loads((directory/'hive_metrics.json').read_text())['preprocess_failures']==1
    directory,_=run('mutate',[files['race']])
    metrics=json.loads((directory/'hive_metrics.json').read_text())
    assert metrics['mutation_obligation_changes']>0 and metrics['mutation_initial_schedules']==1
    # Real all_event_pairs.py, stub converter/predictor, two independent worker directories.
    for _ in range(2):
        directory,_=run('pipeline')
        assert json.loads((directory/'all_pairs.json').read_text())=={'rels':[{'r':123,'w':456}],'scores':[0.0]}
        assert not (directory/'all_pairs.json').is_symlink()
        assert shared_sentinel.read_text()=='do not modify'
    for step in ['convert','predict']:
        directory,output=run('pipeline',extra={'FAIL_STEP':step},success=False)
        assert 'Preprocessing command' in output
        assert json.loads((directory/'hive_metrics.json').read_text())['preprocess_failures']==1
    for args in [['/bin/sh','-c','exit 9'],['/bin/sh','-c','kill -TERM $$'],['/does/not/exist']]:
        _,output=run('command',args,success=False)
        assert 'Preprocessing command test command failed' in output
    converter.unlink()
    _,output=run('pipeline',success=False)
    assert 'Missing preprocessing tool' in output
print('PASS: checked pair loading, valid empty sets, invalid data rollback, structural mutations, worker-local pipeline, command failures, missing tools.')
