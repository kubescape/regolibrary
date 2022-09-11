import json
import os
import collections
import sys

attack_tracks = ['container','kubeapi','node']
container_track_categories = ['Initial access','Execution','Persistence','Privilege escalation','Defense evasion - KubeAPI','Credential access','Discovery','Lateral movement','Impact - service access','Impact - K8s API access','Impact - Data access in container','Impact - service destruction']
kubeapi_categories = ['Initial access','Persistence','Privilege escalation','Defense evasion','Credential access','Discovery','Lateral movement','Impact - data destruction','Impact - service injection']
node_categories = ['Initial access','Execution','Persistence','Privilege escalation','Defense evasion','Credential access','Discovery','Lateral movement','Impact']
track_to_categories = {
    'container' : container_track_categories,
    'kubeapi' : kubeapi_categories,
    'node' : node_categories
}
control_type = ['security','compliance','devops','security-impact']

def user_wants_to_edit_control_type(control):
    if 'control-type-tags' in control['attributes']:
        print('control type tags:',','.join(control['attributes']))
        while True:
            a = input('Want to edit?')
            if not a in ['y','n']:
                continue
            elif a == 'n':
                return False
            else:
                return True

def print_options(list_object):
    print('\n'.join(['%d. %s'%(ndx,item) for ndx,item in enumerate(list_object)]))

def float_answer_validator(a):
    try:
        float(a)
        return True
    except:
        return False
    

def get_user_input_choice(text, valid_answers=None, answer_validator=None, accept_multiple_answers = False):
    while True:
        answer = input(text+' (q to exit)')
        if answer == 'q':
            return None
        r = None
        if accept_multiple_answers:
            r = []
            for ma in answer.split():
                if (valid_answers and ma in valid_answers) or (answer_validator and answer_validator(ma)) or (not valid_answers and not answer_validator):
                    r.append(ma)
                else:
                    print('Invalid answer!')
                    break
            if not len(r):
                continue
        else:
            if (valid_answers and answer in valid_answers) or (answer_validator and answer_validator(answer)) or (not valid_answers and not answer_validator):
                    r = answer
            else:
                print('Invalid answer!')
        if r:
            return r
        
control_by_filenames = {}
for file_name in filter(lambda x: x.endswith('.json'),os.listdir('controls')):
    with open(os.path.join('controls',file_name)) as f:
        control_by_filenames[file_name] = json.load(f)

od = collections.OrderedDict(sorted(control_by_filenames.items(), key=lambda x: x[1]['id']))

start_from = 0
if len(sys.argv) > 1:
    start_from = int(sys.argv[1])

for file_name in list(od.keys())[start_from:]:
    control = {}
    with open(os.path.join('controls',file_name)) as f:
        control = json.load(f)
    print('^'*120)
    print('Control ',control['controlID'])
    print('base score', control['baseScore'])
    print(control['name'])
    print(control['description'])
    print('-'*120)

    if get_user_input_choice('Want to edit score?',valid_answers=['y','n']) == 'y':
        new_score = get_user_input_choice('What should be the score?',answer_validator=float_answer_validator)
        if new_score:
            control['baseScore'] = float(new_score)
    
    if not 'control-type-tags' in control['attributes'] or user_wants_to_edit_control_type(control):
        print('Defining control type tags')
        print_options(control_type)
        choices = get_user_input_choice('Which to add?',valid_answers=['%d'%i for i in range(len(control_type))],accept_multiple_answers=True)
        if choices:
            control['attributes']['control-type-tags'] = [control_type[int(i)] for i in choices]
    print(control['attributes']['control-type-tags'])
    
        

    if 'security' in control['attributes']['control-type-tags'] or 'security-impact' in control['attributes']['control-type-tags']:
        while True:
            a = input('Edit attack tracks? (y/n)')
            if not a in ['y','n']:
                continue
            elif a == 'n':
                break
            else:
                while True:
                    a = input('Which track to add? (%s or q to stop)'%(','.join(attack_tracks)))
                    if a in [str(i) for i in range(len(attack_tracks))]:
                        track = attack_tracks[int(a)]
                        if not 'attack-tracks' in control['attributes']:
                            control['attributes']['attack-tracks'] = {}
                        if track in control['attributes']['attack-tracks']:
                            print('already there: ',','.join(control['attributes']['attack-tracks']))
                        else:
                            control['attributes']['attack-tracks'][track] = []
                        while True:
                            print('Categories:\n%s\n'%('\n'.join(['%d. %s'%(ndx, category) for ndx, category in enumerate(track_to_categories[track])])))
                            answer = input('Which to include?')
                            try:
                                control['attributes']['attack-tracks'][track] = [track_to_categories[track][int(c)] for c in answer.split()]
                                break
                            except Exception as e:
                                print(e)
                                continue                        
                    if a == 'q':
                        break
        
    
    with open(os.path.join('controls',file_name),'w') as f:
        json.dump(control,f, indent=4)


