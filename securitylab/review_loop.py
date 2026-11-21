"""Read/search over the immutable in-memory snapshot only."""
import json
from . import review_contract as contract
from .policy import PolicyError
from .storage import atomic_text


def run(entry,files,context,mapping,ask,folder,emit,checkpoint):
    history=[]
    for turn in range(1,contract.MAX_TURNS+1):
        checkpoint()
        req=contract.make_request('red',entry,files,context,mapping,history)
        emit('review','wait_model',f'Ревью кода: шаг {turn}/{contract.MAX_TURNS}; ожидаем ответ.')
        action,receipt=ask(req);contract.validate_reply(req,action)
        atomic_text(folder/f'review_request_{turn}.json',json.dumps(req,ensure_ascii=False,indent=2))
        if 'review' in action:return action,receipt,history
        if turn==contract.MAX_TURNS:raise PolicyError('Review decision budget exhausted; no final review')
        emit('review','running','Чтение исходников' if action['action']=='read' else 'Поиск по исходникам')
        if action['action']=='read':
            lines=files[action['file']].splitlines();start=action['start']-1
            if start>=len(lines) and lines:raise PolicyError('Read start exceeds source length')
            text='\n'.join(f'{i+1}: {line}' for i,line in enumerate(lines) if start<=i<start+action['count'])
            if len(text.encode())>4500:raise PolicyError('Read excerpt exceeds 4500 bytes; choose smaller range')
            result={'file':action['file'],'text':text,'total_lines':len(lines)}
        else:
            matches=[{'file':p,'line':i,'text':line[:180]} for p,s in files.items() for i,line in enumerate(s.splitlines(),1) if action['query'] in line]
            result={'matches':matches[:15],'total_matches':len(matches),'truncated':len(matches)>15}
        history.append({'action':action,'result':result})
        atomic_text(folder/'review_history.json',json.dumps(history,ensure_ascii=False,indent=2))
    raise PolicyError('Review budget exhausted')
